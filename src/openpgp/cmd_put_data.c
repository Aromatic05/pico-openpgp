/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "openpgp.h"
#include "otp.h"

int cmd_put_data() {
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (fid == EF_RESET_CODE) {
        fid = EF_RC;
    }
    else if (fid == EF_ALGO_SIG || fid == EF_ALGO_DEC || fid == EF_ALGO_AUT) {
        fid |= 0x1000;
    }
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == EF_PW_STATUS) {
        fid = EF_PW_PRIV;
        apdu.nc = 4; //we silently ommit the reset parameters
    }
    if (currentEF && (currentEF->fid & 0x1FF0) == (fid & 0x1FF0)) { //previously selected
        ef = currentEF;
    }
    if (apdu.nc > 0 && (ef->type & FILE_DATA_FLASH)) {
        int r = 0;
        if (fid == EF_RC) {
            has_rc = false;
            if ((r = load_dek()) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            file_t *status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
            if (!file_has_data(tf) || !file_has_data(status)) {
                return SW_REFERENCE_NOT_FOUND();
            }

            const bool had_rc = file_has_data(ef);
            const uint16_t old_rc_len = file_get_size(ef);
            const uint16_t old_dek_len = file_get_size(tf);
            const uint16_t old_status_len = file_get_size(status);
            uint8_t old_rc[64] = {0};
            uint8_t old_dek[IV_SIZE + 32 * 4] = {0};
            uint8_t old_status[16] = {0};
            if (old_rc_len > sizeof(old_rc) || old_dek_len > sizeof(old_dek) ||
                old_status_len > sizeof(old_status)) {
                return SW_MEMORY_FAILURE();
            }
            if (had_rc) {
                memcpy(old_rc, file_get_data(ef), old_rc_len);
            }
            memcpy(old_dek, file_get_data(tf), old_dek_len);
            memcpy(old_status, file_get_data(status), old_status_len);

            uint8_t dhash[33];
            dhash[0] = apdu.nc;
            double_hash_pin(apdu.data, apdu.nc, dhash + 1);
            uint8_t def[IV_SIZE + 32 + 32 + 32 + 32];
            memcpy(def, file_get_data(tf), file_get_size(tf));
            hash_multi(apdu.data, apdu.nc, session_rc);
            /* load_dek() returns the unmasked content-encryption key. DEK
             * wrappers persist the device-masked form so an OTP-derived
             * hardware secret remains part of every password/RC unwrap. */
            if (otp_key_1) {
                for (int i = 0; i < 32; i++) {
                    dek[IV_SIZE + i] ^= otp_key_1[i];
                }
            }
            memcpy(def + IV_SIZE + 32, dek + IV_SIZE, 32);
            aes_encrypt_cfb_256(session_rc, def, def + IV_SIZE + 32, 32);
            r = file_put_data(ef, dhash, sizeof(dhash));
            if (r == PICOKEY_OK) {
                r = file_put_data(tf, def, sizeof(def));
            }
            if (r == PICOKEY_OK) {
                r = pin_reset_retries_deferred(ef, true);
            }
            if (r != PICOKEY_OK) {
                int rr = had_rc ? file_put_data(ef, old_rc, old_rc_len)
                                : flash_clear_file(ef);
                int rd = file_put_data(tf, old_dek, old_dek_len);
                int rs = file_put_data(status, old_status, old_status_len);
                if (rr == PICOKEY_OK && rd == PICOKEY_OK && rs == PICOKEY_OK) {
                    low_flash_available();
                }
                openpgp_unload();
                openpgp_revoke_auth_sessions();
            }
            mbedtls_platform_zeroize(old_rc, sizeof(old_rc));
            mbedtls_platform_zeroize(old_dek, sizeof(old_dek));
            mbedtls_platform_zeroize(old_status, sizeof(old_status));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            mbedtls_platform_zeroize(def, sizeof(def));
            mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
        }
        else {
            bool key_algorithm_changed =
                (fid == EF_ALGO_PRIV1 || fid == EF_ALGO_PRIV2 || fid == EF_ALGO_PRIV3) &&
                (!file_has_data(ef) || file_get_size(ef) != apdu.nc ||
                 memcmp(file_get_data(ef), apdu.data, apdu.nc) != 0);
            r = file_put_data(ef, apdu.data, apdu.nc);
            if (r == PICOKEY_OK && key_algorithm_changed) {
                const uint16_t key_fid = EF_PK_SIG + (fid - EF_ALGO_PRIV1);
                const uint16_t public_fid = EF_PB_SIG + (fid - EF_ALGO_PRIV1);
                file_t *private_key = search_by_fid(key_fid, NULL, SPECIFY_EF);
                file_t *public_key = search_by_fid(public_fid, NULL, SPECIFY_EF);
                if (!private_key || !public_key ||
                    flash_clear_file(private_key) != PICOKEY_OK ||
                    flash_clear_file(public_key) != PICOKEY_OK) {
                    return SW_MEMORY_FAILURE();
                }
            }
        }
        if (r != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
        low_flash_available();
        if (fid == EF_RC) {
            openpgp_revoke_auth_sessions();
        }
    }
    return SW_OK();
}

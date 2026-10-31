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

int cmd_reset_retry() {
    if (P2(apdu) != 0x81) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        int newpin_len = 0;
        file_t *pw = NULL;
        has_pw1 = false;
        if (!(pw = search_by_fid(EF_PW1, NULL, SPECIFY_EF))) {
            return SW_REFERENCE_NOT_FOUND();
        }
        if (P1(apdu) == 0x0) {
            file_t *rc;
            if (!(rc = search_by_fid(EF_RC, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            if (!file_has_data(rc)) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_get_data(rc)[0];
            if (apdu.nc <= pin_len) {
                return SW_WRONG_LENGTH();
            }
            uint16_t r = check_pin(rc, apdu.data, pin_len);
            if (r != 0x9000) {
                return r;
            }
            newpin_len = apdu.nc - pin_len;
            has_rc = true;
            hash_multi(apdu.data, pin_len, session_rc);
            has_pw1 = has_pw2 = has_pw3 = false;
            isUserAuthenticated = false;
        }
        else if (P1(apdu) == 0x2) {
            if (!has_pw3) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            newpin_len = apdu.nc;
        }
        if (newpin_len == 0) {
            return SW_WRONG_LENGTH();
        }
        int r = 0;
        if ((r = load_dek()) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        file_t *status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
        if (!file_has_data(status)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint16_t old_dek_len = file_get_size(tf);
        uint16_t old_pw_len = file_get_size(pw);
        uint16_t old_status_len = file_get_size(status);
        uint8_t old_dek[IV_SIZE + 32 * 4] = {0};
        uint8_t old_pw[64] = {0};
        uint8_t old_status[16] = {0};
        if (old_dek_len > sizeof(old_dek) || old_pw_len > sizeof(old_pw) ||
            old_status_len > sizeof(old_status)) {
            return SW_MEMORY_FAILURE();
        }
        memcpy(old_dek, file_get_data(tf), old_dek_len);
        memcpy(old_pw, file_get_data(pw), old_pw_len);
        memcpy(old_status, file_get_data(status), old_status_len);
        if (otp_key_1) {
            for (int i = 0; i < 32; i++) {
                dek[IV_SIZE + i] ^= otp_key_1[i];
            }
        }
        uint8_t def[IV_SIZE + 32 + 32 + 32 + 32];
        memcpy(def, file_get_data(tf), file_get_size(tf));
        hash_multi(apdu.data + (apdu.nc - newpin_len), newpin_len, session_pw1);
        memcpy(def + IV_SIZE, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_pw1, def, def + IV_SIZE, 32);
        r = file_put_data(tf, def, sizeof(def));

        uint8_t dhash[33];
        dhash[0] = newpin_len;
        double_hash_pin(apdu.data + (apdu.nc - newpin_len), newpin_len, dhash + 1);
        if (r == PICOKEY_OK) {
            r = file_put_data(pw, dhash, sizeof(dhash));
        }
        if (r == PICOKEY_OK) {
            r = pin_reset_retries_deferred(pw, true);
        }

        /* Validate the newly wrapped PW1 before publishing any of the three
         * persistent mutations. RESET RETRY COUNTER should not leave an
         * authenticated session behind regardless of the authorization path. */
        if (r == PICOKEY_OK) {
            has_pw1 = true;
            has_pw2 = has_pw3 = has_rc = false;
            r = load_dek();
        }
        if (r != PICOKEY_OK) {
            int rd = file_put_data(tf, old_dek, old_dek_len);
            int rp = file_put_data(pw, old_pw, old_pw_len);
            int rs = file_put_data(status, old_status, old_status_len);
            if (rd == PICOKEY_OK && rp == PICOKEY_OK && rs == PICOKEY_OK) {
                low_flash_available();
            }
            openpgp_unload();
            openpgp_revoke_auth_sessions();
            mbedtls_platform_zeroize(old_dek, sizeof(old_dek));
            mbedtls_platform_zeroize(old_pw, sizeof(old_pw));
            mbedtls_platform_zeroize(old_status, sizeof(old_status));
            mbedtls_platform_zeroize(def, sizeof(def));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            return SW_MEMORY_FAILURE();
        }
        openpgp_unload();
        openpgp_revoke_auth_sessions();
        low_flash_available();
        mbedtls_platform_zeroize(old_dek, sizeof(old_dek));
        mbedtls_platform_zeroize(old_pw, sizeof(old_pw));
        mbedtls_platform_zeroize(old_status, sizeof(old_status));
        mbedtls_platform_zeroize(def, sizeof(def));
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}

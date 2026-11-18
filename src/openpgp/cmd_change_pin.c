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

int cmd_change_pin() {
    if (P1(apdu) != 0x0) {
        return SW_WRONG_P1P2();
    }
    uint16_t fid = 0x1000 | P2(apdu);
    file_t *pw;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF)) || !file_has_data(pw)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t pin_len = file_get_data(pw)[0];
    if (apdu.nc <= pin_len || apdu.nc - pin_len > OPENPGP_MAX_PIN_LENGTH) {
        return SW_WRONG_LENGTH();
    }
    uint16_t r = 0;
    r = check_pin(pw, apdu.data, pin_len);
    if (r != 0x9000) {
        return r;
    }
    if (fid == EF_RC) {
        has_pw1 = has_pw2 = false;
        has_rc = true;
        hash_multi(apdu.data, pin_len, session_rc);
    }
    r = load_dek();
    if (fid == EF_RC) {
        has_rc = false;
        mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    }
    if (r != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }

    if (otp_key_1) {
        for (int i = 0; i < 32; i++) {
            dek[IV_SIZE + i] ^= otp_key_1[i];
        }
    }
    file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
    if (!tf) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint16_t old_pw_len = file_get_size(pw);
    uint16_t old_dek_len = file_get_size(tf);
    uint8_t old_pw[64] = {0};
    uint8_t old_dek[IV_SIZE + 32 * 4] = {0};
    if (old_pw_len > sizeof(old_pw) || old_dek_len > sizeof(old_dek)) {
        return SW_MEMORY_FAILURE();
    }
    memcpy(old_pw, file_get_data(pw), old_pw_len);
    memcpy(old_dek, file_get_data(tf), old_dek_len);

    uint8_t dhash[33];
    dhash[0] = apdu.nc - pin_len;
    double_hash_pin(apdu.data + pin_len, apdu.nc - pin_len, dhash + 1);
    uint8_t def[IV_SIZE + 32 + 32 + 32 + 32] = {0};
    memcpy(def, file_get_data(tf), file_get_size(tf));
    if (P2(apdu) == 0x81) {
        hash_multi(apdu.data + pin_len, apdu.nc - pin_len, session_pw1);
        memcpy(def + IV_SIZE, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_pw1, def, def + IV_SIZE, 32);
    }
    else if (fid == EF_RC) {
        hash_multi(apdu.data + pin_len, apdu.nc - pin_len, session_rc);
        memcpy(def + IV_SIZE + 32, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_rc, def, def + IV_SIZE + 32, 32);
    }
    else if (P2(apdu) == 0x83) {
        hash_multi(apdu.data + pin_len, apdu.nc - pin_len, session_pw3);
        memcpy(def + IV_SIZE + 32 + 32, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_pw3, def, def + IV_SIZE + 32 + 32, 32);
    }
    r = file_put_data(pw, dhash, sizeof(dhash));
    if (r == PICOKEY_OK) {
        r = file_put_data(tf, def, sizeof(def));
    }
    if (r != PICOKEY_OK) {
        int restore_pw = file_put_data(pw, old_pw, old_pw_len);
        int restore_dek = file_put_data(tf, old_dek, old_dek_len);
        if (restore_pw == PICOKEY_OK && restore_dek == PICOKEY_OK) {
            low_flash_available();
        }
        openpgp_unload();
        openpgp_revoke_auth_sessions();
        mbedtls_platform_zeroize(old_pw, sizeof(old_pw));
        mbedtls_platform_zeroize(old_dek, sizeof(old_dek));
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        mbedtls_platform_zeroize(def, sizeof(def));
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    openpgp_revoke_auth_sessions();
    mbedtls_platform_zeroize(old_pw, sizeof(old_pw));
    mbedtls_platform_zeroize(old_dek, sizeof(old_dek));
    mbedtls_platform_zeroize(dhash, sizeof(dhash));
    mbedtls_platform_zeroize(def, sizeof(def));
    return SW_OK();
}

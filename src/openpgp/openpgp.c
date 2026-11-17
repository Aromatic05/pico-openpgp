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

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#else
#include "common.h"
#endif
#include "openpgp.h"
#include "version.h"
#include "random.h"
#include "eac.h"
#include "mbedtls/asn1.h"
#include "usb.h"
#include "ccid/ccid.h"
#include "otp.h"
#include "do.h"
#ifdef MBEDTLS_EDDSA_C
#include "mbedtls/eddsa.h"
#endif

static openpgp_session_auth_t openpgp_sessions[APDU_SESSION_COUNT];

openpgp_session_auth_t *openpgp_active_auth(void) {
    return &openpgp_sessions[apdu_current_session()];
}

void openpgp_reset_all_sessions(void) {
    mbedtls_platform_zeroize(openpgp_sessions, sizeof(openpgp_sessions));
}

void openpgp_revoke_auth_sessions(void) {
    openpgp_reset_all_sessions();
    file_clear_all_authenticated_sessions();
}
uint16_t algo_dec = EF_ALGO_PRIV2, algo_aut = EF_ALGO_PRIV3, pk_dec = EF_PK_DEC, pk_aut = EF_PK_AUT;

uint8_t openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};

uint8_t openpgp_aid_full[] = {
    16, 00,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    OPGP_VERSION_MAJOR, OPGP_VERSION_MINOR, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
};

char atr_openpgp[] = {
    21,
    0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03, 0x00, 0x31, 0xf5, 0x73, 0xc0, 0x01,
    0x60, 0x00, 0x90, 0x00, 0x1c
};

int openpgp_process_apdu();

extern uint32_t board_button_read(void);

bool wait_button_pressed_fid(uint16_t fid) {
    uint32_t val = EV_PRESS_BUTTON;
#ifndef ENABLE_EMULATION
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_ANY);
    if (ef && ef->data && file_get_data(ef)[0] > 0) {
        queue_try_add(&card_to_usb_q, &val);
        do {
            queue_remove_blocking(&usb_to_card_q, &val);
        }while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT);
    }
#endif
    return val == EV_BUTTON_TIMEOUT;
}

void select_file(file_t *pe) {
    if (!pe) {
        currentDF = (file_t *) MF;
        currentEF = NULL;
    }
    else if (pe->type & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = &file_entries[pe->parent];
    }
    else {
        currentDF = pe;
    }
    if (currentEF == file_openpgp) {
        selected_applet = currentEF;
        //sc_hsm_unload(); //reset auth status
    }
}

int scan_files_openpgp() {
    scan_flash();
    int ret = PICOKEY_OK;
    file_t *ef;
    if ((ef = search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        memcpy(ef->data + 12, pico_serial.id, 4);
    }
    bool reset_dek = false;
    if ((ef = search_by_fid(EF_DEK, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("DEK is empty\r\n");
            const uint8_t def1[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            const uint8_t def3[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

            uint8_t def[IV_SIZE + 32 + 32 + 32];
            const uint8_t *initial_dek = random_bytes_get(IV_SIZE + 32);
            memcpy(def, initial_dek, IV_SIZE + 32);
            memcpy(def + IV_SIZE + 32 + 32, def + IV_SIZE, 32);
            /* Wrapper #1 belongs exclusively to the optional Reset Code.
             * RC is empty at factory state, so leave no known default
             * credential capable of unwrapping the DEK through this slot. */
            memcpy(def + IV_SIZE + 32, random_bytes_get(32), 32);
            hash_multi(def1, sizeof(def1), session_pw1);
            aes_encrypt_cfb_256(session_pw1, def, def + IV_SIZE, 32);
            memset(session_pw1, 0, sizeof(session_pw1));

            hash_multi(def3, sizeof(def3), session_pw3);
            aes_encrypt_cfb_256(session_pw3, def, def + IV_SIZE + 32 + 32, 32);
            memset(session_pw3, 0, sizeof(session_pw3));
            ret = file_put_data(ef, def, sizeof(def));
            mbedtls_platform_zeroize(def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
            reset_dek = true;
        }
    }
    if ((ef = search_by_fid(EF_PW1, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW1 is empty. Initializing with default password\r\n");
            const uint8_t def[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            ret = file_put_data(ef, dhash, sizeof(dhash));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    bool migrated_legacy_default_rc = false;
    if ((ef = search_by_fid(EF_RC, NULL, SPECIFY_ANY))) {
        if (reset_dek && file_has_data(ef)) {
            /* OpenPGP Card 3.4 requires RC to be empty by default. A newly
             * generated DEK invalidates any old RC wrapper as well. */
            ret = flash_clear_file(ef);
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
        else if (file_has_data(ef) && file_get_size(ef) == 33) {
            /* Older pico-openpgp firmware materialized the public value
             * "12345678" as RC. Treat that exact known legacy value as
             * unsafe factory state on upgrade, even if it was explicitly
             * chosen by a user, and invalidate its dedicated DEK wrapper. */
            static const uint8_t legacy_rc[] = {
                '1', '2', '3', '4', '5', '6', '7', '8'
            };
            uint8_t legacy_hash[33];
            legacy_hash[0] = sizeof(legacy_rc);
            double_hash_pin(legacy_rc, sizeof(legacy_rc), legacy_hash + 1);
            if (memcmp(file_get_data(ef), legacy_hash, sizeof(legacy_hash)) == 0) {
                file_t *dek_ef = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
                if (file_has_data(dek_ef) &&
                    file_get_size(dek_ef) >= IV_SIZE + 64 &&
                    file_get_size(dek_ef) <= IV_SIZE + 4 * 32) {
                    uint8_t record[IV_SIZE + 4 * 32];
                    uint16_t record_len = file_get_size(dek_ef);
                    memcpy(record, file_get_data(dek_ef), record_len);
                    memcpy(record + IV_SIZE + 32, random_bytes_get(32), 32);
                    ret = file_put_data(dek_ef, record, record_len);
                    mbedtls_platform_zeroize(record, sizeof(record));
                    if (ret != PICOKEY_OK) {
                        goto init_done;
                    }
                }
                ret = flash_clear_file(ef);
                if (ret != PICOKEY_OK) {
                    goto init_done;
                }
                migrated_legacy_default_rc = true;
            }
            mbedtls_platform_zeroize(legacy_hash, sizeof(legacy_hash));
        }
    }
    if ((ef = search_by_fid(EF_PW3, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW3 is empty. Initializing with default password\r\n");

            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            ret = file_put_data(ef, dhash, sizeof(dhash));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("SigCount is empty. Initializing to zero\r\n");
            const uint8_t def[3] = { 0 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 0, 3 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    /* Migrate cards written by older firmware that materialized a public
     * default RC. An absent RC always implies a zero current retry counter,
     * even if the shared PW status record predates this fix. */
    file_t *rc = search_by_fid(EF_RC, NULL, SPECIFY_EF);
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if ((migrated_legacy_default_rc || !file_has_data(rc)) &&
        file_has_data(pw_status) &&
        file_get_size(pw_status) >= 7 && file_get_data(pw_status)[5] != 0) {
        uint8_t status[64];
        uint16_t status_len = file_get_size(pw_status);
        if (status_len > sizeof(status)) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
            goto init_done;
        }
        memcpy(status, file_get_data(pw_status), status_len);
        status[5] = 0;
        ret = file_put_data(pw_status, status, status_len);
        mbedtls_platform_zeroize(status, sizeof(status));
        if (ret != PICOKEY_OK) {
            goto init_done;
        }
    }
    if ((ef = search_by_fid(EF_UIF_SIG, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF SIG is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_UIF_DEC, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF DEC is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_UIF_AUT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF AUT is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_KDF, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("KDF is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x81, 0x1, 0x0 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_SEX, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("Sex is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x30 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
    if ((ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW retries is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 3, 3, 3 };
            ret = file_put_data(ef, def, sizeof(def));
            if (ret != PICOKEY_OK) {
                goto init_done;
            }
        }
    }
init_done:
    low_flash_available();
    return ret;
}

void release_dek() {
    memset(dek, 0, sizeof(dek));
}

int load_dek() {
    if (!has_pw1 && !has_pw2 && !has_rc && !has_pw3 && !piv_pin_is_verified()) {
        return PICOKEY_NO_LOGIN;
    }
    file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
    if (!tf) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    int r = PICOKEY_OK;
    if (has_pw1 || has_pw2) {
        memcpy(dek, file_get_data(tf), IV_SIZE + 32);
        r = aes_decrypt_cfb_256(session_pw1, dek, dek + IV_SIZE, 32);
    }
    else if (has_rc) {
        memcpy(dek, file_get_data(tf), IV_SIZE);
        memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32, 32);
        r = aes_decrypt_cfb_256(session_rc, dek, dek + IV_SIZE, 32);
    }
    else if (has_pw3) {
        memcpy(dek, file_get_data(tf), IV_SIZE);
        memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32 + 32, 32);
        r = aes_decrypt_cfb_256(session_pw3, dek, dek + IV_SIZE, 32);
    }
    else if (piv_pin_is_verified()) {
        memcpy(dek, file_get_data(tf), IV_SIZE);
        memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32 + 32 + 32, 32);
        r = aes_decrypt_cfb_256(piv_pin_session_key(), dek, dek + IV_SIZE, 32);
    }
    if (r != 0) {
        release_dek();
        return PICOKEY_EXEC_ERROR;
    }
    if (otp_key_1) {
        for (int i = 0; i < 32; i++) {
            dek[IV_SIZE + i] ^= otp_key_1[i];
        }
    }
    return PICOKEY_OK;
}

int dek_encrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEY_OK) {
        return r;
    }
    r = aes_encrypt_cfb_256(dek + IV_SIZE, dek, data, len);
    release_dek();
    return r;
}

int dek_decrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEY_OK) {
        return r;
    }
    r = aes_decrypt_cfb_256(dek + IV_SIZE, dek, data, len);
    release_dek();
    return r;
}

static void reset_openpgp_session(void) {
    isUserAuthenticated = false;
    has_pw1 = has_pw2 = has_pw3 = has_rc = false;
    mbedtls_platform_zeroize(session_pw1, sizeof(session_pw1));
    mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    mbedtls_platform_zeroize(session_pw3, sizeof(session_pw3));
    release_dek();
}

int init_openpgp() {
    reset_openpgp_session();
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    int ret = scan_files_openpgp();
    //cmd_select();
    return ret;
}

int openpgp_unload() {
    reset_openpgp_session();
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    return PICOKEY_OK;
}

extern char __StackLimit;
int heapLeft() {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
#else
    int left = 1024 * 1024;
#endif
    return left;
}

int openpgp_select_aid(app_t *a, uint8_t force) {
    (void) force;
    int ret = init_openpgp();
    if (ret != PICOKEY_OK) {
        return ret;
    }
    a->process_apdu = openpgp_process_apdu;
    a->unload = openpgp_unload;
    process_fci(file_openpgp, 1);
    memcpy(res_APDU + res_APDU_size, "\x64\x06\x53\x04", 4);
    res_APDU_size += 4;
    int heap_left = heapLeft();
    res_APDU[res_APDU_size++] = ((heap_left >> 24) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 16) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 8) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 0) & 0xff);
    res_APDU[1] += 8;
    apdu.ne = res_APDU_size;
    return PICOKEY_OK;
}

INITIALIZER( openpgp_ctor ) {
    ccid_atr = (uint8_t *) atr_openpgp;
    register_app(openpgp_select_aid, openpgp_aid);
}

static int pin_reset_retries_impl(const file_t *pin, bool force, bool publish) {
    if (!pin) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *pw_retries = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!pw_status || !pw_retries) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (3 + (pin->fid & 0xf) >= file_get_size(pw_status) || (pin->fid & 0xf) >= file_get_size(pw_retries)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    uint8_t p[64];
    memcpy(p, file_get_data(pw_status), file_get_size(pw_status));
    uint8_t retries = p[3 + (pin->fid & 0xf)];
    if (retries == 0 && force == false) { //blocked
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t max_retries = file_get_data(pw_retries)[(pin->fid & 0xf)];
    p[3 + (pin->fid & 0xf)] = max_retries;
    int r = file_put_data(pw_status, p, file_get_size(pw_status));
    if (r == PICOKEY_OK && publish) {
        low_flash_available();
    }
    return r;
}

int pin_reset_retries(const file_t *pin, bool force) {
    return pin_reset_retries_impl(pin, force, true);
}

int pin_reset_retries_deferred(const file_t *pin, bool force) {
    return pin_reset_retries_impl(pin, force, false);
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if (!pw_status) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t p[64];
    memcpy(p, file_get_data(pw_status), file_get_size(pw_status));
    if (p[3 + (pin->fid & 0xf)] > 0) {
        p[3 + (pin->fid & 0xf)] -= 1;
        int r = file_put_data(pw_status, p, file_get_size(pw_status));
        if (r != PICOKEY_OK) {
            return r;
        }
        low_flash_available();
        if (p[3 + (pin->fid & 0xf)] == 0) {
            return PICOKEY_ERR_BLOCKED;
        }
        return p[3 + (pin->fid & 0xf)];
    }
    return PICOKEY_ERR_BLOCKED;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!data || len == 0) {
        return SW_WRONG_LENGTH();
    }
    if (!pin) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!pin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    //has_pw1 = has_pw3 = false;

    uint8_t dhash[32];
    double_hash_pin(data, len, dhash);
    if (sizeof(dhash) != file_get_size(pin) - 1) { //1 byte for pin len
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (memcmp(file_get_data(pin) + 1, dhash, sizeof(dhash)) != 0) {
        int retries;
        if ((retries = pin_wrong_retry(pin)) < PICOKEY_OK) {
            return SW_PIN_BLOCKED();
        }
        return set_res_sw(0x63, 0xc0 | retries);
    }

    int r = pin_reset_retries(pin, false);
    if (r == PICOKEY_ERR_BLOCKED) {
        return SW_PIN_BLOCKED();
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    isUserAuthenticated = true;
    if (pin->fid == EF_PW1) {
        if (P2(apdu) == 0x81) {
            has_pw1 = true;
        }
        else {
            has_pw2 = true;
        }
        hash_multi(data, len, session_pw1);
    }
    else if (pin->fid == EF_PW3) {
        has_pw3 = true;
        hash_multi(data, len, session_pw3);
    }
    return SW_OK();
}

int inc_sig_count() {
    file_t *pw_status;
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) || !pw_status->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw_status)[0] == 0) {
        has_pw1 = false;
    }
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t *p = file_get_data(ef);
    uint32_t counter = (p[0] << 16) | (p[1] << 8) | p[2];
    counter++;
    uint8_t q[3] = { (counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff };
    int r = file_put_data(ef, q, sizeof(q));
    if (r != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int reset_sig_count() {
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t q[3] = { 0 };
    int r = file_put_data(ef, q, sizeof(q));
    if (r != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int store_keys(void *key_ctx, int type, uint16_t key_id, bool use_kek) {
    int r, key_size = 0;
    uint8_t kdata[4096 / 8]; //worst

    //if (!has_pw3)
    //    return PICOKEY_NO_LOGIN;
    //file_t *pw3 = search_by_fid(EF_PW3, NULL, SPECIFY_EF);
    //if (!pw3)
    //    return PICOKEY_ERR_FILE_NOT_FOUND;
    file_t *ef = search_by_fid(key_id, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (type == ALGO_RSA) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        key_size = mbedtls_rsa_get_len(rsa);
        if ((key_size != 128 && key_size != 256 && key_size != 384 && key_size != 512) ||
            key_size > sizeof(kdata) ||
            mbedtls_mpi_size(&rsa->P) > (size_t)key_size / 2 ||
            mbedtls_mpi_size(&rsa->Q) > (size_t)key_size / 2) {
            return PICOKEY_WRONG_LENGTH;
        }
        if (mbedtls_mpi_write_binary(&rsa->P, kdata, key_size / 2) != 0 ||
            mbedtls_mpi_write_binary(&rsa->Q, kdata + key_size / 2, key_size / 2) != 0) {
            return PICOKEY_WRONG_DATA;
        }
    }
    else if (type == ALGO_ECDSA || type == ALGO_ECDH || type == ALGO_EDDSA) {
        mbedtls_ecp_keypair *ecdsa = (mbedtls_ecp_keypair *) key_ctx;
        size_t olen = 0;
        kdata[0] = ecdsa->grp.id & 0xff;
        mbedtls_ecp_write_key_ext(ecdsa, &olen, kdata + 1, sizeof(kdata) - 1);
        key_size = olen + 1;
    }
    else if (type & ALGO_AES) {
        if (type == ALGO_AES_128) {
            key_size = 16;
        }
        else if (type == ALGO_AES_192) {
            key_size = 24;
        }
        else if (type == ALGO_AES_256) {
            key_size = 32;
        }
        memcpy(kdata, key_ctx, key_size);
    }
    if (use_kek) {
        r = dek_encrypt(kdata, key_size);
        if (r != PICOKEY_OK) {
            return r;
        }
    }
    //r = aes_encrypt_cfb_256(file_read(pw3->data+2), session_pw3, kdata, key_size);
    //if (r != PICOKEY_OK)
    //    return r;
    r = file_put_data(ef, kdata, key_size);
    if (r != PICOKEY_OK) {
        return r;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, bool use_dek) {
    int key_size = file_get_size(fkey);
    uint8_t kdata[4096 / 8];
    if (key_size != 128 && key_size != 256 && key_size != 384 && key_size != 512) {
        return PICOKEY_WRONG_LENGTH;
    }
    memcpy(kdata, file_get_data(fkey), key_size);
    if (use_dek && dek_decrypt(kdata, key_size) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size / 2) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata + key_size / 2, key_size / 2) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    return PICOKEY_OK;
}

int load_private_key_ecdsa(mbedtls_ecp_keypair *ctx, file_t *fkey, bool use_dek) {
    int key_size = file_get_size(fkey);
    uint8_t kdata[67]; //Worst case, 521 bit + 1byte
    memcpy(kdata, file_get_data(fkey), key_size);
    if (use_dek && dek_decrypt(kdata, key_size) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    mbedtls_ecp_group_id gid = kdata[0];
    int r = mbedtls_ecp_read_key(gid, ctx, kdata + 1, key_size - 1);
    if (r != 0) {
        mbedtls_ecp_keypair_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
#ifdef MBEDTLS_EDDSA_C
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519 || ctx->grp.id == MBEDTLS_ECP_DP_ED448) {
        r = mbedtls_ecp_point_edwards(&ctx->grp, &ctx->Q, &ctx->d, random_gen, NULL);
    }
    else
#endif
    {
        r = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, random_gen, NULL);
    }
    if (r != 0) {
        mbedtls_ecdsa_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

int load_aes_key(uint8_t *aes_key, file_t *fkey) {
    int key_size = file_get_size(fkey);
    memcpy(aes_key, file_get_data(fkey), key_size);
    if (dek_decrypt(aes_key, key_size) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

static bool algorithm_attr_oid_matches(const uint8_t *attr,
                                       const uint8_t *algo,
                                       size_t algo_len) {
    if (!attr || !algo || attr[0] < 1) {
        return false;
    }
    size_t expected_len = (size_t)attr[0] - 1;
    return algo_len == expected_len &&
           memcmp(attr + 2, algo, expected_len) == 0;
}

mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len) {
    if (algorithm_attr_oid_matches(algorithm_attr_p256k1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_SECP256K1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_p256r1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_SECP256R1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_p384r1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_SECP384R1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_p521r1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_SECP521R1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_bp256r1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_BP256R1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_bp384r1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_BP384R1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_bp512r1, algo, algo_len)) {
        return MBEDTLS_ECP_DP_BP512R1;
    }
    else if (algorithm_attr_oid_matches(algorithm_attr_cv25519, algo, algo_len)) {
        return MBEDTLS_ECP_DP_CURVE25519;
    }
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
    else if (algorithm_attr_oid_matches(algorithm_attr_x448, algo, algo_len)) {
        return MBEDTLS_ECP_DP_CURVE448;
    }
#endif
#if defined(MBEDTLS_EDDSA_C) && defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
    else if (algorithm_attr_oid_matches(algorithm_attr_ed25519, algo, algo_len)) {
        return MBEDTLS_ECP_DP_ED25519;
    }
#endif
#if defined(MBEDTLS_EDDSA_C) && defined(MBEDTLS_ECP_DP_ED448_ENABLED)
    else if (algorithm_attr_oid_matches(algorithm_attr_ed448, algo, algo_len)) {
        return MBEDTLS_ECP_DP_ED448;
    }
#endif
    return MBEDTLS_ECP_DP_NONE;
}

void make_rsa_response(mbedtls_rsa_context *rsa) {
    memcpy(res_APDU, "\x7f\x49\x82\x00\x00", 5);
    res_APDU_size = 5;
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 0x82;
    put_uint16_t_be(mbedtls_mpi_size(&rsa->N), res_APDU + res_APDU_size); res_APDU_size += 2;
    mbedtls_mpi_write_binary(&rsa->N, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->N));
    res_APDU_size += mbedtls_mpi_size(&rsa->N);
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&rsa->E) & 0xff;
    mbedtls_mpi_write_binary(&rsa->E, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->E));
    res_APDU_size += mbedtls_mpi_size(&rsa->E);
    put_uint16_t_be(res_APDU_size - 5, res_APDU + 3);
}

void make_ecdsa_response(mbedtls_ecp_keypair *ecdsa) {
    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
    size_t plen = 0;
    mbedtls_ecp_point_write_binary(&ecdsa->grp,
                                   &ecdsa->Q,
                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                   &plen,
                                   pt,
                                   sizeof(pt));
    res_APDU[res_APDU_size++] = 0x7f;
    res_APDU[res_APDU_size++] = 0x49;
    if (plen >= 128) {
        res_APDU[res_APDU_size++] = 0x81;
    }
    res_APDU[res_APDU_size++] = plen + (plen >= 128 ? 3 : 2);
    res_APDU[res_APDU_size++] = 0x86;
    if (plen >= 128) {
        res_APDU[res_APDU_size++] = 0x81;
    }
    res_APDU[res_APDU_size++] = plen;
    memcpy(res_APDU + res_APDU_size, pt, plen);
    res_APDU_size += plen;
}

int rsa_sign(mbedtls_rsa_context *ctx,
             const uint8_t *data,
             size_t data_len,
             uint8_t *out,
             size_t *out_len) {
    uint8_t *d = (uint8_t *) data, *end = d + data_len, *hsh = NULL;
    size_t seq_len = 0, hash_len = 0;
    int key_size = ctx->len, r = 0;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    if (mbedtls_asn1_get_tag(&d, end, &seq_len,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0) {
        mbedtls_asn1_buf mdb;
        r = mbedtls_asn1_get_alg_null(&d, end, &mdb);
        if (r == 0) {
            if (mbedtls_asn1_get_tag(&d, end, &hash_len, MBEDTLS_ASN1_OCTET_STRING) == 0) {
                if (memcmp(mdb.p, "\x2B\x0E\x03\x02\x1A", 5) == 0) {
                    md = MBEDTLS_MD_SHA1;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", 9) == 0) {
                    md = MBEDTLS_MD_SHA224;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 9) == 0) {
                    md = MBEDTLS_MD_SHA256;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", 9) == 0) {
                    md = MBEDTLS_MD_SHA384;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 9) == 0) {
                    md = MBEDTLS_MD_SHA512;
                }
                hsh = d;
            }
        }
    }
    if (md == MBEDTLS_MD_NONE) {
        if (data_len == 32) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (data_len == 20) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (data_len == 28) {
            md = MBEDTLS_MD_SHA224;
        }
        else if (data_len == 48) {
            md = MBEDTLS_MD_SHA384;
        }
        else if (data_len == 64) {
            md = MBEDTLS_MD_SHA512;
        }
        hash_len = data_len;
        hsh = (uint8_t *) data;
    }
    if (md == MBEDTLS_MD_NONE) {
        if (data_len < key_size) { //needs padding
            memset((uint8_t *) data + data_len, 0, key_size - data_len);
        }
        r = mbedtls_rsa_private(ctx, random_gen, NULL, data, out);
    }
    else {
        r = mbedtls_rsa_pkcs1_sign(ctx, random_gen, NULL, md, hash_len, hsh, out);
    }
    *out_len = key_size;
    return r;
}

int ecdsa_sign(mbedtls_ecp_keypair *ctx,
               const uint8_t *data,
               size_t data_len,
               uint8_t *out,
               size_t *out_len) {

    int r = 0;
#ifdef MBEDTLS_EDDSA_C
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519 || ctx->grp.id == MBEDTLS_ECP_DP_ED448) {
           r = mbedtls_eddsa_write_signature(ctx, data, data_len, out, 114, out_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_gen, NULL);
    }
    else
#endif
    {
        mbedtls_mpi ri, si;
        mbedtls_mpi_init(&ri);
        mbedtls_mpi_init(&si);
        r = mbedtls_ecdsa_sign(&ctx->grp, &ri, &si, &ctx->d, data, data_len, random_gen, NULL);
        if (r == 0) {
            size_t plen = (ctx->grp.nbits + 7) / 8;
            mbedtls_mpi_write_binary(&ri, out, plen);
            mbedtls_mpi_write_binary(&si, out + plen, plen);
            *out_len = 2 * plen;
        }
        mbedtls_mpi_free(&ri);
        mbedtls_mpi_free(&si);
    }
    return r;
}

extern int cmd_select();
extern int cmd_get_data();
extern int cmd_get_next_data();
extern int cmd_put_data();
extern int cmd_verify();
extern int cmd_select_data();
extern int cmd_version_openpgp();
extern int cmd_import_data();
extern int cmd_change_pin();
extern int cmd_mse();
extern int cmd_internal_aut();
extern int cmd_challenge();
extern int cmd_activate_file();
extern int cmd_terminate_df();
extern int cmd_pso();
extern int cmd_keypair_gen();
extern int cmd_reset_retry();

#define INS_VERIFY          0x20
#define INS_MSE             0x22
#define INS_CHANGE_PIN      0x24
#define INS_PSO             0x2A
#define INS_RESET_RETRY     0x2C
#define INS_ACTIVATE_FILE   0x44
#define INS_KEYPAIR_GEN     0x47
#define INS_CHALLENGE       0x84
#define INS_INTERNAL_AUT    0x88
#define INS_SELECT          0xA4
#define INS_SELECT_DATA     0xA5
#define INS_GET_DATA        0xCA
#define INS_GET_NEXT_DATA   0xCC
#define INS_PUT_DATA        0xDA
#define INS_IMPORT_DATA     0xDB
#define INS_TERMINATE_DF    0xE6
#define INS_VERSION         0xF1

static const cmd_t cmds[] = {
    { INS_GET_DATA, cmd_get_data },
    { INS_SELECT, cmd_select },
    { INS_VERIFY, cmd_verify },
    { INS_PUT_DATA, cmd_put_data },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_KEYPAIR_GEN, cmd_keypair_gen },
    { INS_PSO, cmd_pso },
    { INS_TERMINATE_DF, cmd_terminate_df },
    { INS_ACTIVATE_FILE, cmd_activate_file },
    { INS_CHALLENGE, cmd_challenge },
    { INS_INTERNAL_AUT, cmd_internal_aut },
    { INS_MSE, cmd_mse },
    { INS_IMPORT_DATA, cmd_import_data },
    { INS_VERSION, cmd_version_openpgp },
    { INS_SELECT_DATA, cmd_select_data },
    { INS_GET_NEXT_DATA, cmd_get_next_data },
    { 0x00, 0x0 }
};

int openpgp_process_apdu() {
    int r = sm_unwrap();
    if (r != PICOKEY_OK) {
        return r > 0 ? r : SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            sm_wrap();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}

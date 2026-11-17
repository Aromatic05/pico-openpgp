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
#include "files.h"
#include "apdu.h"
#include "usb.h"
#include "pico_keys.h"
#include "random.h"
#include "eac.h"
#include "crypto_utils.h"
#include "version.h"
#include "asn1.h"
#include "mbedtls/aes.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/x509_crt.h"
#include "openpgp.h"

#define PIV_ALGO_3DES   0x03
#define PIV_ALGO_AES128 0x08
#define PIV_ALGO_AES192 0x0a
#define PIV_ALGO_AES256 0x0c
#define PIV_ALGO_RSA1024 0x06
#define PIV_ALGO_RSA2048 0x07
#define PIV_ALGO_RSA3072 0x05
#define PIV_ALGO_RSA4096 0x16
#define PIV_ALGO_ECCP256 0x11
#define PIV_ALGO_ECCP384 0x14
#define PIV_ALGO_ED25519 0xE0
#define PIV_ALGO_X25519 0xE1

#define PINPOLICY_DEFAULT 0
#define PINPOLICY_NEVER 1
#define PINPOLICY_ONCE 2
#define PINPOLICY_ALWAYS 3

#define TOUCHPOLICY_DEFAULT 0
#define TOUCHPOLICY_NEVER 1
#define TOUCHPOLICY_ALWAYS 2
#define TOUCHPOLICY_CACHED 3
#define TOUCHPOLICY_AUTO 0xFF

#define ORIGIN_GENERATED 0x01
#define ORIGIN_IMPORTED 0x02

#define IS_RETIRED(x) ((x) >= EF_PIV_KEY_RETIRED1 && (x) <= EF_PIV_KEY_RETIRED20)
#define IS_ACTIVE(x) ((x) >= EF_PIV_KEY_AUTHENTICATION && (x) <= EF_PIV_KEY_CARDAUTH)
#define IS_KEY(x) ((IS_ACTIVE((x))) || (IS_RETIRED((x))))

static uint16_t piv_key_storage_fid(uint8_t key_ref) {
    return key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref;
}

uint8_t piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};
uint8_t yk_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x1, 0x1
};

typedef struct {
    bool has_pwpiv;
    bool has_mgm;
    bool has_challenge;
    bool challenge_encrypted;
    uint8_t session_pwpiv[32];
    uint8_t challenge[16];
    bool touch_cached;
    uint8_t touch_key_ref;
    uint32_t last_touch_ms;
} piv_session_auth_t;

static piv_session_auth_t piv_auth_sessions[APDU_SESSION_COUNT];

static piv_session_auth_t *piv_auth(void) {
    return &piv_auth_sessions[apdu_current_session()];
}

#define has_pwpiv (piv_auth()->has_pwpiv)
#define has_mgm (piv_auth()->has_mgm)
#define has_challenge (piv_auth()->has_challenge)
#define challenge_encrypted (piv_auth()->challenge_encrypted)
#define session_pwpiv (piv_auth()->session_pwpiv)
#define challenge (piv_auth()->challenge)

bool piv_pin_is_verified(void) {
    return has_pwpiv;
}

const uint8_t *piv_pin_session_key(void) {
    return session_pwpiv;
}

void piv_reset_all_sessions(void) {
    mbedtls_platform_zeroize(piv_auth_sessions, sizeof(piv_auth_sessions));
}

int piv_process_apdu();

static int get_serial() {
    uint32_t serial = (pico_serial.id[0] & 0x7F) << 24 | pico_serial.id[1] << 16 | pico_serial.id[2] << 8 | pico_serial.id[3];
    return serial;
}

static int x509_create_cert(void *pk_ctx, uint8_t algo, uint8_t slot, bool attestation, uint8_t *buffer, size_t buffer_size) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20240325000000", "20741231235959");
    uint8_t serial[16];
    random_gen(NULL, serial, sizeof(serial));
    size_t serial_offset = 0;
    while (serial_offset + 1 < sizeof(serial) && serial[serial_offset] == 0) {
        serial_offset++;
    }
    if (serial_offset == sizeof(serial) - 1 && serial[serial_offset] == 0) {
        serial[serial_offset] = 1;
    }
    int ret = mbedtls_x509write_crt_set_serial_raw(
        &ctx, serial + serial_offset, sizeof(serial) - serial_offset);
    if (ret != 0) {
        mbedtls_x509write_crt_free(&ctx);
        return ret;
    }
    mbedtls_pk_context skey, ikey;
    mbedtls_ecdsa_context actx; // attestation key
    mbedtls_pk_init(&skey);
    mbedtls_pk_init(&ikey);
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 ||
        algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        mbedtls_pk_setup(&skey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384 ||
             algo == PIV_ALGO_ED25519 || algo == PIV_ALGO_X25519) {
        mbedtls_pk_setup(&skey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    }
    skey.pk_ctx = pk_ctx;
    mbedtls_x509write_crt_set_subject_key(&ctx, &skey);
    char buf_sname[256];
    if (attestation) {
        sprintf(buf_sname, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Attestation %X", slot);
        mbedtls_x509write_crt_set_subject_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_issuer_name(&ctx, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot F9");
        file_t *ef_key = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_EF);
        if (!file_has_data(ef_key)) {
            mbedtls_x509write_crt_free(&ctx);
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        mbedtls_ecdsa_init(&actx);
        ret = load_private_key_ecdsa(&actx, ef_key, false);
        if (ret != PICOKEY_OK) {
            mbedtls_ecdsa_free(&actx);
            mbedtls_x509write_crt_free(&ctx);
            return ret;
        }
        ret = mbedtls_pk_setup(&ikey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0) {
            mbedtls_ecdsa_free(&actx);
            mbedtls_x509write_crt_free(&ctx);
            return ret;
        }
        ikey.pk_ctx = &actx;
        mbedtls_x509write_crt_set_issuer_key(&ctx, &ikey);
        uint8_t ver[] = {PIV_VERSION_MAJOR, PIV_VERSION_MINOR, 0};
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x03", 10, 0, ver, sizeof(ver));
        uint8_t serial_ext[7];
        uint8_t *serial_ext_p = serial_ext + sizeof(serial_ext);
        int serial_ext_len = mbedtls_asn1_write_int(&serial_ext_p, serial_ext, get_serial());
        if (serial_ext_len < 0) {
            mbedtls_ecdsa_free(&actx);
            mbedtls_x509write_crt_free(&ctx);
            return serial_ext_len;
        }
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x07", 10, 0,
                                            serial_ext_p, (size_t)serial_ext_len);
        uint8_t *meta = NULL;
        uint16_t meta_len = meta_find(slot, &meta);
        if (meta_len >= 3) {
            mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x08", 10, 0,
                                                &meta[1], 2);
        }
        uint8_t form_factor = 1;
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x09", 10, 0,
                                            &form_factor, sizeof(form_factor));
    }
    else {
        uint8_t wslot = slot;
        if (slot == EF_PIV_KEY_ATTESTATION) {
            wslot = 0xF9;
        }
        else if (slot == EF_PIV_KEY_RETIRED18) {
            wslot = 0x93;
        }
        sprintf(buf_sname, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot %X", wslot);
        mbedtls_x509write_crt_set_issuer_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_subject_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_issuer_key(&ctx, &skey);
    }
    if (!attestation && algo == PIV_ALGO_ECCP384) {
        mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA384);
    }
    else {
        mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
    }
    if (slot == EF_PIV_KEY_ATTESTATION) {
        mbedtls_x509write_crt_set_basic_constraints(&ctx, 1, 1);
    }
    else {
        mbedtls_x509write_crt_set_basic_constraints(&ctx, 0, 0);
    }
    mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
    mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
    mbedtls_x509write_crt_set_key_usage(&ctx,
                                        MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                        MBEDTLS_X509_KU_KEY_CERT_SIGN);
    ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, random_gen, NULL);
    /* skey cannot be freed, as it is freed later */
    if (attestation) {
        mbedtls_ecdsa_free(&actx);
    }
    mbedtls_x509write_crt_free(&ctx);
    return ret;
}

static int scan_files_piv() {
    scan_flash();
    file_t *ef = search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_EF);
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 0, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
        else if (file_get_size(ef) == 7) {
            printf("PW status is older. Initializing to default\r\n");
            uint8_t def[9] = { 0 };
            memcpy(def, file_get_data(ef), 7);
            def[7] = def[8] = 3; // PIV retries
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW retries is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 3, 3, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
        else if (file_get_size(ef) == 4) {
            printf("PW retries is older. Initializing to default\r\n");
            uint8_t def[6] = { 0 };
            memcpy(def, file_get_data(ef), 4);
            def[4] = def[5] = 3; // PIV retries
            file_put_data(ef, def, sizeof(def));
        }
    }
    bool reset_dek = false;
    if ((ef = search_by_fid(EF_DEK, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0 || file_get_size(ef) == IV_SIZE+32*3) {
            printf("DEK is empty or older\r\n");
            const uint8_t defpin[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            const uint8_t *initial_dek = random_bytes_get(IV_SIZE + 32);
            uint8_t def[IV_SIZE + 32 + 32 + 32 + 32];
            if (file_get_size(ef) > 0) {
                memcpy(def, file_get_data(ef), file_get_size(ef));
            }
            else {
                memcpy(def, initial_dek, IV_SIZE);
            }
            memcpy(def + IV_SIZE + 32*3, initial_dek + IV_SIZE, 32);
            hash_multi(defpin, sizeof(defpin), session_pwpiv);
            aes_encrypt_cfb_256(session_pwpiv, def, def + IV_SIZE + 32*3, 32);
            file_put_data(ef, def, sizeof(def));
            reset_dek = true;
        }
    }
    static const uint8_t default_mgm_key[24] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    file_t *mgm = search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_EF);
    uint8_t *meta = NULL;
    uint16_t meta_len = meta_find(EF_PIV_KEY_CARDMGM, &meta);
    if (!file_has_data(mgm)) {
        file_put_data(mgm, default_mgm_key, sizeof(default_mgm_key));
        uint8_t default_meta[] = { PIV_ALGO_AES192, PINPOLICY_ALWAYS, TOUCHPOLICY_NEVER };
        meta_add(EF_PIV_KEY_CARDMGM, default_meta, sizeof(default_meta));
    }
    else if (file_get_size(mgm) == sizeof(default_mgm_key) &&
             memcmp(file_get_data(mgm), default_mgm_key, sizeof(default_mgm_key)) == 0 &&
             meta_len == 3 && meta[0] == PIV_ALGO_3DES) {
        uint8_t fixed_meta[3] = { PIV_ALGO_AES192, meta[1], TOUCHPOLICY_NEVER };
        meta_add(EF_PIV_KEY_CARDMGM, fixed_meta, sizeof(fixed_meta));
    }
    if ((ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PIV PIN is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            file_put_data(ef, dhash, sizeof(dhash));
        }
    }
    if ((ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PIV PUK is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            file_put_data(ef, dhash, sizeof(dhash));
        }
    }
    if ((ef = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("ATTESTATION key is empty. Initializing with random one\r\n");
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            int r = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP384R1, random_gen, NULL);
            uint8_t cert[2048];
            if (r == 0) {
                r = x509_create_cert(&ecdsa, PIV_ALGO_ECCP384, EF_PIV_KEY_ATTESTATION, false, cert, sizeof(cert));
            }
            if (r <= 0 || (size_t)r > sizeof(cert)) {
                mbedtls_ecdsa_free(&ecdsa);
                return PICOKEY_EXEC_ERROR;
            }
            uint16_t cert_len = (uint16_t)r;
            r = store_keys(&ecdsa, ALGO_ECDSA, EF_PIV_KEY_ATTESTATION, false);
            mbedtls_ecdsa_free(&ecdsa);
            if (r != PICOKEY_OK) {
                return r;
            }
            ef = search_by_fid(EF_PIV_ATTESTATION, NULL, SPECIFY_ANY);
            if (!ef) {
                return PICOKEY_ERR_FILE_NOT_FOUND;
            }
            r = file_put_data(ef, cert + sizeof(cert) - cert_len, cert_len);
            if (r != PICOKEY_OK) {
                return r;
            }
        }
    }
    low_flash_available();
    return PICOKEY_OK;
}

static void reset_piv_pin_session(void) {
    has_pwpiv = false;
    mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
}

static void reset_piv_session(void) {
    reset_piv_pin_session();
    has_mgm = false;
    has_challenge = false;
    challenge_encrypted = false;
    piv_auth()->touch_cached = false;
    piv_auth()->touch_key_ref = 0;
    piv_auth()->last_touch_ms = 0;
    mbedtls_platform_zeroize(challenge, sizeof(challenge));
}

int init_piv() {
    int ret = scan_files_piv();
    reset_piv_session();
    return ret;
}

int piv_unload() {
    reset_piv_session();
    return PICOKEY_OK;
}

void select_piv_aid() {
    res_APDU[res_APDU_size++] = 0x61;
    res_APDU[res_APDU_size++] = 0; //filled later
    res_APDU[res_APDU_size++] = 0x4F;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = 0x00;
    res_APDU[res_APDU_size++] = 0x79;
    res_APDU[res_APDU_size++] = 9;
    memcpy(res_APDU + res_APDU_size, "\xA0\x00\x00\x03\x08\x00\x00\x10\x00", 9);
    res_APDU_size += 9;
    const char *app_label = "Pico Keys PIV";
    res_APDU[res_APDU_size++] = 0x50;
    res_APDU[res_APDU_size++] = strlen(app_label);
    memcpy(res_APDU + res_APDU_size, app_label, strlen(app_label));

    res_APDU[res_APDU_size++] = 0xAC;
    res_APDU[res_APDU_size++] = 12;
    res_APDU[res_APDU_size++] = 0x80;
    res_APDU[res_APDU_size++] = 7;
    memcpy(res_APDU + res_APDU_size, "\x07\x08\x0A\x0C\x11\x14\x2E", 7);
    res_APDU_size += 7;
    res_APDU[res_APDU_size++] = 0x6;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;
}

int piv_select_aid(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = piv_process_apdu;
    a->unload = piv_unload;
    int ret = init_piv();
    if (ret != PICOKEY_OK) return ret;
    select_piv_aid();
    return PICOKEY_OK;
}

INITIALIZER( piv_ctor ) {
    register_app(piv_select_aid, piv_aid);
    register_app(piv_select_aid, yk_aid);
}

static int cmd_version() {
    res_APDU[res_APDU_size++] = PIV_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIV_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0x0;
    return SW_OK();
}

static int cmd_select() {
    if (P2(apdu) != 0x1) {
        return SW_WRONG_P1P2();
    }
    if (memcmp(apdu.data, piv_aid, 5) == 0) {
        select_piv_aid();
    }
    return SW_OK();
}

int piv_parse_discovery(const file_t *ef) {
    memcpy(res_APDU, "\x7E\x12\x4F\x0B\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00\x5F\x2F\x02\x40\x10", 20);
    res_APDU_size = 20;
    return res_APDU_size;
}

static int cmd_get_serial() {
    uint32_t serial = get_serial();
    res_APDU[res_APDU_size++] = serial >> 24;
    res_APDU[res_APDU_size++] = serial >> 16;
    res_APDU[res_APDU_size++] = serial >> 8;
    res_APDU[res_APDU_size++] = serial & 0xFF;
    return SW_OK();
}

extern int check_pin(const file_t *pin, const uint8_t *data, size_t len);
static int cmd_verify() {
    uint8_t key_ref = P2(apdu);
    if (P1(apdu) != 0x00 && P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (key_ref != 0x80) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *pw, *pw_status;
    uint16_t fid = EF_PIV_PIN;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw)[0] == 0) { //not initialized
        return SW_REFERENCE_NOT_FOUND();
    }
    if (apdu.nc > 0) {
        uint16_t ret = check_pin(pw, apdu.data, apdu.nc);
        if (ret == 0x9000) {
            has_pwpiv = true;
            hash_multi(apdu.data, apdu.nc, session_pwpiv);
        }
        return ret; //SW already set
    }
    uint8_t retries = *(file_get_data(pw_status) + 3 + (fid & 0xf));
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((key_ref == 0x80 && has_pwpiv)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | retries);
}

static int cmd_get_data() {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.data[0] != 0x5C || (apdu.data[1] & 0x80) || apdu.data[1] >= 4 || apdu.data[1] == 0) {
        return SW_WRONG_DATA();
    }
    uint32_t fid = apdu.data[2];
    for (uint8_t lt = 1; lt < apdu.data[1]; lt++) {
        fid <<= 8;
        fid |= apdu.data[2 + lt];
    }
    if ((fid & 0xFFFF00) != 0x5FC100 && (fid & 0xFFFF) != EF_PIV_BITGT && (fid & 0xFFFF) != EF_PIV_DISCOVERY && (fid & 0xFFFF) != EF_PIV_ATTESTATION) {
        return SW_FILE_NOT_FOUND();
    }
    file_t *ef = NULL;
    if ((ef = search_by_fid((uint16_t)(fid & 0xFFFF), NULL, SPECIFY_EF))) {
        uint16_t data_len = 0;
        res_APDU_size = 2; // Minimum: TAG+LEN
        if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            data_len = ((int (*)(const file_t *))(ef->data))((const file_t *) ef);
        }
        else {
            if (ef->data) {
                data_len = file_get_size(ef);
                if (data_len > USB_BUFFER_SIZE - 16) {
                    return SW_MEMORY_FAILURE();
                }
                memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
            }
        }
        if (data_len == 0) {
            return SW_FILE_NOT_FOUND();
        }
        if ((uint16_t)fid == EF_PIV_ATTESTATION) {
            /* F9 stores raw DER. GET DATA must return a PIV certificate
             * object inside 53: 70 <DER>, 71 01 00, FE 00. */
            uint8_t length_size = format_tlv_len(data_len, NULL);
            memmove(res_APDU + 3 + length_size, res_APDU + 2, data_len);
            res_APDU[2] = 0x70;
            format_tlv_len(data_len, res_APDU + 3);
            data_len += 1 + length_size;
            memcpy(res_APDU + 2 + data_len, "\x71\x01\x00\xFE\x00", 5);
            data_len += 5;
        }
        if (data_len > 255) {
            memmove(res_APDU + res_APDU_size + 2, res_APDU + res_APDU_size, data_len);
        }
        else if (data_len > 127) {
            memmove(res_APDU + res_APDU_size + 1, res_APDU + res_APDU_size, data_len);
        }
        res_APDU[0] = 0x53;
        res_APDU_size = 1 + format_tlv_len(data_len, res_APDU + 1) + data_len;
    }
    else {
        return SW_FILE_NOT_FOUND();
    }
    return SW_OK();
}

static int cmd_get_metadata() {
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint8_t *meta = NULL;
    uint16_t key_ref = P2(apdu);
    if (key_ref == 0x80) {
        key_ref = EF_PIV_PIN;
    }
    else if (key_ref == 0x81) {
        key_ref = EF_PIV_PUK;
    }
    uint16_t storage_fid = (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK)
                               ? key_ref
                               : piv_key_storage_fid((uint8_t)key_ref);
    file_t *ef_key = search_by_fid(storage_fid, NULL, SPECIFY_EF);
    if (!file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (key_ref != EF_PIV_PIN && key_ref != EF_PIV_PUK) {
        int meta_len = 0;
        if ((meta_len = meta_find(key_ref, &meta)) <= 0) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU[res_APDU_size++] = 0x1;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = meta[0];
        res_APDU[res_APDU_size++] = 0x2;
        res_APDU[res_APDU_size++] = 2;
        res_APDU[res_APDU_size++] = meta[1];
        res_APDU[res_APDU_size++] = meta[2];
        if (key_ref != EF_PIV_KEY_CARDMGM) {
            res_APDU[res_APDU_size++] = 0x3;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = meta[3];
            if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 || meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096 || meta[0] == PIV_ALGO_ECCP256 || meta[0] == PIV_ALGO_ECCP384 || meta[0] == PIV_ALGO_ED25519 || meta[0] == PIV_ALGO_X25519) {
                res_APDU[res_APDU_size++] = 0x4;
                res_APDU[res_APDU_size++] = 0; // Filled later
                uint8_t *pk = &res_APDU[res_APDU_size];
                if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 || meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096) {
                    mbedtls_rsa_context ctx;
                    mbedtls_rsa_init(&ctx);
                    int r = load_private_key_rsa(&ctx, ef_key, false);
                    if (r != PICOKEY_OK) {
                        mbedtls_rsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    res_APDU[res_APDU_size++] = 0x81;
                    res_APDU[res_APDU_size++] = 0x82;
                    put_uint16_t_be(mbedtls_mpi_size(&ctx.N), res_APDU + res_APDU_size); res_APDU_size += 2;
                    mbedtls_mpi_write_binary(&ctx.N, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.N));
                    res_APDU_size += mbedtls_mpi_size(&ctx.N);
                    res_APDU[res_APDU_size++] = 0x82;
                    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&ctx.E) & 0xff;
                    mbedtls_mpi_write_binary(&ctx.E, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.E));
                    res_APDU_size += mbedtls_mpi_size(&ctx.E);
                    mbedtls_rsa_free(&ctx);
                }
                else {
                    mbedtls_ecdsa_context ctx;
                    mbedtls_ecdsa_init(&ctx);
                    int r = load_private_key_ecdsa(&ctx, ef_key, false);
                    if (r != PICOKEY_OK) {
                        mbedtls_ecdsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
                    size_t plen = 0;
                    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &plen, pt, sizeof(pt));
                    mbedtls_ecdsa_free(&ctx);
                    res_APDU[res_APDU_size++] = 0x86;
                    if (plen >= 128) {
                        res_APDU[res_APDU_size++] = 0x81;
                    }
                    res_APDU[res_APDU_size++] = plen;
                    memcpy(res_APDU + res_APDU_size, pt, plen);
                    res_APDU_size += plen;
                }
                uint16_t pk_len = res_APDU_size - (pk - res_APDU);
                if (pk_len > 255) {
                    memmove(pk + 2, pk, pk_len);
                    pk[-1] = 0x82;
                    pk[0] = pk_len >> 8;
                    pk[1] = pk_len & 0xff;
                    res_APDU_size += 2;
                }
                else if (pk_len > 127) {
                    memmove(pk + 1, pk, pk_len);
                    pk[-1] = 0x81;
                    pk[0] = pk_len;
                    res_APDU_size += 1;
                }
                else {
                    pk[-1] = pk_len;
                }
            }
        }
    }
    if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK || key_ref == EF_PIV_KEY_CARDMGM) {
        uint8_t dhash[32];
        int32_t eq = 0;
        if (key_ref == EF_PIV_PIN) {
            double_hash_pin((const uint8_t *)"\x31\x32\x33\x34\x35\x36\xFF\xFF", 8, dhash);
            eq = memcmp(dhash, file_get_data(ef_key) + 1, file_get_size(ef_key) - 1);
        }
        else if (key_ref == EF_PIV_PUK) {
            double_hash_pin((const uint8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38", 8, dhash);
            eq = memcmp(dhash, file_get_data(ef_key) + 1, file_get_size(ef_key) - 1);
        }
        else if (key_ref == EF_PIV_KEY_CARDMGM) {
            eq = memcmp("\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08", file_get_data(ef_key), file_get_size(ef_key));
        }
        res_APDU[res_APDU_size++] = 0x5;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = eq == 0;
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            file_t *pw_status;
            if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t retries = *(file_get_data(pw_status) + 3 + (key_ref & 0xf));
            if (!(pw_status = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t total = *(file_get_data(pw_status) + (key_ref & 0xf));
            res_APDU[res_APDU_size++] = 0x6;
            res_APDU[res_APDU_size++] = 2;
            res_APDU[res_APDU_size++] = total;
            res_APDU[res_APDU_size++] = retries;
        }
    }
    return SW_OK();
}
static bool piv_touch_granted(uint8_t policy, uint8_t key_ref) {
    if (policy == TOUCHPOLICY_NEVER) {
        return true;
    }
    if (policy == TOUCHPOLICY_CACHED && piv_auth()->touch_cached &&
        piv_auth()->touch_key_ref == key_ref &&
        (uint32_t)(board_millis() - piv_auth()->last_touch_ms) < 15000) {
        return true;
    }
    if (policy != TOUCHPOLICY_ALWAYS && policy != TOUCHPOLICY_CACHED &&
        policy != TOUCHPOLICY_DEFAULT && policy != TOUCHPOLICY_AUTO) {
        return false;
    }
#ifndef ENABLE_EMULATION
    uint32_t button_event = EV_PRESS_BUTTON;
    if (!queue_try_add(&card_to_usb_q, &button_event)) {
        return false;
    }
    do {
        queue_remove_blocking(&usb_to_card_q, &button_event);
    } while (button_event != EV_BUTTON_PRESSED && button_event != EV_BUTTON_TIMEOUT);
    if (button_event != EV_BUTTON_PRESSED) {
        return false;
    }
#endif
    piv_auth()->touch_cached = policy == TOUCHPOLICY_CACHED;
    piv_auth()->touch_key_ref = key_ref;
    piv_auth()->last_touch_ms = board_millis();
    return true;
}

static int cmd_authenticate() {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    bool mgm_verified_now = false;
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0x7C) {
        return SW_WRONG_DATA();
    }
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        if (algo != PIV_ALGO_AES128 && algo != PIV_ALGO_AES192 && algo != PIV_ALGO_AES256 && algo != PIV_ALGO_3DES) {
            return SW_INCORRECT_P1P2();
        }
        file_t *ef_mgm = search_by_fid(key_ref, NULL, SPECIFY_EF);
        if (!file_has_data(ef_mgm)) {
            return SW_MEMORY_FAILURE();
        }
        uint16_t mgm_len = file_get_size(ef_mgm);
        if ((algo == PIV_ALGO_AES128 && mgm_len != 16) || (algo == PIV_ALGO_AES192 && mgm_len != 24) || (algo == PIV_ALGO_AES256 && mgm_len != 32) || (algo == PIV_ALGO_3DES && mgm_len != 24)) {
            return SW_INCORRECT_P1P2();
        }
    }
    uint8_t *meta = NULL;
    int meta_len = 0;
    if ((meta_len = meta_find(key_ref, &meta)) < 4) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (meta[1] == PINPOLICY_DEFAULT) {
        if (key_ref == EF_PIV_KEY_SIGNATURE) {
            meta[1] = PINPOLICY_ALWAYS;
        }
        else {
            meta[1] = PINPOLICY_ONCE;
        }
    }
    if ((meta[1] == PINPOLICY_ALWAYS || meta[1] == PINPOLICY_ONCE) && (!has_pwpiv && (key_ref == EF_PIV_KEY_AUTHENTICATION || key_ref == EF_PIV_KEY_SIGNATURE || key_ref == EF_PIV_KEY_KEYMGM || key_ref == EF_PIV_KEY_CARDAUTH || IS_RETIRED(key_ref)))) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t chal_len = (algo == PIV_ALGO_3DES ? sizeof(challenge) / 2 : sizeof(challenge));
    asn1_ctx_t ctxi, a7c = { 0 };
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (!asn1_find_tag(&ctxi, 0x7C, &a7c) || asn1_len(&ctxi) == 0) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t a80 = { 0 }, a81 = { 0 }, a82 = { 0 }, a85 = { 0 };
    asn1_find_tag(&a7c, 0x80, &a80);
    asn1_find_tag(&a7c, 0x81, &a81);
    asn1_find_tag(&a7c, 0x82, &a82);
    asn1_find_tag(&a7c, 0x85, &a85);
    if (key_ref != EF_PIV_KEY_CARDMGM &&
        ((a81.data && a81.len > 0) || (a85.data && a85.len > 0)) &&
        !piv_touch_granted(meta[2], key_ref)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (a80.data) {
        if (a80.len == 0) {
            memcpy(challenge, random_bytes_get(sizeof(challenge)), sizeof(challenge));
            if (algo == PIV_ALGO_AES128 || algo == PIV_ALGO_AES192 || algo == PIV_ALGO_AES256 || algo == PIV_ALGO_3DES) {
                if (key_ref != EF_PIV_KEY_CARDMGM) {
                    return SW_INCORRECT_P1P2();
                }
                file_t *ef_mgm = search_by_fid(key_ref, NULL, SPECIFY_EF);
                if (!file_has_data(ef_mgm)) {
                    return SW_MEMORY_FAILURE();
                }
                uint16_t mgm_len = file_get_size(ef_mgm);
                res_APDU[res_APDU_size++] = 0x7C;
                res_APDU[res_APDU_size++] = chal_len + 2;
                res_APDU[res_APDU_size++] = 0x80;
                res_APDU[res_APDU_size++] = chal_len;
                int r = 0;
                if (algo == PIV_ALGO_3DES) {
                    mbedtls_des3_context ctx;
                    mbedtls_des3_init(&ctx);
                    r = mbedtls_des3_set3key_enc(&ctx, file_get_data(ef_mgm));
                    if (r != 0) {
                        mbedtls_des3_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    r = mbedtls_des3_crypt_ecb(&ctx, challenge, res_APDU + res_APDU_size);
                    res_APDU_size += 8;
                    mbedtls_des3_free(&ctx);
                }
                else {
                    mbedtls_aes_context ctx;
                    mbedtls_aes_init(&ctx);
                    r = mbedtls_aes_setkey_enc(&ctx, file_get_data(ef_mgm), mgm_len * 8);
                    if (r != 0) {
                        mbedtls_aes_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, challenge, res_APDU + res_APDU_size);
                    res_APDU_size += 16;
                    mbedtls_aes_free(&ctx);
                }
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                has_challenge = true;
                challenge_encrypted = true;
            }
        }
        else {
            if (key_ref != EF_PIV_KEY_CARDMGM) {
                return SW_INCORRECT_P1P2();
            }
            if (!has_challenge || !challenge_encrypted || a80.len != chal_len || a81.len != chal_len) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            has_challenge = false;
            challenge_encrypted = false;
            if (mbedtls_ct_memcmp(a80.data, challenge, chal_len) != 0) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            mgm_verified_now = true;
        }
    }
    if (a81.data) {
        if (!a81.len) {
            memcpy(challenge, random_bytes_get(sizeof(challenge)), sizeof(challenge));
            res_APDU[res_APDU_size++] = 0x7C;
            res_APDU[res_APDU_size++] = chal_len + 2;
            res_APDU[res_APDU_size++] = 0x81;
            res_APDU[res_APDU_size++] = chal_len;
            memcpy(res_APDU + res_APDU_size, challenge, chal_len);
            res_APDU_size += chal_len;
            has_challenge = true;
            challenge_encrypted = false;
        }
        else {
            file_t *ef_key = search_by_fid(piv_key_storage_fid(key_ref), NULL, SPECIFY_EF);
            if (!file_has_data(ef_key)) {
                return SW_MEMORY_FAILURE();
            }
            if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
                mbedtls_rsa_context ctx;
                mbedtls_rsa_init(&ctx);
                int r = load_private_key_rsa(&ctx, ef_key, false);
                if (r != PICOKEY_OK) {
                    mbedtls_rsa_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                size_t olen = mbedtls_rsa_get_len(&ctx);
                if (olen != a81.len || olen > 512) {
                    mbedtls_rsa_free(&ctx);
                    return SW_WRONG_LENGTH();
                }
                if (algo == PIV_ALGO_RSA1024) {
                    memcpy(res_APDU, "\x7C\x81\x00\x82\x81\x00", 6);
                    res_APDU_size = 6;
                }
                else {
                    memcpy(res_APDU, "\x7C\x82\x00\x00\x82\x82\x00\x00", 8);
                    res_APDU_size = 8;
                }
                r = mbedtls_rsa_private(&ctx, random_gen, NULL, a81.data, res_APDU + res_APDU_size);
                mbedtls_rsa_free(&ctx);
                if (algo == PIV_ALGO_RSA1024) {
                    res_APDU[res_APDU_size - 1] = olen;
                    res_APDU[res_APDU_size - 4] = olen + 3;
                }
                else {
                    res_APDU[res_APDU_size - 2] = olen >> 8;
                    res_APDU[res_APDU_size - 1] = olen & 0xFF;
                    res_APDU[res_APDU_size - 6] = (olen + 4) >> 8;
                    res_APDU[res_APDU_size - 5] = (olen + 4) & 0xFF;
                }
                res_APDU_size += olen;
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
            else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
                mbedtls_ecdsa_context ctx;
                mbedtls_ecdsa_init(&ctx);
                int r = load_private_key_ecdsa(&ctx, ef_key, false);
                if (r != PICOKEY_OK) {
                    mbedtls_ecdsa_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                size_t olen = 0;
                memcpy(res_APDU, "\x7C\x00\x82\x00", 4);
                res_APDU_size = 4;
                r = mbedtls_ecdsa_write_signature(&ctx, algo == PIV_ALGO_ECCP256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA384, a81.data, a81.len, res_APDU + res_APDU_size, MBEDTLS_ECDSA_MAX_LEN, &olen, random_gen, NULL);
                mbedtls_ecdsa_free(&ctx);
                res_APDU[res_APDU_size - 1] = olen;
                res_APDU[res_APDU_size - 3] = olen + 2;
                res_APDU_size += olen;
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
#ifdef MBEDTLS_EDDSA_C
            else if (algo == PIV_ALGO_ED25519) {
                mbedtls_ecp_keypair ctx;
                mbedtls_ecp_keypair_init(&ctx);
                int r = load_private_key_ecdsa(&ctx, ef_key, false);
                if (r != PICOKEY_OK || ctx.grp.id != MBEDTLS_ECP_DP_ED25519) {
                    mbedtls_ecp_keypair_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                size_t olen = 0;
                memcpy(res_APDU, "\x7C\x00\x82\x00", 4);
                res_APDU_size = 4;
                r = ecdsa_sign(&ctx, a81.data, a81.len,
                               res_APDU + res_APDU_size, &olen);
                mbedtls_ecp_keypair_free(&ctx);
                if (r != 0 || olen != 64) {
                    return SW_EXEC_ERROR();
                }
                res_APDU[res_APDU_size - 1] = (uint8_t)olen;
                res_APDU[res_APDU_size - 3] = (uint8_t)(olen + 2);
                res_APDU_size += olen;
            }
#endif
            else if (algo == PIV_ALGO_AES128 || algo == PIV_ALGO_AES192 || algo == PIV_ALGO_AES256 || algo == PIV_ALGO_3DES) {
                uint16_t key_len = file_get_size(ef_key);
                if (a81.len != chal_len) {
                    return SW_DATA_INVALID();
                }
                res_APDU[0] = 0x7C;
                res_APDU[1] = chal_len + 2;
                res_APDU[2] = 0x82;
                res_APDU[3] = chal_len;
                res_APDU_size = 4;
                int r = 0;
                if (algo == PIV_ALGO_3DES) {
                    mbedtls_des3_context ctx;
                    mbedtls_des3_init(&ctx);
                    r = mbedtls_des3_set3key_enc(&ctx, file_get_data(ef_key));
                    if (r != 0) {
                        mbedtls_des3_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    r = mbedtls_des3_crypt_ecb(&ctx, a81.data, res_APDU + res_APDU_size);
                    mbedtls_des3_free(&ctx);
                    res_APDU_size += 8;
                }
                else {
                    mbedtls_aes_context ctx;
                    mbedtls_aes_init(&ctx);
                    r = mbedtls_aes_setkey_enc(&ctx, file_get_data(ef_key), key_len * 8);
                    if (r != 0) {
                        mbedtls_aes_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, a81.data, res_APDU + res_APDU_size);
                    mbedtls_aes_free(&ctx);
                    res_APDU_size += 16;
                }
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
        }
    }
    if (a82.data) {
        if (!a82.len) {
            // Should be handled by a81 or a80
        }
        else {
            if (key_ref != EF_PIV_KEY_CARDMGM) {
                return SW_INCORRECT_P1P2();
            }
            if (!has_challenge) {
                return SW_INCORRECT_PARAMS();
            }
            if (chal_len != a82.len) {
                return SW_DATA_INVALID();
            }
            file_t *ef_key = search_by_fid(piv_key_storage_fid(key_ref), NULL, SPECIFY_EF);
            if (!file_has_data(ef_key)) {
                return SW_MEMORY_FAILURE();
            }
            uint16_t key_len = file_get_size(ef_key);
            int r = 0;
            if (algo == PIV_ALGO_3DES)
            {
                mbedtls_des3_context ctx;
                mbedtls_des3_init(&ctx);
                r = mbedtls_des3_set3key_dec(&ctx, file_get_data(ef_key));
                if (r != 0) {
                    mbedtls_des3_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                r = mbedtls_des3_crypt_ecb(&ctx, a82.data, res_APDU);
                mbedtls_des3_free(&ctx);
            }
            else {
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                r = mbedtls_aes_setkey_dec(&ctx, file_get_data(ef_key), key_len * 8);
                if (r != 0) {
                    mbedtls_aes_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, a82.data, res_APDU);
                mbedtls_aes_free(&ctx);
            }
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            if (mbedtls_ct_memcmp(res_APDU, challenge, chal_len) != 0) {
                return SW_DATA_INVALID();
            }
            has_challenge = false;
            challenge_encrypted = false;
        }
    }
    if (a85.data) {
        if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384 || algo == PIV_ALGO_X25519) {
            file_t *ef_key = search_by_fid(piv_key_storage_fid(key_ref), NULL, SPECIFY_EF);
            if (!file_has_data(ef_key)) {
                return SW_MEMORY_FAILURE();
            }
            mbedtls_ecdsa_context ecdsa_ctx;
            mbedtls_ecdsa_init(&ecdsa_ctx);
            int r = load_private_key_ecdsa(&ecdsa_ctx, ef_key, false);
            if (r != PICOKEY_OK) {
                mbedtls_ecdsa_free(&ecdsa_ctx);
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdh_context ecdh_ctx;
            mbedtls_ecdh_init(&ecdh_ctx);
            mbedtls_ecp_group_id gid = ecdsa_ctx.grp.id;
            r = mbedtls_ecdh_setup(&ecdh_ctx, gid);
            if (r != 0) {
                mbedtls_ecdsa_free(&ecdsa_ctx);
                mbedtls_ecdh_free(&ecdh_ctx);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_mpi_copy(&ecdh_ctx.ctx.mbed_ecdh.d, &ecdsa_ctx.d);
            mbedtls_ecdsa_free(&ecdsa_ctx);
            if (r != 0) {
                mbedtls_ecdh_free(&ecdh_ctx);
                return SW_EXEC_ERROR();
            }
            // mbedtls_ecdh_read_public expects TLS format: [length][point_data].
            // PIV tag 0x85 carries the raw public point/key bytes.
            if (a85.len > MBEDTLS_ECP_MAX_PT_LEN) {
                mbedtls_ecdh_free(&ecdh_ctx);
                return SW_WRONG_LENGTH();
            }
            uint8_t pub_buf[1 + MBEDTLS_ECP_MAX_PT_LEN];
            pub_buf[0] = (uint8_t)a85.len;
            memcpy(pub_buf + 1, a85.data, a85.len);
            r = mbedtls_ecdh_read_public(&ecdh_ctx, pub_buf, a85.len + 1);
            if (r != 0) {
                mbedtls_ecdh_free(&ecdh_ctx);
                return SW_DATA_INVALID();
            }
            size_t olen = 0;
            uint8_t shared_secret[MBEDTLS_ECP_MAX_BYTES];
            r = mbedtls_ecdh_calc_secret(&ecdh_ctx, &olen, shared_secret,
                                          sizeof(shared_secret), random_gen, NULL);
            mbedtls_ecdh_free(&ecdh_ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU[res_APDU_size++] = 0x7C;
            res_APDU[res_APDU_size++] = olen + 2;
            res_APDU[res_APDU_size++] = 0x82;
            res_APDU[res_APDU_size++] = olen;
            memcpy(res_APDU + res_APDU_size, shared_secret, olen);
            res_APDU_size += olen;
            mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        }
        else {
            return SW_INCORRECT_P1P2();
        }
    }
    if (meta[1] == PINPOLICY_ALWAYS) {
        reset_piv_pin_session();
    }
    if (mgm_verified_now) {
        if (!piv_touch_granted(meta[2], key_ref)) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        has_mgm = true;
    }
    return SW_OK();
}

static void piv_clear_generated_key(uint8_t key_ref) {
    file_t *key = search_by_fid(piv_key_storage_fid(key_ref), NULL, SPECIFY_EF);
    flash_clear_file(key);
    meta_delete(key_ref);
    low_flash_available();
}

static int cmd_asym_keygen() {
    uint8_t key_ref = P2(apdu);
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0xAC) {
        return SW_WRONG_DATA();
    }
    if (P1(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    asn1_ctx_t ctxi, aac = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (!asn1_find_tag(&ctxi, 0xAC, &aac) || asn1_len(&aac) == 0) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t a80 = {0}, aaa = {0}, aab = {0};
    asn1_find_tag(&aac, 0x80, &a80);
    asn1_find_tag(&aac, 0xAA, &aaa);
    asn1_find_tag(&aac, 0xAB, &aab);
    if (asn1_len(&a80) == 0) {
        return SW_WRONG_DATA();
    }
    if (a80.data[0] == PIV_ALGO_RSA1024 || a80.data[0] == PIV_ALGO_RSA2048 ||
        a80.data[0] == PIV_ALGO_RSA3072 || a80.data[0] == PIV_ALGO_RSA4096) {
        printf("KEYPAIR RSA\r\n");
        asn1_ctx_t a81 = {0};
        asn1_find_tag(&aac, 0x81, &a81);
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int exponent = 65537;
        int nlen = a80.data[0] == PIV_ALGO_RSA1024 ? 1024 :
                   a80.data[0] == PIV_ALGO_RSA2048 ? 2048 :
                   a80.data[0] == PIV_ALGO_RSA3072 ? 3072 : 4096;
        if (asn1_len(&a81)) {
            exponent = (int)asn1_get_uint(&a81);
        }
        int r = mbedtls_rsa_gen_key(&rsa, random_gen, NULL, nlen, exponent);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        make_rsa_response(&rsa);
        r = store_keys(&rsa, ALGO_RSA, piv_key_storage_fid(key_ref), false);
        mbedtls_rsa_free(&rsa);
        if (r != PICOKEY_OK) {
            piv_clear_generated_key(key_ref);
            return SW_EXEC_ERROR();
        }
    }
    else if (a80.data[0] == PIV_ALGO_ECCP256 || a80.data[0] == PIV_ALGO_ECCP384 ||
             a80.data[0] == PIV_ALGO_X25519
#ifdef MBEDTLS_EDDSA_C
             || a80.data[0] == PIV_ALGO_ED25519
#endif
             ) {
        mbedtls_ecp_group_id gid = a80.data[0] == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 :
                                   a80.data[0] == PIV_ALGO_ECCP384 ? MBEDTLS_ECP_DP_SECP384R1 :
                                   a80.data[0] == PIV_ALGO_X25519 ? MBEDTLS_ECP_DP_CURVE25519 :
#ifdef MBEDTLS_EDDSA_C
                                   MBEDTLS_ECP_DP_ED25519;
#else
                                   MBEDTLS_ECP_DP_NONE;
#endif
        mbedtls_ecp_keypair ecp;
        mbedtls_ecp_keypair_init(&ecp);
        int r = mbedtls_ecp_gen_key(gid, &ecp, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
        make_ecdsa_response(&ecp);
        int storage_type = a80.data[0] == PIV_ALGO_X25519 ? ALGO_ECDH :
                           a80.data[0] == PIV_ALGO_ED25519 ? ALGO_EDDSA : ALGO_ECDSA;
        r = store_keys(&ecp, storage_type, piv_key_storage_fid(key_ref), false);
        mbedtls_ecp_keypair_free(&ecp);
        if (r != PICOKEY_OK) {
            piv_clear_generated_key(key_ref);
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_DATA_INVALID();
    }
    uint8_t def_pinpol = PINPOLICY_ONCE;
    if (key_ref == EF_PIV_KEY_SIGNATURE) {
        def_pinpol = PINPOLICY_ALWAYS;
    }
    uint8_t meta[] = {a80.data[0], asn1_len(&aaa) ? aaa.data[0] : def_pinpol, asn1_len(&aab) ? aab.data[0] : TOUCHPOLICY_ALWAYS, ORIGIN_GENERATED};
    if (meta_add(key_ref, meta, sizeof(meta)) != PICOKEY_OK) {
        piv_clear_generated_key(key_ref);
        return SW_EXEC_ERROR();
    }
    low_flash_available();
    return SW_OK();
}

static int cmd_put_data() {
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    asn1_ctx_t ctxi, a5c = {0}, a53 = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (apdu.data[0] != 0x7E && apdu.data[0] != 0x7F && (!asn1_find_tag(&ctxi, 0x5C, &a5c) || !asn1_find_tag(&ctxi, 0x53, &a53))) {
        return SW_WRONG_DATA();
    }
    if (a5c.data && a53.data) {
        if (a5c.len != 3 || a5c.data[0] != 0x5F || a5c.data[1] != 0xC1) {
            return SW_WRONG_DATA();
        }
        uint16_t fid = (a5c.data[1] << 8 | a5c.data[2]);
        file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
        if (!ef) {
            return SW_MEMORY_FAILURE();
        }
        if (a53.len > 0) {
            if (file_put_data(ef, a53.data, a53.len) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else {
            if (flash_clear_file(ef) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
        low_flash_available();
    }
    return SW_OK();
}

static int cmd_set_mgmkey() {
    if (P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    uint8_t touch = P2(apdu);
    if (touch != 0xFF && touch != 0xFE) {
        return SW_INCORRECT_P1P2();
    }
    if (touch == 0xFF) {
        touch = TOUCHPOLICY_NEVER;
    }
    else if (touch == 0xFE) {
        touch = TOUCHPOLICY_ALWAYS;
    }
    uint8_t algo = apdu.data[0], key_ref = apdu.data[1], pinlen = apdu.data[2];
    if ((key_ref != EF_PIV_KEY_CARDMGM) || (!(algo == PIV_ALGO_AES128 && pinlen == 16) && !(algo == PIV_ALGO_AES192 && pinlen == 24) && !(algo == PIV_ALGO_AES256 && pinlen == 32) && !(algo == PIV_ALGO_3DES && pinlen == 24))) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != (size_t)pinlen + 3) {
        return SW_WRONG_LENGTH();
    }
    uint8_t *meta = NULL, new_meta[4];
    int meta_len = 0;
    if ((meta_len = meta_find(key_ref, &meta)) < 4) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef = search_by_fid(key_ref, NULL, SPECIFY_ANY);
    if (!ef || file_put_data(ef, apdu.data + 3, pinlen) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    memcpy(new_meta, meta, 4);
    new_meta[0] = algo;
    new_meta[2] = touch;
    if (meta_add(key_ref, new_meta, sizeof(new_meta)) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    low_flash_available();
    piv_reset_all_sessions();
    return SW_OK();
}

static int cmd_move_key() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    uint8_t to_ref = P1(apdu), from_ref = P2(apdu);
    if ((!IS_KEY(to_ref) && to_ref != 0xFF) || !IS_KEY(from_ref) || to_ref == from_ref) {
        return SW_INCORRECT_P1P2();
    }

    uint16_t from_fid = piv_key_storage_fid(from_ref);
    uint16_t to_fid = to_ref == 0xFF ? 0xFFFF : piv_key_storage_fid(to_ref);
    file_t *source = search_by_fid(from_fid, NULL, SPECIFY_EF);
    file_t *dest = to_ref == 0xFF ? NULL : search_by_fid(to_fid, NULL, SPECIFY_EF);
    if (!file_has_data(source) || (to_ref != 0xFF && !dest)) {
        return SW_FILE_NOT_FOUND();
    }

    if (to_ref != 0xFF) {
        uint8_t meta_copy[8];
        uint8_t *meta = NULL;
        uint16_t meta_len = meta_find(from_ref, &meta);
        if (meta_len > sizeof(meta_copy)) {
            return SW_EXEC_ERROR();
        }
        if (meta_len > 0) {
            memcpy(meta_copy, meta, meta_len);
        }
        if (file_put_data(dest, file_get_data(source), file_get_size(source)) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        if (meta_len > 0 && meta_add(to_ref, meta_copy, meta_len) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }

    /* Keep the source metadata record allocated. GET METADATA is gated on key
     * presence, and reusing the record avoids flash churn on delete/regenerate. */
    if (flash_clear_file(source) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    low_flash_available();
    return SW_OK();
}

typedef struct {
    uint8_t pin[64];
    uint16_t pin_len;
    uint8_t puk[64];
    uint16_t puk_len;
    uint8_t status[16];
    uint16_t status_len;
    uint8_t limits[16];
    uint16_t limits_len;
} piv_pin_state_snapshot_t;

static int piv_snapshot_file(uint16_t fid, uint8_t *out, size_t capacity, uint16_t *out_len) {
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
    if (!file_has_data(ef)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    *out_len = file_get_size(ef);
    if (*out_len > capacity) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(out, file_get_data(ef), *out_len);
    return PICOKEY_OK;
}

static int piv_capture_pin_state(piv_pin_state_snapshot_t *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    int r = piv_snapshot_file(EF_PIV_PIN, snapshot->pin, sizeof(snapshot->pin), &snapshot->pin_len);
    if (r == PICOKEY_OK) {
        r = piv_snapshot_file(EF_PIV_PUK, snapshot->puk, sizeof(snapshot->puk), &snapshot->puk_len);
    }
    if (r == PICOKEY_OK) {
        r = piv_snapshot_file(EF_PW_PRIV, snapshot->status, sizeof(snapshot->status), &snapshot->status_len);
    }
    if (r == PICOKEY_OK) {
        r = piv_snapshot_file(EF_PW_RETRIES, snapshot->limits, sizeof(snapshot->limits), &snapshot->limits_len);
    }
    return r;
}

static int piv_restore_pin_state(const piv_pin_state_snapshot_t *snapshot) {
    file_t *pin = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_EF);
    file_t *puk = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_EF);
    file_t *status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *limits = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    int r = file_put_data(pin, snapshot->pin, snapshot->pin_len);
    if (r == PICOKEY_OK) r = file_put_data(puk, snapshot->puk, snapshot->puk_len);
    if (r == PICOKEY_OK) r = file_put_data(status, snapshot->status, snapshot->status_len);
    if (r == PICOKEY_OK) r = file_put_data(limits, snapshot->limits, snapshot->limits_len);
    return r;
}

static void piv_clear_pin_snapshot(piv_pin_state_snapshot_t *snapshot) {
    mbedtls_platform_zeroize(snapshot, sizeof(*snapshot));
}

static int piv_abort_pin_transaction(piv_pin_state_snapshot_t *snapshot) {
    int r = piv_restore_pin_state(snapshot);
    if (r == PICOKEY_OK) {
        low_flash_available();
    }
    piv_clear_pin_snapshot(snapshot);
    piv_reset_all_sessions();
    return r;
}

static int cmd_change_pin() {
    uint8_t pin_ref = P2(apdu);
    if (P1(apdu) != 0x0 || (pin_ref != 0x80 && pin_ref != 0x81)) {
        return SW_INCORRECT_P1P2();
    }
    file_t *ef = search_by_fid(pin_ref == 0x80 ? EF_PIV_PIN : EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint8_t *pin_data = file_get_data(ef);
    if (apdu.nc <= pin_data[0]) {
        return SW_WRONG_LENGTH();
    }
    uint8_t pin_len = (uint8_t)(apdu.nc - pin_data[0]);
    uint16_t ret = check_pin(ef, apdu.data, pin_data[0]);
    if (ret != 0x9000) {
        return ret;
    }
    uint8_t dhash[33];
    dhash[0] = pin_len;
    double_hash_pin(apdu.data + pin_data[0], pin_len, dhash + 1);
    if (file_put_data(ef, dhash, sizeof(dhash)) != PICOKEY_OK) {
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        return SW_MEMORY_FAILURE();
    }
    mbedtls_platform_zeroize(dhash, sizeof(dhash));
    low_flash_available();
    piv_reset_all_sessions();
    return SW_OK();
}

static int cmd_reset_retry() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x80) {
        return SW_INCORRECT_P1P2();
    }
    file_t *ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint8_t *puk_data = file_get_data(ef);
    if (apdu.nc <= puk_data[0]) {
        return SW_WRONG_LENGTH();
    }
    uint8_t pin_len = (uint8_t)(apdu.nc - puk_data[0]);
    uint16_t ret = check_pin(ef, apdu.data, puk_data[0]);
    if (ret != 0x9000) {
        return ret;
    }
    uint8_t dhash[33];
    dhash[0] = pin_len;
    double_hash_pin(apdu.data + puk_data[0], pin_len, dhash + 1);
    piv_pin_state_snapshot_t snapshot;
    if (piv_capture_pin_state(&snapshot) != PICOKEY_OK) {
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        return SW_MEMORY_FAILURE();
    }
    ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    int r = file_put_data(ef, dhash, sizeof(dhash));
    if (r == PICOKEY_OK) {
        r = pin_reset_retries_deferred(ef, true);
    }
    mbedtls_platform_zeroize(dhash, sizeof(dhash));
    if (r != PICOKEY_OK) {
        (void)piv_abort_pin_transaction(&snapshot);
        return SW_MEMORY_FAILURE();
    }
    piv_clear_pin_snapshot(&snapshot);
    low_flash_available();
    piv_reset_all_sessions();
    return SW_OK();
}

static int cmd_set_retries() {
    file_t *ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    if (!file_has_data(ef) || file_get_size(ef) != 6) {
        return SW_MEMORY_FAILURE();
    }
    piv_pin_state_snapshot_t snapshot;
    if (piv_capture_pin_state(&snapshot) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    uint8_t tmp[6];
    memcpy(tmp, file_get_data(ef), sizeof(tmp));
    tmp[4] = P1(apdu);
    tmp[5] = P2(apdu);
    int r = file_put_data(ef, tmp, sizeof(tmp));

    ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    const uint8_t def_pin[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };
    uint8_t dhash[33];
    dhash[0] = sizeof(def_pin);
    double_hash_pin(def_pin, sizeof(def_pin), dhash + 1);
    if (r == PICOKEY_OK) r = file_put_data(ef, dhash, sizeof(dhash));
    if (r == PICOKEY_OK) r = pin_reset_retries_deferred(ef, true);

    ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    const uint8_t def_puk[8] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    dhash[0] = sizeof(def_puk);
    double_hash_pin(def_puk, sizeof(def_puk), dhash + 1);
    if (r == PICOKEY_OK) r = file_put_data(ef, dhash, sizeof(dhash));
    if (r == PICOKEY_OK) r = pin_reset_retries_deferred(ef, true);

    mbedtls_platform_zeroize(tmp, sizeof(tmp));
    mbedtls_platform_zeroize(dhash, sizeof(dhash));
    if (r != PICOKEY_OK) {
        (void)piv_abort_pin_transaction(&snapshot);
        return SW_MEMORY_FAILURE();
    }

    piv_clear_pin_snapshot(&snapshot);
    low_flash_available();
    piv_reset_all_sessions();
    return SW_OK();
}

static int cmd_reset() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *pw_status;
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)))
    {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retPIN = *(file_get_data(pw_status) + 3 + (EF_PIV_PIN & 0xf)), retPUK = *(file_get_data(pw_status) + 3 + (EF_PIV_PUK & 0xf));
    if (retPIN != 0 || retPUK != 0) {
        return SW_INCORRECT_PARAMS();
    }
    if (reset_piv_storage() != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    if (init_piv() != PICOKEY_OK) return SW_EXEC_ERROR();
    piv_reset_all_sessions();
    return SW_OK();
}

static int cmd_attestation() {
    uint8_t key_ref = P1(apdu);
    if (P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (!IS_KEY(key_ref)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef_key = NULL;
    int meta_len = 0;
    uint8_t *meta = NULL;
    if (!(ef_key = search_by_fid(piv_key_storage_fid(key_ref), NULL, SPECIFY_EF)) || !file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if ((meta_len = meta_find(key_ref, &meta)) <= 0) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (meta[3] != ORIGIN_GENERATED) {
        return SW_INCORRECT_PARAMS();
    }
    int r = 0;
    if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 ||
        meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef_key, false);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, meta[0], key_ref, true, res_APDU, 2048);
        mbedtls_rsa_free(&ctx);
    }
    else if (meta[0] == PIV_ALGO_ECCP256 || meta[0] == PIV_ALGO_ECCP384 ||
             meta[0] == PIV_ALGO_ED25519 || meta[0] == PIV_ALGO_X25519) {
        mbedtls_ecp_keypair ctx;
        mbedtls_ecp_keypair_init(&ctx);
        r = load_private_key_ecdsa(&ctx, ef_key, false);
        if (r != PICOKEY_OK) {
            mbedtls_ecp_keypair_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, meta[0], key_ref, true, res_APDU, 2048);
        mbedtls_ecp_keypair_free(&ctx);
    }
    else {
        return SW_WRONG_DATA();
    }
    if (r <= 0) {
        return SW_EXEC_ERROR();
    }
    memmove(res_APDU, res_APDU + 2048 - r, r);
    res_APDU_size = r;
    return SW_OK();
}

static int cmd_import_asym() {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    asn1_ctx_t ctxi, aaa = {0}, aab = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    asn1_find_tag(&ctxi, 0xAA, &aaa);
    asn1_find_tag(&ctxi, 0xAB, &aab);
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        asn1_ctx_t a1 = { 0 }, a2 = { 0 };
        asn1_find_tag(&ctxi, 0x01, &a1);
        asn1_find_tag(&ctxi, 0x02, &a2);
        if (asn1_len(&a1) <= 0 || asn1_len(&a2) <= 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int r = mbedtls_mpi_read_binary(&rsa.P, a1.data, a1.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, a2.data, a2.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        int exponent = 65537;
        mbedtls_mpi_lset(&rsa.E, exponent);
        r = mbedtls_rsa_import(&rsa, NULL, &rsa.P, &rsa.Q, NULL, &rsa.E);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_complete(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_check_privkey(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&rsa, ALGO_RSA, piv_key_storage_fid(key_ref), false);
        mbedtls_rsa_free(&rsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384 ||
             algo == PIV_ALGO_X25519
#ifdef MBEDTLS_EDDSA_C
             || algo == PIV_ALGO_ED25519
#endif
             ) {
        asn1_ctx_t key_data = {0};
        uint16_t key_tag = algo == PIV_ALGO_ED25519 ? 0x07 :
                           algo == PIV_ALGO_X25519 ? 0x08 : 0x06;
        asn1_find_tag(&ctxi, key_tag, &key_data);
        if (asn1_len(&key_data) <= 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecp_group_id gid = algo == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 :
                                   algo == PIV_ALGO_ECCP384 ? MBEDTLS_ECP_DP_SECP384R1 :
                                   algo == PIV_ALGO_X25519 ? MBEDTLS_ECP_DP_CURVE25519 :
#ifdef MBEDTLS_EDDSA_C
                                   MBEDTLS_ECP_DP_ED25519;
#else
                                   MBEDTLS_ECP_DP_NONE;
#endif
        mbedtls_ecp_keypair ecp;
        mbedtls_ecp_keypair_init(&ecp);
        int r = mbedtls_ecp_read_key(gid, &ecp, key_data.data, key_data.len);
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
#ifdef MBEDTLS_EDDSA_C
        if (gid == MBEDTLS_ECP_DP_ED25519) {
            r = mbedtls_ecp_point_edwards(&ecp.grp, &ecp.Q, &ecp.d, random_gen, NULL);
        }
        else
#endif
        {
            r = mbedtls_ecp_mul(&ecp.grp, &ecp.Q, &ecp.d, &ecp.grp.G, random_gen, NULL);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_check_pub_priv(&ecp, &ecp, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
        int storage_type = algo == PIV_ALGO_X25519 ? ALGO_ECDH :
                           algo == PIV_ALGO_ED25519 ? ALGO_EDDSA : ALGO_ECDSA;
        r = store_keys(&ecp, storage_type, piv_key_storage_fid(key_ref), false);
        mbedtls_ecp_keypair_free(&ecp);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_WRONG_DATA();
    }
    uint8_t def_pinpol = PINPOLICY_ONCE;
    if (key_ref == EF_PIV_KEY_SIGNATURE) {
        def_pinpol = PINPOLICY_ALWAYS;
    }
    uint8_t meta[] = { algo,  asn1_len(&aaa) ? aaa.data[0] : def_pinpol, asn1_len(&aab) ? aab.data[0] : TOUCHPOLICY_ALWAYS, ORIGIN_IMPORTED };
    if (meta_add(key_ref, meta, sizeof(meta)) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}

#define INS_VERIFY          0x20
#define INS_VERSION         0xFD
#define INS_SELECT          0xA4
#define INS_YK_SERIAL       0xF8
#define INS_VERIFY          0x20
#define INS_GET_DATA        0xCB
#define INS_GET_METADATA    0xF7
#define INS_AUTHENTICATE    0x87
#define INS_ASYM_KEYGEN     0x47
#define INS_PUT_DATA        0xDB
#define INS_SET_MGMKEY      0xFF
#define INS_MOVE_KEY        0xF6
#define INS_CHANGE_PIN      0x24
#define INS_RESET_RETRY     0x2C
#define INS_SET_RETRIES     0xFA
#define INS_RESET           0xFB
#define INS_ATTESTATION     0xF9
#define INS_IMPORT_ASYM     0xFE

static const cmd_t cmds[] = {
    { INS_VERSION, cmd_version },
    { INS_SELECT, cmd_select },
    { INS_YK_SERIAL, cmd_get_serial },
    { INS_VERIFY, cmd_verify },
    { INS_GET_DATA, cmd_get_data },
    { INS_GET_METADATA, cmd_get_metadata },
    { INS_AUTHENTICATE, cmd_authenticate },
    { INS_ASYM_KEYGEN, cmd_asym_keygen },
    { INS_PUT_DATA, cmd_put_data },
    { INS_SET_MGMKEY, cmd_set_mgmkey },
    { INS_MOVE_KEY, cmd_move_key },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_SET_RETRIES, cmd_set_retries },
    { INS_RESET, cmd_reset },
    { INS_ATTESTATION, cmd_attestation },
    { INS_IMPORT_ASYM, cmd_import_asym },
    { 0x00, 0x0 }
};

int piv_process_apdu() {
    sm_unwrap();
    switch (INS(apdu)) {
        case INS_ASYM_KEYGEN:
        case INS_PUT_DATA:
        case INS_SET_MGMKEY:
        case INS_MOVE_KEY:
        case INS_SET_RETRIES:
        case INS_IMPORT_ASYM:
            if (!has_mgm) {
                sm_wrap();
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            break;
        default:
            break;
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

/*
 * Applet-local persistent reset helpers.
 *
 * PicoKeys stores OpenPGP, PIV and FIDO state in one append-only flash
 * region.  A protocol-level reset must therefore clear only the owning
 * applet's records.  Protocol-level applet resets must never call the
 * low-level whole-store initialize_flash(true) primitive.
 */

#include "openpgp.h"
#include "mbedtls/platform_util.h"
#include "random.h"

#define OPENPGP_DEK_WRAPPERS 3u
#define PIV_DEK_WRAPPER 3u
#define DEK_WRAPPER_SIZE 32u
#define DEK_MAX_SIZE (IV_SIZE + 4u * DEK_WRAPPER_SIZE)
#define PIV_ATTESTATION_META_MAX 64u

typedef struct {
    bool valid;
    uint16_t key_len;
    uint16_t cert_len;
    uint16_t meta_len;
    uint8_t *key;
    uint8_t *cert;
    uint8_t *meta;
} piv_attestation_snapshot_t;

static piv_attestation_snapshot_t piv_attestation_snapshot;

static void zeroize_free(uint8_t **ptr, uint16_t len) {
    if (*ptr != NULL) {
        mbedtls_platform_zeroize(*ptr, len);
        free(*ptr);
        *ptr = NULL;
    }
}

static void clear_piv_attestation_snapshot(void) {
    zeroize_free(&piv_attestation_snapshot.key,
                 piv_attestation_snapshot.key_len);
    zeroize_free(&piv_attestation_snapshot.cert,
                 piv_attestation_snapshot.cert_len);
    zeroize_free(&piv_attestation_snapshot.meta,
                 piv_attestation_snapshot.meta_len);
    mbedtls_platform_zeroize(&piv_attestation_snapshot,
                             sizeof(piv_attestation_snapshot));
}

void piv_cancel_device_reset(void) {
    clear_piv_attestation_snapshot();
}

static int snapshot_file(uint16_t fid, uint8_t **out, uint16_t *out_len) {
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
    *out = NULL;
    *out_len = 0;
    if (!file_has_data(ef)) {
        return PICOKEY_OK;
    }
    uint16_t len = file_get_size(ef);
    if (len > PICO_KEYS_FLASH_SECTOR_SIZE) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    uint8_t *copy = malloc(len);
    if (copy == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    memcpy(copy, file_get_data(ef), len);
    *out = copy;
    *out_len = len;
    return PICOKEY_OK;
}

int piv_prepare_device_reset(void) {
    clear_piv_attestation_snapshot();

    int r = snapshot_file(EF_PIV_KEY_ATTESTATION,
                          &piv_attestation_snapshot.key,
                          &piv_attestation_snapshot.key_len);
    if (r != PICOKEY_OK) {
        return r;
    }
    r = snapshot_file(EF_PIV_ATTESTATION,
                      &piv_attestation_snapshot.cert,
                      &piv_attestation_snapshot.cert_len);
    if (r != PICOKEY_OK) {
        clear_piv_attestation_snapshot();
        return r;
    }

    uint8_t *meta = NULL;
    uint16_t meta_len = meta_find(EF_PIV_KEY_ATTESTATION, &meta);
    if (meta_len > PIV_ATTESTATION_META_MAX) {
        clear_piv_attestation_snapshot();
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (meta_len > 0) {
        piv_attestation_snapshot.meta = malloc(meta_len);
        if (piv_attestation_snapshot.meta == NULL) {
            clear_piv_attestation_snapshot();
            return PICOKEY_ERR_NO_MEMORY;
        }
        memcpy(piv_attestation_snapshot.meta, meta, meta_len);
        piv_attestation_snapshot.meta_len = meta_len;
    }
    piv_attestation_snapshot.valid = true;
    return PICOKEY_OK;
}

int piv_restore_device_reset(void) {
    if (!piv_attestation_snapshot.valid) {
        return PICOKEY_OK;
    }

    int r = PICOKEY_OK;
    if (piv_attestation_snapshot.key_len > 0) {
        file_t *ef = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_EF);
        r = file_put_data(ef, piv_attestation_snapshot.key,
                          piv_attestation_snapshot.key_len);
    }
    if (r == PICOKEY_OK && piv_attestation_snapshot.cert_len > 0) {
        file_t *ef = search_by_fid(EF_PIV_ATTESTATION, NULL, SPECIFY_EF);
        r = file_put_data(ef, piv_attestation_snapshot.cert,
                          piv_attestation_snapshot.cert_len);
    }
    if (r == PICOKEY_OK && piv_attestation_snapshot.meta_len > 0) {
        r = meta_add(EF_PIV_KEY_ATTESTATION,
                     piv_attestation_snapshot.meta,
                     piv_attestation_snapshot.meta_len);
    }
    if (r == PICOKEY_OK) {
        low_flash_available();
    }
    clear_piv_attestation_snapshot();
    return r;
}

static int clear_flash_file(file_t *ef) {
    if (ef == NULL || (ef->type & FILE_DATA_FLASH) != FILE_DATA_FLASH || !file_has_data(ef)) {
        return PICOKEY_OK;
    }
    return flash_clear_file(ef);
}

static int reset_shared_retry_state(bool piv) {
    file_t *status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *limits = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!file_has_data(status) || !file_has_data(limits)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }

    uint16_t status_len = file_get_size(status);
    uint16_t limits_len = file_get_size(limits);
    uint8_t status_data[16];
    uint8_t limits_data[16];
    if (status_len > sizeof(status_data) || limits_len > sizeof(limits_data)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(status_data, file_get_data(status), status_len);
    memcpy(limits_data, file_get_data(limits), limits_len);

    if (!piv) {
        static const uint8_t openpgp_status[] = { 0x01, 127, 127, 127, 3, 0, 3 };
        static const uint8_t openpgp_limits[] = { 0x01, 3, 3, 3 };
        if (status_len < sizeof(openpgp_status) || limits_len < sizeof(openpgp_limits)) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        memcpy(status_data, openpgp_status, sizeof(openpgp_status));
        memcpy(limits_data, openpgp_limits, sizeof(openpgp_limits));
    }
    else {
        if (status_len < 9 || limits_len < 6) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        status_data[7] = 3;
        status_data[8] = 3;
        limits_data[4] = 3;
        limits_data[5] = 3;
    }

    int r = file_put_data(status, status_data, status_len);
    if (r == PICOKEY_OK) {
        r = file_put_data(limits, limits_data, limits_len);
    }
    mbedtls_platform_zeroize(status_data, sizeof(status_data));
    mbedtls_platform_zeroize(limits_data, sizeof(limits_data));
    return r;
}

static int wrap_dek_secret(uint8_t *record,
                           size_t wrapper_index,
                           const uint8_t *pin,
                           size_t pin_len,
                           const uint8_t secret[DEK_WRAPPER_SIZE]) {
    uint8_t wrapping_key[32];
    uint8_t *wrapper = record + IV_SIZE + wrapper_index * DEK_WRAPPER_SIZE;
    memcpy(wrapper, secret, DEK_WRAPPER_SIZE);
    hash_multi(pin, pin_len, wrapping_key);
    int r = aes_encrypt_cfb_256(wrapping_key, record, wrapper, DEK_WRAPPER_SIZE);
    mbedtls_platform_zeroize(wrapping_key, sizeof(wrapping_key));
    return r;
}

static int reset_dek_wrappers(bool piv) {
    file_t *ef = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
    if (!file_has_data(ef)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }

    uint16_t old_len = file_get_size(ef);
    const uint16_t openpgp_len = IV_SIZE + OPENPGP_DEK_WRAPPERS * DEK_WRAPPER_SIZE;
    if (old_len < openpgp_len || old_len > DEK_MAX_SIZE) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    uint16_t new_len = old_len;
    if (piv && new_len < DEK_MAX_SIZE) {
        new_len = DEK_MAX_SIZE;
    }

    uint8_t record[DEK_MAX_SIZE];
    memset(record, 0, sizeof(record));
    memcpy(record, file_get_data(ef), old_len);

    uint8_t secret[DEK_WRAPPER_SIZE];
    memcpy(secret, random_bytes_get(sizeof(secret)), sizeof(secret));
    int r = PICOKEY_OK;

    if (!piv) {
        static const uint8_t pw1[] = { '1', '2', '3', '4', '5', '6' };
        static const uint8_t pw3[] = { '1', '2', '3', '4', '5', '6', '7', '8' };
        r = wrap_dek_secret(record, 0, pw1, sizeof(pw1), secret);
        if (r == PICOKEY_OK) {
            /* Wrapper #1 is reserved for RC. Factory reset leaves RC empty,
             * so this slot must not be recoverable with any default PIN. */
            memcpy(record + IV_SIZE + DEK_WRAPPER_SIZE,
                   random_bytes_get(DEK_WRAPPER_SIZE), DEK_WRAPPER_SIZE);
        }
        if (r == PICOKEY_OK) {
            r = wrap_dek_secret(record, 2, pw3, sizeof(pw3), secret);
        }
    }
    else {
        static const uint8_t piv_pin[] = { '1', '2', '3', '4', '5', '6', 0xFF, 0xFF };
        r = wrap_dek_secret(record, PIV_DEK_WRAPPER, piv_pin, sizeof(piv_pin), secret);
    }

    if (r == PICOKEY_OK) {
        r = file_put_data(ef, record, new_len);
    }
    mbedtls_platform_zeroize(secret, sizeof(secret));
    mbedtls_platform_zeroize(record, sizeof(record));
    return r;
}

int reset_openpgp_storage() {
    file_t *piv_first = search_by_fid(EF_PIV_ADMIN_DATA, NULL, SPECIFY_EF);
    if (piv_first == NULL || piv_first <= &file_entries[1]) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }

    for (file_t *ef = &file_entries[1]; ef < piv_first; ef++) {
        if (ef->fid == EF_PW_PRIV || ef->fid == EF_DEK) {
            continue;
        }
        int r = clear_flash_file(ef);
        if (r != PICOKEY_OK) {
            return r;
        }
    }

    /* The AES key belongs to OpenPGP even though its FID is outside 0x10xx. */
    int r = clear_flash_file(search_by_fid(EF_AES_KEY, NULL, SPECIFY_EF));
    if (r != PICOKEY_OK) {
        return r;
    }
    r = reset_shared_retry_state(false);
    if (r != PICOKEY_OK) {
        return r;
    }
    r = reset_dek_wrappers(false);
    if (r != PICOKEY_OK) {
        return r;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int reset_piv_storage() {
    file_t *piv_first = search_by_fid(EF_PIV_ADMIN_DATA, NULL, SPECIFY_EF);
    file_t *shared_retries = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (piv_first == NULL || shared_retries == NULL || shared_retries <= piv_first) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }

    uint8_t attestation_meta[PIV_ATTESTATION_META_MAX] = {0};
    uint8_t *meta = NULL;
    uint16_t attestation_meta_len = meta_find(EF_PIV_KEY_ATTESTATION, &meta);
    if (attestation_meta_len > sizeof(attestation_meta)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (attestation_meta_len > 0) {
        memcpy(attestation_meta, meta, attestation_meta_len);
    }

    for (file_t *ef = piv_first; ef < shared_retries; ef++) {
        if (ef->fid == EF_PIV_ATTESTATION ||
            ef->fid == EF_PIV_KEY_ATTESTATION) {
            continue;
        }
        int r = clear_flash_file(ef);
        if (r != PICOKEY_OK) {
            mbedtls_platform_zeroize(attestation_meta, sizeof(attestation_meta));
            return r;
        }
    }

    if (attestation_meta_len > 0) {
        int r = meta_add(EF_PIV_KEY_ATTESTATION,
                         attestation_meta, attestation_meta_len);
        if (r != PICOKEY_OK) {
            mbedtls_platform_zeroize(attestation_meta, sizeof(attestation_meta));
            return r;
        }
    }
    mbedtls_platform_zeroize(attestation_meta, sizeof(attestation_meta));

    int r = reset_shared_retry_state(true);
    if (r != PICOKEY_OK) {
        return r;
    }
    r = reset_dek_wrappers(true);
    if (r != PICOKEY_OK) {
        return r;
    }
    low_flash_available();
    return PICOKEY_OK;
}

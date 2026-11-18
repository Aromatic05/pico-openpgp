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
#include "random.h"
#include "do.h"

#include "mbedtls/asn1.h"

static int save_imported_key(void *key, int type, uint16_t fid) {
    file_t *public_key = search_by_fid(fid + 3, NULL, SPECIFY_EF);
    file_t *counter = NULL;
    uint8_t old_counter[3];
    if (!public_key) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (fid == EF_PK_SIG) {
        counter = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
        if (file_get_size(counter) != sizeof(old_counter)) {
            return SW_EXEC_ERROR();
        }
        memcpy(old_counter, file_get_data(counter), sizeof(old_counter));
    }
    uint16_t old_public_len = file_get_size(public_key);
    uint8_t *old_public = NULL;
    if (old_public_len) {
        old_public = malloc(old_public_len);
        if (!old_public) {
            return SW_MEMORY_FAILURE();
        }
        memcpy(old_public, file_get_data(public_key), old_public_len);
    }

    int r = file_put_data(public_key, res_APDU, res_APDU_size);
    bool public_written = r == PICOKEY_OK;
    bool counter_written = false;
    if (r == PICOKEY_OK && counter) {
        r = file_put_data(counter, (const uint8_t[3]){0}, sizeof(old_counter));
        counter_written = r == PICOKEY_OK;
    }
    /* store_keys publishes the cached writes only after saving the private key. */
    if (r == PICOKEY_OK) {
        r = store_keys(key, type, fid, true);
    }
    if (r != PICOKEY_OK && public_written) {
        int restore_counter = counter_written
            ? file_put_data(counter, old_counter, sizeof(old_counter)) : PICOKEY_OK;
        int restore_public = old_public_len
            ? file_put_data(public_key, old_public, old_public_len) : flash_clear_file(public_key);
        if (restore_counter == PICOKEY_OK && restore_public == PICOKEY_OK) {
            low_flash_available();
        }
    }
    free(old_public);
    return r == PICOKEY_OK ? SW_OK() : SW_EXEC_ERROR();
}

int cmd_import_data() {
    file_t *ef = NULL;
    uint16_t fid = 0x0;
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_WRONG_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    uint8_t *start = apdu.data;
    const uint8_t *end = apdu.data + apdu.nc;
    size_t tgl = 0;
    if (mbedtls_asn1_get_tag(&start, end, &tgl, 0x4D) != 0 ||
        tgl != (size_t)(end - start) || start == end) {
        return SW_WRONG_DATA();
    }
    uint8_t key_ref = *start++;
    if (key_ref == 0xB6) {
        fid = EF_PK_SIG;
    }
    else if (key_ref == 0xB8) {
        fid = EF_PK_DEC;
    }
    else if (key_ref == 0xA4) {
        fid = EF_PK_AUT;
    }
    else {
        return SW_WRONG_DATA();
    }
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!has_pw3 || !authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (mbedtls_asn1_get_len(&start, end, &tgl) != 0) {
        return SW_WRONG_DATA();
    }
    start += tgl;
    if (start == end || *start++ != 0x7F ||
        mbedtls_asn1_get_tag(&start, end, &tgl, 0x48) != 0) {
        return SW_WRONG_DATA();
    }
    const uint8_t *header_end = start + tgl;
    uint8_t *p[9] = { 0 };
    uint16_t len[9] = { 0 };
    while (start < header_end) {
        uint8_t tag = *start++;
        if (!((tag >= 0x91 && tag <= 0x97) || tag == 0x99)) {
            return SW_WRONG_DATA();
        }
        /* These descriptors contain lengths only, not nested values. The
         * components follow in 5F48; bound the BER length and descriptor cursor
         * separately, then validate every component against that value. */
        size_t component_len = 0;
        if (mbedtls_asn1_get_len(&start, end, &component_len) != 0 ||
            start > header_end || component_len == 0 || len[tag - 0x91] != 0) {
            return SW_WRONG_DATA();
        }
        len[tag - 0x91] = (uint16_t)component_len;
    }
    if (start == end || *start++ != 0x5F ||
        mbedtls_asn1_get_tag(&start, end, &tgl, 0x48) != 0 ||
        tgl != (size_t)(end - start)) {
        return SW_WRONG_DATA();
    }
    for (int t = 0; t < 9; t++) {
        if (len[t] > (size_t)(end - start)) {
            return SW_WRONG_DATA();
        }
        if (len[t] > 0) {
            p[t] = start;
            start += len[t];
        }
    }
    if (start != end) {
        return SW_WRONG_DATA();
    }

    file_t *algo_ef = search_by_fid(fid - 0x0010, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    int r = 0;
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context rsa;
        if (algo_len < 3) {
            return SW_WRONG_DATA();
        }
        size_t bits = get_uint16_t_be(algo + 1);
        if ((bits != 1024 && bits != 2048 && bits != 3072 && bits != 4096) ||
            len[1] > bits / 16 || len[2] > bits / 16) {
            return SW_WRONG_DATA();
        }
        if (p[0] == NULL || len[0] == 0 || p[1] == NULL || len[1] == 0 || p[2] == NULL ||
            len[2] == 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_rsa_init(&rsa);
        r = mbedtls_mpi_read_binary(&rsa.E, p[0], len[0]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_read_binary(&rsa.P, p[1], len[1]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, p[2], len[2]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
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
        if (mbedtls_mpi_bitlen(&rsa.N) != bits) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        make_rsa_response(&rsa);
        r = save_imported_key(&rsa, ALGO_RSA, fid);
        mbedtls_rsa_free(&rsa);
    }
    else if (algo[0] == ALGO_ECDSA || algo[0] == ALGO_ECDH || algo[0] == ALGO_EDDSA) {
        mbedtls_ecp_keypair ecdsa;
        if (p[1] == NULL || len[1] == 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(algo + 1, algo_len - 1);
        if (gid == MBEDTLS_ECP_DP_NONE) {
            return SW_FUNC_NOT_SUPPORTED();
        }
        mbedtls_ecp_keypair_init(&ecdsa);
        if (gid == MBEDTLS_ECP_DP_CURVE25519) {
            mbedtls_ecp_group_load(&ecdsa.grp, gid);
            r = mbedtls_mpi_read_binary(&ecdsa.d, p[1], len[1]);
        }
        else {
            r = mbedtls_ecp_read_key(gid, &ecdsa, p[1], len[1]);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
#ifdef MBEDTLS_EDDSA_C
        if (ecdsa.grp.id == MBEDTLS_ECP_DP_ED25519) {
            r = mbedtls_ecp_point_edwards(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, random_gen, NULL);
        }
        else
#endif
        {
            r = mbedtls_ecp_mul(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, &ecdsa.grp.G, random_gen, NULL);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        make_ecdsa_response(&ecdsa);
        r = save_imported_key(&ecdsa, ALGO_ECDSA, fid);
        mbedtls_ecp_keypair_free(&ecdsa);
    }
    else {
        return SW_FUNC_NOT_SUPPORTED();
    }
    res_APDU_size = 0; //make_*_response sets a response. we need to overwrite
    return r;
}

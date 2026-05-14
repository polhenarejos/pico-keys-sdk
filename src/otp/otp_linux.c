/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include "picokeys.h"
#include "otp_platform.h"
#include "random.h"

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#define OTP_LINUX_DEFAULT_TPM_HANDLE "0x81010001"
#define OTP_LINUX_DEFAULT_PEER_KEY_FILE ".config/pico-novus/otp_peer_p256.bin"

static int derive_secp256k1_privkey_from_secret(const uint8_t *secret, size_t secret_len, uint8_t out_key32[32]) {
    int rc = -1;
    uint8_t digest[32];
    const uint8_t label[] = "pico-novus/se-ecdh-to-k1-v1";
    mbedtls_ecp_group grp;
    mbedtls_mpi x, n_minus_1;

    if (!secret || secret_len == 0 || !out_key32) {
        return -1;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, label, sizeof(label) - 1);
    mbedtls_sha256_update(&sha, secret, secret_len);
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n_minus_1);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&x, digest, sizeof(digest)) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_copy(&n_minus_1, &grp.N) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_sub_int(&n_minus_1, &n_minus_1, 1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_mod_mpi(&x, &x, &n_minus_1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_add_int(&x, &x, 1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_write_binary(&x, out_key32, 32) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    mbedtls_mpi_free(&n_minus_1);
    mbedtls_mpi_free(&x);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

static int ensure_parent_dir(const char *path) {
    char tmp[512];
    char *slash;

    if (!path || strlen(path) >= sizeof(tmp)) {
        return -1;
    }
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    slash = strrchr(tmp, '/');
    if (!slash) {
        return 0;
    }
    *slash = '\0';
    if (tmp[0] == '\0') {
        return 0;
    }

    if (mkdir(tmp, 0700) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int random_fill_buffer_rng(void *ctx, unsigned char *output, size_t output_len) {
    (void)ctx;
    random_fill_buffer(output, output_len);
    return 0;
}

static int is_valid_p256_privkey(const uint8_t priv32[32]) {
    int ok = 0;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&d, priv32, 32) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_cmp_int(&d, 1) < 0 || mbedtls_mpi_cmp_mpi(&d, &grp.N) >= 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

static int generate_valid_p256_privkey(uint8_t out_priv32[32]) {
    int rc = -1;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        goto cleanup;
    }
    if (mbedtls_ecp_gen_privkey(&grp, &d, random_fill_buffer_rng, NULL) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_write_binary(&d, out_priv32, 32) != 0) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

static int load_or_create_peer_p256_privkey(uint8_t out_priv32[32]) {
    int rc = -1;
    FILE *fp = NULL;
    const char *custom = getenv("PICO_NOVUS_PEER_KEY_FILE");
    const char *home = getenv("HOME");
    char path[512];

    if (custom && custom[0] != '\0') {
        strncpy(path, custom, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }
    else if (home && home[0] != '\0') {
        if (snprintf(path, sizeof(path), "%s/%s", home, OTP_LINUX_DEFAULT_PEER_KEY_FILE) >= (int)sizeof(path)) {
            return -1;
        }
    }
    else {
        if (snprintf(path, sizeof(path), "%s", OTP_LINUX_DEFAULT_PEER_KEY_FILE) >= (int)sizeof(path)) {
            return -1;
        }
    }

    fp = fopen(path, "rb");
    if (fp) {
        size_t n = fread(out_priv32, 1, 32, fp);
        fclose(fp);
        if (n == 32 && is_valid_p256_privkey(out_priv32)) {
            return 0;
        }
    }

    if (generate_valid_p256_privkey(out_priv32) != 0) {
        return -1;
    }

    if (ensure_parent_dir(path) != 0) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }
    if (fwrite(out_priv32, 1, 32, fp) != 32) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    chmod(path, 0600);

    rc = 0;
    return rc;
}

static int peer_priv_to_pub_point(const uint8_t priv32[32], TPM2B_ECC_POINT *pub_out) {
    int rc = -1;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};

    if (!priv32 || !pub_out) {
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&d, priv32, 32) != 0) {
        goto cleanup;
    }

    if (!is_valid_p256_privkey(priv32)) {
        goto cleanup;
    }

    if (mbedtls_ecp_mul(&grp, &q, &d, &grp.G, random_fill_buffer_rng, NULL) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_write_binary(&q.X, x, sizeof(x)) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_write_binary(&q.Y, y, sizeof(y)) != 0) {
        goto cleanup;
    }

    memset(pub_out, 0, sizeof(*pub_out));
    pub_out->point.x.size = sizeof(x);
    memcpy(pub_out->point.x.buffer, x, sizeof(x));
    pub_out->point.y.size = sizeof(y);
    memcpy(pub_out->point.y.buffer, y, sizeof(y));

    rc = 0;

cleanup:
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

static int load_or_create_tpm_p256_key(ESYS_CONTEXT *esys, TPM2_HANDLE handle, ESYS_TR *key_out) {
    TSS2_RC rc;
    ESYS_TR key = ESYS_TR_NONE;
    ESYS_TR transient = ESYS_TR_NONE;
    ESYS_TR persisted = ESYS_TR_NONE;
    TPM2B_PUBLIC in_public = {0};
    TPM2B_SENSITIVE_CREATE in_sensitive = {0};
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST *creation_hash = NULL;
    TPMT_TK_CREATION *creation_ticket = NULL;

    if (!esys || !key_out) {
        return -1;
    }
    *key_out = ESYS_TR_NONE;

    rc = Esys_TR_FromTPMPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &key);
    if (rc == TSS2_RC_SUCCESS) {
        *key_out = key;
        return 0;
    }

    in_public.publicArea.type = TPM2_ALG_ECC;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;

    rc = Esys_CreatePrimary(esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive, &in_public, &outside_info, &creation_pcr, &transient, &out_public, &creation_data, &creation_hash, &creation_ticket);
    if (rc != TSS2_RC_SUCCESS || transient == ESYS_TR_NONE) {
        fprintf(stderr, "[otp-linux] Esys_CreatePrimary failed while provisioning TPM key: 0x%x\n", rc);
        goto cleanup;
    }

    rc = Esys_EvictControl(esys, ESYS_TR_RH_OWNER, transient, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, handle, &persisted);
    if (rc != TSS2_RC_SUCCESS) {
        /* If another process persisted it first, try to load the handle again. */
        ESYS_TR retry = ESYS_TR_NONE;
        rc = Esys_TR_FromTPMPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &retry);
        if (rc == TSS2_RC_SUCCESS) {
            *key_out = retry;
            goto cleanup;
        }
        fprintf(stderr, "[otp-linux] Esys_EvictControl failed while provisioning TPM key: 0x%x\n", rc);
        goto cleanup;
    }

    if (persisted != ESYS_TR_NONE) {
        *key_out = persisted;
        persisted = ESYS_TR_NONE;
    }
    else {
        rc = Esys_TR_FromTPMPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, key_out);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "[otp-linux] Persisted key created but reload failed: 0x%x\n", rc);
            *key_out = ESYS_TR_NONE;
            goto cleanup;
        }
    }

cleanup:
    if (creation_ticket) Esys_Free(creation_ticket);
    if (creation_hash) Esys_Free(creation_hash);
    if (creation_data) Esys_Free(creation_data);
    if (out_public) Esys_Free(out_public);
    if (persisted != ESYS_TR_NONE) {
        Esys_TR_Close(esys, &persisted);
    }
    if (transient != ESYS_TR_NONE) {
        Esys_TR_Close(esys, &transient);
    }
    return (*key_out != ESYS_TR_NONE) ? 0 : -1;
}

static int linux_tpm_vault_load_or_create_key(uint8_t out_key32[32]) {
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR tpm_key = ESYS_TR_NONE;
    TPM2B_ECC_POINT peer_pub = {0};
    TPM2B_ECC_POINT *z_point = NULL;
    TPM2B_PUBLIC *tpm_pub = NULL;
    uint8_t peer_priv[32] = {0};
    uint8_t ecdh_secret[132] = {0};
    size_t ecdh_secret_len = 0;

    int rc_out = -1;
    TSS2_RC rc;

    const char *tcti_name = getenv("PICO_NOVUS_TCTI");
    const char *handle_hex = getenv("PICO_NOVUS_TPM_HANDLE");

    if (!tcti_name || tcti_name[0] == '\0') {
        tcti_name = getenv("TPM2TOOLS_TCTI");
    }
    if (!handle_hex || handle_hex[0] == '\0') {
        handle_hex = OTP_LINUX_DEFAULT_TPM_HANDLE;
    }

    if (tcti_name && tcti_name[0] != '\0') {
        rc = Tss2_TctiLdr_Initialize(tcti_name, &tcti);
    }
    else {
        rc = Tss2_TctiLdr_Initialize(NULL, &tcti);
        if (rc != TSS2_RC_SUCCESS) {
            rc = Tss2_TctiLdr_Initialize("swtpm:host=127.0.0.1,port=2321", &tcti);
            if (rc != TSS2_RC_SUCCESS) {
                rc = Tss2_TctiLdr_Initialize("mssim:host=127.0.0.1,port=2321", &tcti);
            }
        }
    }
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[otp-linux] Tss2_TctiLdr_Initialize failed: 0x%x\n", rc);
        goto cleanup;
    }
    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[otp-linux] Esys_Initialize failed: 0x%x\n", rc);
        goto cleanup;
    }

    {
        unsigned long handle_num = strtoul(handle_hex, NULL, 0);
        if (load_or_create_tpm_p256_key(esys, (TPM2_HANDLE)handle_num, &tpm_key) != 0) {
            fprintf(stderr, "[otp-linux] Cannot load/create persistent TPM key at handle: %s\n", handle_hex);
            goto cleanup;
        }
    }

    rc = Esys_ReadPublic(esys, tpm_key, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tpm_pub, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS || !tpm_pub) {
        fprintf(stderr, "[otp-linux] Esys_ReadPublic failed: 0x%x\n", rc);
        goto cleanup;
    }

    if (tpm_pub->publicArea.type != TPM2_ALG_ECC || tpm_pub->publicArea.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256) {
        fprintf(stderr, "[otp-linux] TPM key must be ECC P-256\n");
        goto cleanup;
    }

    if (load_or_create_peer_p256_privkey(peer_priv) != 0) {
        fprintf(stderr, "[otp-linux] Cannot load/create software peer key\n");
        goto cleanup;
    }

    if (peer_priv_to_pub_point(peer_priv, &peer_pub) != 0) {
        fprintf(stderr, "[otp-linux] Cannot derive software peer public key\n");
        goto cleanup;
    }

    rc = Esys_ECDH_ZGen(esys, tpm_key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &peer_pub, &z_point);
    if (rc != TSS2_RC_SUCCESS || !z_point) {
        fprintf(stderr, "[otp-linux] Esys_ECDH_ZGen failed: 0x%x\n", rc);
        goto cleanup;
    }

    if (z_point->point.x.size > 66 || z_point->point.y.size > 66) {
        fprintf(stderr, "[otp-linux] Unexpected ECDH point size\n");
        goto cleanup;
    }

    memcpy(ecdh_secret + ecdh_secret_len, z_point->point.x.buffer, z_point->point.x.size);
    ecdh_secret_len += z_point->point.x.size;
    memcpy(ecdh_secret + ecdh_secret_len, z_point->point.y.buffer, z_point->point.y.size);
    ecdh_secret_len += z_point->point.y.size;

    if (derive_secp256k1_privkey_from_secret(ecdh_secret, ecdh_secret_len, out_key32) != 0) {
        fprintf(stderr, "[otp-linux] Failed deriving secp256k1 key\n");
        goto cleanup;
    }

    rc_out = 0;

cleanup:
    if (z_point) Esys_Free(z_point);
    if (tpm_pub) Esys_Free(tpm_pub);
    if (esys) {
        if (tpm_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys, &tpm_key);
        }
        Esys_Finalize(&esys);
    }
    if (tcti) {
        Tss2_TctiLdr_Finalize(&tcti);
    }
    return rc_out;
}

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    (void)bootkey;
    (void)secure_lock;
    return PICOKEYS_OK;
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    (void)bootkey;
    return false;
}

bool otp_platform_is_secure_boot_locked(void) {
    return false;
}

void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out) {
    static uint8_t _otp1[32] = {0};
    static uint8_t _otp2[32] = {0};

    memset(_otp1, 0xAC, sizeof(_otp1));
    memset(_otp2, 0xBE, sizeof(_otp2));

    if (linux_tpm_vault_load_or_create_key(_otp2) != 0) {
        printf("[otp-linux] Warning: TPM path unavailable, using emulated otp_key_2\n");
    }

    *otp_key_1_out = _otp1;
    *otp_key_2_out = _otp2;
}

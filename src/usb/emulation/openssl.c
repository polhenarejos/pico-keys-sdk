/*
 * OpenSSL-backed compatibility layer for a subset of mbedTLS APIs used in
 * ENABLE_EMULATION builds.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
#include <openssl/cmac.h>
#endif

#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/eddsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "oid.h"

typedef struct state_node {
    const void *ctx;
    void *state;
    struct state_node *next;
} state_node_t;

const mbedtls_ecp_curve_info *openssl_mbedtls_ecp_curve_info_from_grp_id(mbedtls_ecp_group_id grp_id);

static void mpi_zero(mbedtls_mpi *X) {
    X->MBEDTLS_PRIVATE(p) = NULL;
    X->MBEDTLS_PRIVATE(s) = 1;
    X->MBEDTLS_PRIVATE(n) = 0;
}

static void mpi_trim(mbedtls_mpi *X) {
    size_t n = X->MBEDTLS_PRIVATE(n);
    while (n > 0 && X->MBEDTLS_PRIVATE(p)[n - 1] == 0) {
        n--;
    }
    if (n == 0) {
        if (X->MBEDTLS_PRIVATE(p) != NULL) {
            OPENSSL_cleanse(X->MBEDTLS_PRIVATE(p),
                            (size_t) X->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
            free(X->MBEDTLS_PRIVATE(p));
        }
        mpi_zero(X);
        return;
    }
    X->MBEDTLS_PRIVATE(n) = (unsigned short) n;
    if (X->MBEDTLS_PRIVATE(s) == 0) {
        X->MBEDTLS_PRIVATE(s) = 1;
    }
}

static int mpi_reserve_limbs(mbedtls_mpi *X, size_t nblimbs) {
    mbedtls_mpi_uint *p = NULL;
    size_t old = X->MBEDTLS_PRIVATE(n);
    if (nblimbs == 0) {
        return 0;
    }
    if (X->MBEDTLS_PRIVATE(n) >= nblimbs) {
        return 0;
    }
    p = (mbedtls_mpi_uint *) calloc(nblimbs, sizeof(mbedtls_mpi_uint));
    if (p == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    if (old > 0 && X->MBEDTLS_PRIVATE(p) != NULL) {
        memcpy(p, X->MBEDTLS_PRIVATE(p), old * sizeof(mbedtls_mpi_uint));
        OPENSSL_cleanse(X->MBEDTLS_PRIVATE(p), old * sizeof(mbedtls_mpi_uint));
        free(X->MBEDTLS_PRIVATE(p));
    }
    X->MBEDTLS_PRIVATE(p) = p;
    X->MBEDTLS_PRIVATE(n) = (unsigned short) nblimbs;
    if (X->MBEDTLS_PRIVATE(s) == 0) {
        X->MBEDTLS_PRIVATE(s) = 1;
    }
    return 0;
}

void openssl_mbedtls_mpi_init(mbedtls_mpi *X) {
    if (X != NULL) {
        mpi_zero(X);
    }
}

void openssl_mbedtls_mpi_free(mbedtls_mpi *X) {
    if (X == NULL) {
        return;
    }
    if (X->MBEDTLS_PRIVATE(p) != NULL) {
        OPENSSL_cleanse(X->MBEDTLS_PRIVATE(p),
                        (size_t) X->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
        free(X->MBEDTLS_PRIVATE(p));
    }
    mpi_zero(X);
}

int openssl_mbedtls_mpi_grow(mbedtls_mpi *X, size_t nblimbs) {
    if (X == NULL || nblimbs > MBEDTLS_MPI_MAX_LIMBS) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    return mpi_reserve_limbs(X, nblimbs);
}

int openssl_mbedtls_mpi_lset(mbedtls_mpi *X, mbedtls_mpi_sint z) {
    mbedtls_mpi_uint v = (mbedtls_mpi_uint) (z < 0 ? -z : z);
    if (X == NULL) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    if (v == 0) {
        if (X->MBEDTLS_PRIVATE(p) != NULL) {
            OPENSSL_cleanse(X->MBEDTLS_PRIVATE(p),
                            (size_t) X->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
            memset(X->MBEDTLS_PRIVATE(p), 0, (size_t) X->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
        }
        X->MBEDTLS_PRIVATE(s) = 1;
        return 0;
    }
    if (mpi_reserve_limbs(X, 1) != 0) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    X->MBEDTLS_PRIVATE(p)[0] = v;
    for (size_t i = 1; i < X->MBEDTLS_PRIVATE(n); i++) {
        X->MBEDTLS_PRIVATE(p)[i] = 0;
    }
    X->MBEDTLS_PRIVATE(s) = (z < 0) ? -1 : 1;
    mpi_trim(X);
    return 0;
}

size_t openssl_mbedtls_mpi_size(const mbedtls_mpi *X) {
    size_t n = 0;
    mbedtls_mpi_uint top = 0;
    if (X == NULL || X->MBEDTLS_PRIVATE(n) == 0 || X->MBEDTLS_PRIVATE(p) == NULL) {
        return 0;
    }
    n = X->MBEDTLS_PRIVATE(n);
    while (n > 0 && X->MBEDTLS_PRIVATE(p)[n - 1] == 0) {
        n--;
    }
    if (n == 0) {
        return 0;
    }
    top = X->MBEDTLS_PRIVATE(p)[n - 1];
    return (n - 1) * sizeof(mbedtls_mpi_uint) +
           ((8 * sizeof(mbedtls_mpi_uint) - (size_t) __builtin_clzll((unsigned long long) top) + 7) / 8);
}

static BIGNUM *mpi_to_bn_raw(const mbedtls_mpi *src) {
    size_t bytes = 0;
    size_t limbs = 0;
    unsigned char *tmp = NULL;
    BIGNUM *bn = NULL;
    if (src == NULL) {
        return NULL;
    }
    limbs = src->MBEDTLS_PRIVATE(n);
    while (limbs > 0 && src->MBEDTLS_PRIVATE(p)[limbs - 1] == 0) {
        limbs--;
    }
    if (limbs == 0) {
        bn = BN_new();
        if (bn != NULL) {
            BN_zero(bn);
        }
        return bn;
    }
    bytes = limbs * sizeof(mbedtls_mpi_uint);
    tmp = (unsigned char *) calloc(1, bytes);
    if (tmp == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < limbs; i++) {
        mbedtls_mpi_uint limb = src->MBEDTLS_PRIVATE(p)[i];
        for (size_t j = 0; j < sizeof(mbedtls_mpi_uint); j++) {
            tmp[bytes - 1 - (i * sizeof(mbedtls_mpi_uint) + j)] = (unsigned char) (limb & 0xFFu);
            limb >>= 8;
        }
    }
    bn = BN_bin2bn(tmp, (int) bytes, NULL);
    OPENSSL_cleanse(tmp, bytes);
    free(tmp);
    if (bn != NULL && src->MBEDTLS_PRIVATE(s) < 0 && !BN_is_zero(bn)) {
        BN_set_negative(bn, 1);
    }
    return bn;
}

static int bn_to_mpi_raw(const BIGNUM *bn, mbedtls_mpi *dst) {
    int is_neg = 0;
    int bn_len = 0;
    unsigned char *tmp = NULL;
    size_t limbs = 0;
    if (bn == NULL || dst == NULL) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    is_neg = BN_is_negative(bn);
    bn_len = BN_num_bytes(bn);
    if (bn_len == 0) {
        return openssl_mbedtls_mpi_lset(dst, 0);
    }
    limbs = (size_t) (bn_len + (int) sizeof(mbedtls_mpi_uint) - 1) / sizeof(mbedtls_mpi_uint);
    if (mpi_reserve_limbs(dst, limbs) != 0) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    memset(dst->MBEDTLS_PRIVATE(p), 0, dst->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
    tmp = (unsigned char *) calloc(1, (size_t) bn_len);
    if (tmp == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    if (BN_bn2bin(bn, tmp) != bn_len) {
        OPENSSL_cleanse(tmp, (size_t) bn_len);
        free(tmp);
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    for (int i = 0; i < bn_len; i++) {
        size_t idx = (size_t) i;
        size_t rev = (size_t) bn_len - 1 - idx;
        size_t limb_idx = idx / sizeof(mbedtls_mpi_uint);
        size_t limb_off = idx % sizeof(mbedtls_mpi_uint);
        dst->MBEDTLS_PRIVATE(p)[limb_idx] |=
            ((mbedtls_mpi_uint) tmp[rev]) << (8 * limb_off);
    }
    OPENSSL_cleanse(tmp, (size_t) bn_len);
    free(tmp);
    dst->MBEDTLS_PRIVATE(s) = is_neg ? -1 : 1;
    mpi_trim(dst);
    return 0;
}

int openssl_mbedtls_mpi_read_binary(mbedtls_mpi *X, const unsigned char *buf, size_t buflen) {
    BIGNUM *bn = NULL;
    int rc = 0;
    if (X == NULL || (buflen > 0 && buf == NULL)) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    if (buflen == 0) {
        return openssl_mbedtls_mpi_lset(X, 0);
    }
    bn = BN_bin2bn(buf, (int) buflen, NULL);
    if (bn == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    rc = bn_to_mpi_raw(bn, X);
    BN_free(bn);
    return rc;
}

int openssl_mbedtls_mpi_read_binary_le(mbedtls_mpi *X, const unsigned char *buf, size_t buflen) {
    unsigned char *tmp = NULL;
    int rc = 0;
    if (X == NULL || (buflen > 0 && buf == NULL)) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    tmp = (unsigned char *) calloc(1, buflen > 0 ? buflen : 1);
    if (tmp == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    for (size_t i = 0; i < buflen; i++) {
        tmp[buflen - 1 - i] = buf[i];
    }
    rc = openssl_mbedtls_mpi_read_binary(X, tmp, buflen);
    OPENSSL_cleanse(tmp, buflen > 0 ? buflen : 1);
    free(tmp);
    return rc;
}

int openssl_mbedtls_mpi_write_binary(const mbedtls_mpi *X, unsigned char *buf, size_t buflen) {
    BIGNUM *bn = NULL;
    int nbytes = 0;
    if (X == NULL || (buflen > 0 && buf == NULL)) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    bn = mpi_to_bn_raw(X);
    if (bn == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    nbytes = BN_num_bytes(bn);
    if ((size_t) nbytes > buflen) {
        BN_free(bn);
        return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }
    memset(buf, 0, buflen);
    if (nbytes > 0) {
        BN_bn2bin(bn, buf + (buflen - (size_t) nbytes));
    }
    BN_free(bn);
    return 0;
}

int openssl_mbedtls_mpi_write_binary_le(const mbedtls_mpi *X, unsigned char *buf, size_t buflen) {
    unsigned char *tmp = NULL;
    int rc = 0;
    if (X == NULL || (buflen > 0 && buf == NULL)) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    tmp = (unsigned char *) calloc(1, buflen > 0 ? buflen : 1);
    if (tmp == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    rc = openssl_mbedtls_mpi_write_binary(X, tmp, buflen);
    if (rc == 0) {
        for (size_t i = 0; i < buflen; i++) {
            buf[i] = tmp[buflen - 1 - i];
        }
    }
    OPENSSL_cleanse(tmp, buflen > 0 ? buflen : 1);
    free(tmp);
    return rc;
}

int openssl_mbedtls_mpi_copy(mbedtls_mpi *X, const mbedtls_mpi *Y) {
    if (X == NULL || Y == NULL) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    if (X == Y) {
        return 0;
    }
    if (mpi_reserve_limbs(X, Y->MBEDTLS_PRIVATE(n)) != 0) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }
    memset(X->MBEDTLS_PRIVATE(p), 0, X->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
    if (Y->MBEDTLS_PRIVATE(n) > 0 && Y->MBEDTLS_PRIVATE(p) != NULL) {
        memcpy(X->MBEDTLS_PRIVATE(p), Y->MBEDTLS_PRIVATE(p),
               Y->MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
    }
    X->MBEDTLS_PRIVATE(s) = Y->MBEDTLS_PRIVATE(s);
    mpi_trim(X);
    return 0;
}

int openssl_mbedtls_mpi_cmp_mpi(const mbedtls_mpi *X, const mbedtls_mpi *Y) {
    BIGNUM *bx = mpi_to_bn_raw(X);
    BIGNUM *by = mpi_to_bn_raw(Y);
    int rc = 0;
    if (bx == NULL || by == NULL) {
        BN_free(bx);
        BN_free(by);
        return 0;
    }
    rc = BN_cmp(bx, by);
    BN_free(bx);
    BN_free(by);
    return rc > 0 ? 1 : (rc < 0 ? -1 : 0);
}

int openssl_mbedtls_mpi_cmp_int(const mbedtls_mpi *X, mbedtls_mpi_sint z) {
    mbedtls_mpi Y;
    int rc = 0;
    openssl_mbedtls_mpi_init(&Y);
    openssl_mbedtls_mpi_lset(&Y, z);
    rc = openssl_mbedtls_mpi_cmp_mpi(X, &Y);
    openssl_mbedtls_mpi_free(&Y);
    return rc;
}

int openssl_mbedtls_mpi_add_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B) {
    BIGNUM *ba = mpi_to_bn_raw(A);
    BIGNUM *bb = mpi_to_bn_raw(B);
    BIGNUM *bo = BN_new();
    int rc = 0;
    if (ba == NULL || bb == NULL || bo == NULL || BN_add(bo, ba, bb) != 1) {
        rc = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    else {
        rc = bn_to_mpi_raw(bo, X);
    }
    BN_free(ba); BN_free(bb); BN_free(bo);
    return rc;
}

int openssl_mbedtls_mpi_add_int(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_sint b) {
    mbedtls_mpi B;
    int rc = 0;
    openssl_mbedtls_mpi_init(&B);
    openssl_mbedtls_mpi_lset(&B, b);
    rc = openssl_mbedtls_mpi_add_mpi(X, A, &B);
    openssl_mbedtls_mpi_free(&B);
    return rc;
}

int openssl_mbedtls_mpi_sub_abs(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B) {
    BIGNUM *ba = mpi_to_bn_raw(A);
    BIGNUM *bb = mpi_to_bn_raw(B);
    BIGNUM *bo = BN_new();
    int rc = 0;
    if (ba == NULL || bb == NULL || bo == NULL) {
        rc = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto out;
    }
    BN_set_negative(ba, 0);
    BN_set_negative(bb, 0);
    if (BN_cmp(ba, bb) < 0) {
        rc = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
        goto out;
    }
    if (BN_sub(bo, ba, bb) != 1) {
        rc = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto out;
    }
    rc = bn_to_mpi_raw(bo, X);
out:
    BN_free(ba); BN_free(bb); BN_free(bo);
    return rc;
}

int openssl_mbedtls_mpi_mod_mpi(mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B) {
    BIGNUM *ba = mpi_to_bn_raw(A);
    BIGNUM *bb = mpi_to_bn_raw(B);
    BIGNUM *br = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int rc = 0;
    if (ba == NULL || bb == NULL || br == NULL || ctx == NULL || BN_is_zero(bb)) {
        rc = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto out;
    }
    if (BN_nnmod(br, ba, bb, ctx) != 1) {
        rc = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto out;
    }
    rc = bn_to_mpi_raw(br, R);
out:
    BN_free(ba); BN_free(bb); BN_free(br); BN_CTX_free(ctx);
    return rc;
}

static void *state_get(state_node_t **head, const void *ctx, size_t sz, int create) {
    state_node_t *n = *head;
    while (n != NULL) {
        if (n->ctx == ctx) {
            return n->state;
        }
        n = n->next;
    }
    if (!create) {
        return NULL;
    }
    n = (state_node_t *) calloc(1, sizeof(*n));
    if (n == NULL) {
        return NULL;
    }
    n->state = calloc(1, sz);
    if (n->state == NULL) {
        free(n);
        return NULL;
    }
    n->ctx = ctx;
    n->next = *head;
    *head = n;
    return n->state;
}

static void state_del(state_node_t **head, const void *ctx, void (*cleanup)(void *)) {
    state_node_t *prev = NULL;
    state_node_t *n = *head;
    while (n != NULL) {
        if (n->ctx == ctx) {
            if (cleanup != NULL) {
                cleanup(n->state);
            }
            OPENSSL_cleanse(n->state, sizeof(n->state));
            free(n->state);
            if (prev == NULL) {
                *head = n->next;
            }
            else {
                prev->next = n->next;
            }
            free(n);
            return;
        }
        prev = n;
        n = n->next;
    }
}

static const EVP_MD *evp_md_from_type(mbedtls_md_type_t md_type) {
    switch (md_type) {
        case MBEDTLS_MD_MD5:
            return EVP_md5();
        case MBEDTLS_MD_RIPEMD160:
            return EVP_ripemd160();
        case MBEDTLS_MD_SHA1:
            return EVP_sha1();
        case MBEDTLS_MD_SHA224:
            return EVP_sha224();
        case MBEDTLS_MD_SHA256:
            return EVP_sha256();
        case MBEDTLS_MD_SHA384:
            return EVP_sha384();
        case MBEDTLS_MD_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

typedef struct {
    mbedtls_md_type_t type;
    unsigned char size;
} openssl_md_info_t;

static const openssl_md_info_t g_md_md5 = { MBEDTLS_MD_MD5, 16 };
static const openssl_md_info_t g_md_ripemd160 = { MBEDTLS_MD_RIPEMD160, 20 };
static const openssl_md_info_t g_md_sha1 = { MBEDTLS_MD_SHA1, 20 };
static const openssl_md_info_t g_md_sha224 = { MBEDTLS_MD_SHA224, 28 };
static const openssl_md_info_t g_md_sha256 = { MBEDTLS_MD_SHA256, 32 };
static const openssl_md_info_t g_md_sha384 = { MBEDTLS_MD_SHA384, 48 };
static const openssl_md_info_t g_md_sha512 = { MBEDTLS_MD_SHA512, 64 };

static const openssl_md_info_t *openssl_md_info(const mbedtls_md_info_t *md_info) {
    return (const openssl_md_info_t *) md_info;
}

const mbedtls_md_info_t *openssl_mbedtls_md_info_from_type(mbedtls_md_type_t md_type) {
    switch (md_type) {
        case MBEDTLS_MD_MD5:
            return (const mbedtls_md_info_t *) &g_md_md5;
        case MBEDTLS_MD_RIPEMD160:
            return (const mbedtls_md_info_t *) &g_md_ripemd160;
        case MBEDTLS_MD_SHA1:
            return (const mbedtls_md_info_t *) &g_md_sha1;
        case MBEDTLS_MD_SHA224:
            return (const mbedtls_md_info_t *) &g_md_sha224;
        case MBEDTLS_MD_SHA256:
            return (const mbedtls_md_info_t *) &g_md_sha256;
        case MBEDTLS_MD_SHA384:
            return (const mbedtls_md_info_t *) &g_md_sha384;
        case MBEDTLS_MD_SHA512:
            return (const mbedtls_md_info_t *) &g_md_sha512;
        default:
            return NULL;
    }
}

unsigned char openssl_mbedtls_md_get_size(const mbedtls_md_info_t *md_info) {
    if (md_info == NULL) {
        return 0;
    }
    return openssl_md_info(md_info)->size;
}

int openssl_mbedtls_md(const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
                       unsigned char *output) {
    const openssl_md_info_t *info = openssl_md_info(md_info);
    const EVP_MD *md = info != NULL ? evp_md_from_type(info->type) : NULL;
    unsigned int out_len = 0;
    if (md == NULL || output == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    if (EVP_Digest(input, ilen, output, &out_len, md, NULL) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

int openssl_mbedtls_md_hmac(const mbedtls_md_info_t *md_info, const unsigned char *key, size_t keylen,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output) {
    const openssl_md_info_t *info = openssl_md_info(md_info);
    const EVP_MD *md = info != NULL ? evp_md_from_type(info->type) : NULL;
    unsigned int out_len = 0;
    if (md == NULL || output == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    if (HMAC(md, key, (int) keylen, input, ilen, output, &out_len) == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

typedef struct {
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
} openssl_md_ctx_state_t;

void openssl_mbedtls_md_init(mbedtls_md_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
}

static void md_state_cleanup(void *ptr) {
    openssl_md_ctx_state_t *s = (openssl_md_ctx_state_t *) ptr;
    if (s != NULL && s->ctx != NULL) {
        EVP_MD_CTX_free(s->ctx);
        s->ctx = NULL;
    }
}

int openssl_mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *md_info, int hmac) {
    if (ctx == NULL || md_info == NULL || hmac != 0) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    const openssl_md_info_t *info = openssl_md_info(md_info);
    const EVP_MD *md = info != NULL ? evp_md_from_type(info->type) : NULL;
    if (md == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    openssl_md_ctx_state_t *s = (openssl_md_ctx_state_t *) calloc(1, sizeof(*s));
    if (s == NULL) {
        return MBEDTLS_ERR_MD_ALLOC_FAILED;
    }
    s->ctx = EVP_MD_CTX_new();
    if (s->ctx == NULL) {
        free(s);
        return MBEDTLS_ERR_MD_ALLOC_FAILED;
    }
    s->md = md;
    ctx->MBEDTLS_PRIVATE(md_info) = md_info;
    ctx->MBEDTLS_PRIVATE(md_ctx) = s;
    return 0;
}

int openssl_mbedtls_md_starts(mbedtls_md_context_t *ctx) {
    if (ctx == NULL || ctx->MBEDTLS_PRIVATE(md_ctx) == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    openssl_md_ctx_state_t *s = (openssl_md_ctx_state_t *) ctx->MBEDTLS_PRIVATE(md_ctx);
    if (EVP_DigestInit_ex(s->ctx, s->md, NULL) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

int openssl_mbedtls_md_update(mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen) {
    if (ctx == NULL || ctx->MBEDTLS_PRIVATE(md_ctx) == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    openssl_md_ctx_state_t *s = (openssl_md_ctx_state_t *) ctx->MBEDTLS_PRIVATE(md_ctx);
    if (EVP_DigestUpdate(s->ctx, input, ilen) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

int openssl_mbedtls_md_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
    unsigned int out_len = 0;
    if (ctx == NULL || output == NULL || ctx->MBEDTLS_PRIVATE(md_ctx) == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    openssl_md_ctx_state_t *s = (openssl_md_ctx_state_t *) ctx->MBEDTLS_PRIVATE(md_ctx);
    if (EVP_DigestFinal_ex(s->ctx, output, &out_len) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

void openssl_mbedtls_md_free(mbedtls_md_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->MBEDTLS_PRIVATE(md_ctx) != NULL) {
        openssl_md_ctx_state_t *s = (openssl_md_ctx_state_t *) ctx->MBEDTLS_PRIVATE(md_ctx);
        md_state_cleanup(s);
        OPENSSL_cleanse(s, sizeof(*s));
        free(s);
    }
    memset(ctx, 0, sizeof(*ctx));
}

int openssl_mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                         size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                         const unsigned char *info, size_t info_len,
                         unsigned char *okm, size_t okm_len) {
    const openssl_md_info_t *mi = openssl_md_info(md);
    const EVP_MD *evp_md = mi != NULL ? evp_md_from_type(mi->type) : NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_len = okm_len;
    if (evp_md == NULL || ikm == NULL || okm == NULL) {
        return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, evp_md) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int) salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int) ikm_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int) info_len) <= 0 ||
        EVP_PKEY_derive(pctx, okm, &out_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
    }
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

void openssl_mbedtls_platform_zeroize(void *buf, size_t len) {
    if (buf != NULL && len > 0) {
        OPENSSL_cleanse(buf, len);
    }
}

typedef struct {
    EVP_MD_CTX *ctx;
    int is224;
} sha256_state_t;

static state_node_t *g_sha256_states;

static void sha256_state_free(void *ptr) {
    sha256_state_t *s = (sha256_state_t *) ptr;
    if (s != NULL && s->ctx != NULL) {
        EVP_MD_CTX_free(s->ctx);
        s->ctx = NULL;
    }
}

void openssl_mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
    (void) ctx;
}

void openssl_mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    state_del(&g_sha256_states, ctx, sha256_state_free);
}

int openssl_mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    sha256_state_t *s = (sha256_state_t *) state_get(&g_sha256_states, ctx, sizeof(*s), 1);
    if (s == NULL) {
        return MBEDTLS_ERR_MD_ALLOC_FAILED;
    }
    if (s->ctx == NULL) {
        s->ctx = EVP_MD_CTX_new();
        if (s->ctx == NULL) {
            return MBEDTLS_ERR_MD_ALLOC_FAILED;
        }
    }
    s->is224 = is224;
    if (EVP_DigestInit_ex(s->ctx, is224 ? EVP_sha224() : EVP_sha256(), NULL) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

int openssl_mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                                  const unsigned char *input,
                                  size_t ilen) {
    sha256_state_t *s = (sha256_state_t *) state_get(&g_sha256_states, ctx, sizeof(*s), 0);
    if (s == NULL || s->ctx == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    if (EVP_DigestUpdate(s->ctx, input, ilen) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

int openssl_mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                                  unsigned char output[32]) {
    unsigned int olen = 0;
    sha256_state_t *s = (sha256_state_t *) state_get(&g_sha256_states, ctx, sizeof(*s), 0);
    if (s == NULL || s->ctx == NULL || output == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    if (EVP_DigestFinal_ex(s->ctx, output, &olen) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

int openssl_mbedtls_sha256(const unsigned char *input,
                           size_t ilen,
                           unsigned char output[32],
                           int is224) {
    unsigned int olen = 0;
    if (EVP_Digest(input, ilen, output, &olen, is224 ? EVP_sha224() : EVP_sha256(), NULL) != 1) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    return 0;
}

typedef struct {
    unsigned char key[64];
    unsigned int keybits;
    int is_dec;
} aes_state_t;

static state_node_t *g_aes_states;

typedef struct {
    unsigned char key[64];
    unsigned int keybits;
    int is_dec;
} aes_xts_state_t;

static state_node_t *g_aes_xts_states;

static const EVP_CIPHER *evp_aes_from_bits(unsigned int keybits, int mode) {
    switch (mode) {
        case 1:
            if (keybits == 128) return EVP_aes_128_ecb();
            if (keybits == 192) return EVP_aes_192_ecb();
            if (keybits == 256) return EVP_aes_256_ecb();
            break;
        case 2:
            if (keybits == 128) return EVP_aes_128_cbc();
            if (keybits == 192) return EVP_aes_192_cbc();
            if (keybits == 256) return EVP_aes_256_cbc();
            break;
        case 3:
            if (keybits == 128) return EVP_aes_128_cfb128();
            if (keybits == 192) return EVP_aes_192_cfb128();
            if (keybits == 256) return EVP_aes_256_cfb128();
            break;
        case 4:
            if (keybits == 128) return EVP_aes_128_ofb();
            if (keybits == 192) return EVP_aes_192_ofb();
            if (keybits == 256) return EVP_aes_256_ofb();
            break;
        case 5:
            if (keybits == 128) return EVP_aes_128_ctr();
            if (keybits == 192) return EVP_aes_192_ctr();
            if (keybits == 256) return EVP_aes_256_ctr();
            break;
    }
    return NULL;
}

static int evp_cipher_crypt(const EVP_CIPHER *cipher,
                            int enc,
                            const unsigned char *key,
                            const unsigned char *iv,
                            const unsigned char *in,
                            unsigned char *out,
                            size_t len,
                            int set_no_padding) {
    int outl = 0;
    int finl = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return -1;
    }
    if (EVP_CipherInit_ex(c, cipher, NULL, NULL, NULL, enc) != 1) {
        EVP_CIPHER_CTX_free(c);
        return -1;
    }
    if (set_no_padding) {
        EVP_CIPHER_CTX_set_padding(c, 0);
    }
    if (EVP_CipherInit_ex(c, NULL, NULL, key, iv, enc) != 1) {
        EVP_CIPHER_CTX_free(c);
        return -1;
    }
    if (EVP_CipherUpdate(c, out, &outl, in, (int) len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return -1;
    }
    if (EVP_CipherFinal_ex(c, out + outl, &finl) != 1) {
        EVP_CIPHER_CTX_free(c);
        return -1;
    }
    EVP_CIPHER_CTX_free(c);
    return 0;
}

void openssl_mbedtls_aes_init(mbedtls_aes_context *ctx) {
    (void) ctx;
}

void openssl_mbedtls_aes_free(mbedtls_aes_context *ctx) {
    state_del(&g_aes_states, ctx, NULL);
}

int openssl_mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                                   unsigned int keybits) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL || (keybits != 128 && keybits != 192 && keybits != 256)) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    memcpy(s->key, key, keybits / 8);
    s->keybits = keybits;
    s->is_dec = 0;
    return 0;
}

int openssl_mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                                   unsigned int keybits) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL || (keybits != 128 && keybits != 192 && keybits != 256)) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    memcpy(s->key, key, keybits / 8);
    s->keybits = keybits;
    s->is_dec = 1;
    return 0;
}

int openssl_mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                                  int mode,
                                  const unsigned char input[16],
                                  unsigned char output[16]) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = NULL;
    if (s == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    cipher = evp_aes_from_bits(s->keybits, 1);
    if (cipher == NULL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    return evp_cipher_crypt(cipher, mode == MBEDTLS_AES_ENCRYPT ? 1 : 0, s->key, NULL,
                            input, output, 16, 1) == 0 ? 0 : MBEDTLS_ERR_AES_BAD_INPUT_DATA;
}

int openssl_mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                                  int mode,
                                  size_t length,
                                  unsigned char iv[16],
                                  const unsigned char *input,
                                  unsigned char *output) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = NULL;
    if (s == NULL || iv == NULL || input == NULL || output == NULL || (length % 16) != 0) {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }
    cipher = evp_aes_from_bits(s->keybits, 2);
    if (cipher == NULL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    return evp_cipher_crypt(cipher, mode == MBEDTLS_AES_ENCRYPT ? 1 : 0, s->key, iv,
                            input, output, length, 1) == 0 ? 0 : MBEDTLS_ERR_AES_BAD_INPUT_DATA;
}

int openssl_mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx,
                                     int mode,
                                     size_t length,
                                     size_t *iv_off,
                                     unsigned char iv[16],
                                     const unsigned char *input,
                                     unsigned char *output) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = NULL;
    if (s == NULL || iv == NULL || input == NULL || output == NULL || iv_off == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    cipher = evp_aes_from_bits(s->keybits, 3);
    if (cipher == NULL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    if (*iv_off != 0) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    if (evp_cipher_crypt(cipher, mode == MBEDTLS_AES_ENCRYPT ? 1 : 0, s->key, iv,
                         input, output, length, 0) != 0) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    *iv_off = 0;
    return 0;
}

int openssl_mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx,
                                  size_t length,
                                  size_t *iv_off,
                                  unsigned char iv[16],
                                  const unsigned char *input,
                                  unsigned char *output) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = NULL;
    if (s == NULL || iv == NULL || input == NULL || output == NULL || iv_off == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    cipher = evp_aes_from_bits(s->keybits, 4);
    if (cipher == NULL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    if (*iv_off != 0) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    if (evp_cipher_crypt(cipher, 1, s->key, iv, input, output, length, 0) != 0) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    *iv_off = 0;
    return 0;
}

int openssl_mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                                  size_t length,
                                  size_t *nc_off,
                                  unsigned char nonce_counter[16],
                                  unsigned char stream_block[16],
                                  const unsigned char *input,
                                  unsigned char *output) {
    aes_state_t *s = (aes_state_t *) state_get(&g_aes_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = NULL;
    (void) stream_block;
    if (s == NULL || nonce_counter == NULL || input == NULL || output == NULL || nc_off == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    cipher = evp_aes_from_bits(s->keybits, 5);
    if (cipher == NULL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    if (*nc_off != 0) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    if (evp_cipher_crypt(cipher, 1, s->key, nonce_counter, input, output, length, 0) != 0) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    *nc_off = 0;
    memset(stream_block, 0, 16);
    return 0;
}

void openssl_mbedtls_aes_xts_init(mbedtls_aes_xts_context *ctx) {
    (void) ctx;
}

void openssl_mbedtls_aes_xts_free(mbedtls_aes_xts_context *ctx) {
    state_del(&g_aes_xts_states, ctx, NULL);
}

int openssl_mbedtls_aes_xts_setkey_enc(mbedtls_aes_xts_context *ctx,
                                       const unsigned char *key,
                                       unsigned int keybits) {
    aes_xts_state_t *s = (aes_xts_state_t *) state_get(&g_aes_xts_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL || (keybits != 256 && keybits != 512)) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    memcpy(s->key, key, keybits / 8);
    s->keybits = keybits;
    s->is_dec = 0;
    return 0;
}

int openssl_mbedtls_aes_xts_setkey_dec(mbedtls_aes_xts_context *ctx,
                                       const unsigned char *key,
                                       unsigned int keybits) {
    aes_xts_state_t *s = (aes_xts_state_t *) state_get(&g_aes_xts_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL || (keybits != 256 && keybits != 512)) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    memcpy(s->key, key, keybits / 8);
    s->keybits = keybits;
    s->is_dec = 1;
    return 0;
}

int openssl_mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx,
                                  int mode,
                                  size_t length,
                                  const unsigned char data_unit[16],
                                  const unsigned char *input,
                                  unsigned char *output) {
    aes_xts_state_t *s = (aes_xts_state_t *) state_get(&g_aes_xts_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = NULL;
    if (s == NULL || data_unit == NULL || input == NULL || output == NULL || length < 16) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    if (s->keybits == 256) {
        cipher = EVP_aes_128_xts();
    }
    else if (s->keybits == 512) {
        cipher = EVP_aes_256_xts();
    }
    else {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    return evp_cipher_crypt(cipher, mode == MBEDTLS_AES_ENCRYPT ? 1 : 0,
                            s->key, data_unit, input, output, length, 0) == 0
               ? 0
               : MBEDTLS_ERR_AES_BAD_INPUT_DATA;
}

typedef struct {
    unsigned char key[32];
    unsigned int keybits;
} gcm_state_t;

static state_node_t *g_gcm_states;

void openssl_mbedtls_gcm_init(mbedtls_gcm_context *ctx) {
    (void) ctx;
}

void openssl_mbedtls_gcm_free(mbedtls_gcm_context *ctx) {
    state_del(&g_gcm_states, ctx, NULL);
}

int openssl_mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                               mbedtls_cipher_id_t cipher,
                               const unsigned char *key,
                               unsigned int keybits) {
    gcm_state_t *s = (gcm_state_t *) state_get(&g_gcm_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL || cipher != MBEDTLS_CIPHER_ID_AES ||
        (keybits != 128 && keybits != 192 && keybits != 256)) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    memcpy(s->key, key, keybits / 8);
    s->keybits = keybits;
    return 0;
}

static const EVP_CIPHER *evp_gcm_cipher(unsigned int keybits) {
    if (keybits == 128) return EVP_aes_128_gcm();
    if (keybits == 192) return EVP_aes_192_gcm();
    if (keybits == 256) return EVP_aes_256_gcm();
    return NULL;
}

int openssl_mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                                      int mode,
                                      size_t length,
                                      const unsigned char *iv,
                                      size_t iv_len,
                                      const unsigned char *add,
                                      size_t add_len,
                                      const unsigned char *input,
                                      unsigned char *output,
                                      size_t tag_len,
                                      unsigned char *tag) {
    int out_len = 0;
    int tmp = 0;
    gcm_state_t *s = (gcm_state_t *) state_get(&g_gcm_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = s != NULL ? evp_gcm_cipher(s->keybits) : NULL;
    EVP_CIPHER_CTX *c = NULL;
    if (s == NULL || cipher == NULL || iv == NULL || input == NULL || output == NULL || tag == NULL) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (EVP_CipherInit_ex(c, cipher, NULL, NULL, NULL, mode == MBEDTLS_GCM_ENCRYPT ? 1 : 0) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int) iv_len, NULL) != 1 ||
        EVP_CipherInit_ex(c, NULL, NULL, s->key, iv, mode == MBEDTLS_GCM_ENCRYPT ? 1 : 0) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (add_len > 0 && EVP_CipherUpdate(c, NULL, &tmp, add, (int) add_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (EVP_CipherUpdate(c, output, &out_len, input, (int) length) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (EVP_CipherFinal_ex(c, output + out_len, &tmp) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    if (mode == MBEDTLS_GCM_ENCRYPT &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, (int) tag_len, tag) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    EVP_CIPHER_CTX_free(c);
    return 0;
}

int openssl_mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                                     size_t length,
                                     const unsigned char *iv,
                                     size_t iv_len,
                                     const unsigned char *add,
                                     size_t add_len,
                                     const unsigned char *tag,
                                     size_t tag_len,
                                     const unsigned char *input,
                                     unsigned char *output) {
    int out_len = 0;
    int tmp = 0;
    gcm_state_t *s = (gcm_state_t *) state_get(&g_gcm_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = s != NULL ? evp_gcm_cipher(s->keybits) : NULL;
    EVP_CIPHER_CTX *c = NULL;
    if (s == NULL || cipher == NULL || iv == NULL || input == NULL || output == NULL || tag == NULL) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (EVP_DecryptInit_ex(c, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int) iv_len, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, s->key, iv) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (add_len > 0 && EVP_DecryptUpdate(c, NULL, &tmp, add, (int) add_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (EVP_DecryptUpdate(c, output, &out_len, input, (int) length) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, (int) tag_len, (void *) tag) != 1 ||
        EVP_DecryptFinal_ex(c, output + out_len, &tmp) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    EVP_CIPHER_CTX_free(c);
    return 0;
}

typedef struct {
    unsigned char key[32];
    unsigned int keybits;
} ccm_state_t;

static state_node_t *g_ccm_states;

void openssl_mbedtls_ccm_init(mbedtls_ccm_context *ctx) {
    (void) ctx;
}

void openssl_mbedtls_ccm_free(mbedtls_ccm_context *ctx) {
    state_del(&g_ccm_states, ctx, NULL);
}

int openssl_mbedtls_ccm_setkey(mbedtls_ccm_context *ctx,
                               mbedtls_cipher_id_t cipher,
                               const unsigned char *key,
                               unsigned int keybits) {
    ccm_state_t *s = (ccm_state_t *) state_get(&g_ccm_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL || cipher != MBEDTLS_CIPHER_ID_AES ||
        (keybits != 128 && keybits != 192 && keybits != 256)) {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    memcpy(s->key, key, keybits / 8);
    s->keybits = keybits;
    return 0;
}

static const EVP_CIPHER *evp_ccm_cipher(unsigned int keybits) {
    if (keybits == 128) return EVP_aes_128_ccm();
    if (keybits == 192) return EVP_aes_192_ccm();
    if (keybits == 256) return EVP_aes_256_ccm();
    return NULL;
}

int openssl_mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                        const unsigned char *iv, size_t iv_len,
                                        const unsigned char *add, size_t add_len,
                                        const unsigned char *input, unsigned char *output,
                                        unsigned char *tag, size_t tag_len) {
    int len = 0;
    ccm_state_t *s = (ccm_state_t *) state_get(&g_ccm_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = s != NULL ? evp_ccm_cipher(s->keybits) : NULL;
    EVP_CIPHER_CTX *c = NULL;
    if (s == NULL || cipher == NULL || iv == NULL || input == NULL || output == NULL || tag == NULL) {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (EVP_EncryptInit_ex(c, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, (int) iv_len, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, (int) tag_len, NULL) != 1 ||
        EVP_EncryptInit_ex(c, NULL, NULL, s->key, iv) != 1 ||
        EVP_EncryptUpdate(c, NULL, &len, NULL, (int) length) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (add_len > 0 && EVP_EncryptUpdate(c, NULL, &len, add, (int) add_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (EVP_EncryptUpdate(c, output, &len, input, (int) length) != 1 ||
        EVP_EncryptFinal_ex(c, output + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, (int) tag_len, tag) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    EVP_CIPHER_CTX_free(c);
    return 0;
}

int openssl_mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *add, size_t add_len,
                                     const unsigned char *input, unsigned char *output,
                                     const unsigned char *tag, size_t tag_len) {
    int len = 0;
    int ok = 0;
    ccm_state_t *s = (ccm_state_t *) state_get(&g_ccm_states, ctx, sizeof(*s), 0);
    const EVP_CIPHER *cipher = s != NULL ? evp_ccm_cipher(s->keybits) : NULL;
    EVP_CIPHER_CTX *c = NULL;
    if (s == NULL || cipher == NULL || iv == NULL || input == NULL || output == NULL || tag == NULL) {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (EVP_DecryptInit_ex(c, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, (int) iv_len, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, (int) tag_len, (void *) tag) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, s->key, iv) != 1 ||
        EVP_DecryptUpdate(c, NULL, &len, NULL, (int) length) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (add_len > 0 && EVP_DecryptUpdate(c, NULL, &len, add, (int) add_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    ok = EVP_DecryptUpdate(c, output, &len, input, (int) length);
    EVP_CIPHER_CTX_free(c);
    return ok == 1 ? 0 : MBEDTLS_ERR_CCM_AUTH_FAILED;
}

typedef struct {
    unsigned char key[32];
    int has_key;
} chachapoly_state_t;

static state_node_t *g_chacha_states;

void openssl_mbedtls_chachapoly_init(mbedtls_chachapoly_context *ctx) {
    (void) ctx;
}

void openssl_mbedtls_chachapoly_free(mbedtls_chachapoly_context *ctx) {
    state_del(&g_chacha_states, ctx, NULL);
}

int openssl_mbedtls_chachapoly_setkey(mbedtls_chachapoly_context *ctx,
                                      const unsigned char key[32]) {
    chachapoly_state_t *s = (chachapoly_state_t *) state_get(&g_chacha_states, ctx, sizeof(*s), 1);
    if (s == NULL || key == NULL) {
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    memcpy(s->key, key, 32);
    s->has_key = 1;
    return 0;
}

int openssl_mbedtls_chachapoly_encrypt_and_tag(mbedtls_chachapoly_context *ctx,
                                               size_t length,
                                               const unsigned char nonce[12],
                                               const unsigned char *aad,
                                               size_t aad_len,
                                               const unsigned char *input,
                                               unsigned char *output,
                                               unsigned char tag[16]) {
    int out_len = 0;
    int fin_len = 0;
    chachapoly_state_t *s = (chachapoly_state_t *) state_get(&g_chacha_states, ctx, sizeof(*s), 0);
    EVP_CIPHER_CTX *c = NULL;
    if (s == NULL || !s->has_key || nonce == NULL || input == NULL || output == NULL || tag == NULL) {
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    if (EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(c, NULL, NULL, s->key, nonce) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    if (aad_len > 0 && EVP_EncryptUpdate(c, NULL, &out_len, aad, (int) aad_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    if (EVP_EncryptUpdate(c, output, &out_len, input, (int) length) != 1 ||
        EVP_EncryptFinal_ex(c, output + out_len, &fin_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    EVP_CIPHER_CTX_free(c);
    return 0;
}

int openssl_mbedtls_chachapoly_auth_decrypt(mbedtls_chachapoly_context *ctx,
                                            size_t length,
                                            const unsigned char nonce[12],
                                            const unsigned char *aad,
                                            size_t aad_len,
                                            const unsigned char tag[16],
                                            const unsigned char *input,
                                            unsigned char *output) {
    int out_len = 0;
    int fin_len = 0;
    chachapoly_state_t *s = (chachapoly_state_t *) state_get(&g_chacha_states, ctx, sizeof(*s), 0);
    EVP_CIPHER_CTX *c = NULL;
    if (s == NULL || !s->has_key || nonce == NULL || input == NULL || output == NULL || tag == NULL) {
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    if (EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, s->key, nonce) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    if (aad_len > 0 && EVP_DecryptUpdate(c, NULL, &out_len, aad, (int) aad_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CHACHAPOLY_BAD_STATE;
    }
    if (EVP_DecryptUpdate(c, output, &out_len, input, (int) length) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *) tag) != 1 ||
        EVP_DecryptFinal_ex(c, output + out_len, &fin_len) != 1) {
        EVP_CIPHER_CTX_free(c);
        return MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED;
    }
    EVP_CIPHER_CTX_free(c);
    return 0;
}

typedef struct {
    mbedtls_cipher_type_t type;
    unsigned int keybits;
    const char *openssl_name;
} openssl_cipher_info_t;

static const openssl_cipher_info_t g_cipher_aes_128_ecb = {
    MBEDTLS_CIPHER_AES_128_ECB, 128, "AES-128-CBC"
};
static const openssl_cipher_info_t g_cipher_aes_192_ecb = {
    MBEDTLS_CIPHER_AES_192_ECB, 192, "AES-192-CBC"
};
static const openssl_cipher_info_t g_cipher_aes_256_ecb = {
    MBEDTLS_CIPHER_AES_256_ECB, 256, "AES-256-CBC"
};

const mbedtls_cipher_info_t *openssl_mbedtls_cipher_info_from_type(const mbedtls_cipher_type_t cipher_type) {
    switch (cipher_type) {
        case MBEDTLS_CIPHER_AES_128_ECB:
            return (const mbedtls_cipher_info_t *) &g_cipher_aes_128_ecb;
        case MBEDTLS_CIPHER_AES_192_ECB:
            return (const mbedtls_cipher_info_t *) &g_cipher_aes_192_ecb;
        case MBEDTLS_CIPHER_AES_256_ECB:
            return (const mbedtls_cipher_info_t *) &g_cipher_aes_256_ecb;
        default:
            return NULL;
    }
}

int openssl_mbedtls_cipher_cmac(const mbedtls_cipher_info_t *cipher_info,
                                const unsigned char *key,
                                size_t key_bitlen,
                                const unsigned char *input,
                                size_t ilen,
                                unsigned char *output) {
    const openssl_cipher_info_t *info = (const openssl_cipher_info_t *) cipher_info;
    if (info == NULL || key == NULL || input == NULL || output == NULL || info->keybits != key_bitlen) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *mctx = NULL;
    size_t out_len = 0;
    OSSL_PARAM params[2];
    if (mac == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    mctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (mctx == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char *) info->openssl_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(mctx, key, key_bitlen / 8, params) != 1 ||
        EVP_MAC_update(mctx, input, ilen) != 1 ||
        EVP_MAC_final(mctx, output, &out_len, 16) != 1) {
        EVP_MAC_CTX_free(mctx);
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    EVP_MAC_CTX_free(mctx);
#else
    CMAC_CTX *cctx = CMAC_CTX_new();
    size_t out_len = 0;
    const EVP_CIPHER *cipher = NULL;
    if (cctx == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    if (info->keybits == 128) {
        cipher = EVP_aes_128_cbc();
    }
    else if (info->keybits == 192) {
        cipher = EVP_aes_192_cbc();
    }
    else if (info->keybits == 256) {
        cipher = EVP_aes_256_cbc();
    }
    if (cipher == NULL ||
        CMAC_Init(cctx, key, key_bitlen / 8, cipher, NULL) != 1 ||
        CMAC_Update(cctx, input, ilen) != 1 ||
        CMAC_Final(cctx, output, &out_len) != 1) {
        CMAC_CTX_free(cctx);
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    CMAC_CTX_free(cctx);
#endif
    return 0;
}

static int bn_to_mpi(const BIGNUM *bn, mbedtls_mpi *dst) {
    return bn_to_mpi_raw(bn, dst);
}

static BIGNUM *mpi_to_bn(const mbedtls_mpi *src) {
    return mpi_to_bn_raw(src);
}

static EVP_PKEY *rsa_pkey_from_ctx(const mbedtls_rsa_context *ctx, int with_private) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;

    n = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(N));
    e = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(E));
    if (n == NULL || e == NULL) {
        goto out;
    }
    if (with_private) {
        d = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(D));
        if (d == NULL) {
            goto out;
        }
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1 ||
        (with_private && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) != 1)) {
        goto out;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        goto out;
    }
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx == NULL || EVP_PKEY_fromdata_init(pctx) <= 0) {
        goto out;
    }
    if (EVP_PKEY_fromdata(pctx, &pkey, with_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

out:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static int set_rsa_sig_params(EVP_PKEY_CTX *pctx, const mbedtls_rsa_context *ctx, mbedtls_md_type_t md_alg) {
    const EVP_MD *md = NULL;
    int padding = ctx->MBEDTLS_PRIVATE(padding);
    int hash_id = ctx->MBEDTLS_PRIVATE(hash_id);
    if (padding == MBEDTLS_RSA_PKCS_V15) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        }
    }
    else if (padding == MBEDTLS_RSA_PKCS_V21) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        }
    }
    else {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (md_alg != MBEDTLS_MD_NONE) {
        md = evp_md_from_type(md_alg);
    }
    else if (hash_id != MBEDTLS_MD_NONE) {
        md = evp_md_from_type((mbedtls_md_type_t) hash_id);
    }
    if (md != NULL && EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    return 0;
}

static int pkcs1_build_digest_info(mbedtls_md_type_t md_alg,
                                   const unsigned char *hash,
                                   size_t hashlen,
                                   unsigned char *out,
                                   size_t *outlen) {
    static const unsigned char sha1_prefix[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
    };
    static const unsigned char sha224_prefix[] = {
        0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        0x05, 0x00, 0x04, 0x1C
    };
    static const unsigned char sha256_prefix[] = {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20
    };
    static const unsigned char sha384_prefix[] = {
        0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30
    };
    static const unsigned char sha512_prefix[] = {
        0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40
    };
    const unsigned char *prefix = NULL;
    size_t prefix_len = 0;
    size_t md_len = 0;

    if (hash == NULL || out == NULL || outlen == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    switch (md_alg) {
        case MBEDTLS_MD_SHA1:
            prefix = sha1_prefix; prefix_len = sizeof(sha1_prefix); md_len = 20; break;
        case MBEDTLS_MD_SHA224:
            prefix = sha224_prefix; prefix_len = sizeof(sha224_prefix); md_len = 28; break;
        case MBEDTLS_MD_SHA256:
            prefix = sha256_prefix; prefix_len = sizeof(sha256_prefix); md_len = 32; break;
        case MBEDTLS_MD_SHA384:
            prefix = sha384_prefix; prefix_len = sizeof(sha384_prefix); md_len = 48; break;
        case MBEDTLS_MD_SHA512:
            prefix = sha512_prefix; prefix_len = sizeof(sha512_prefix); md_len = 64; break;
        default:
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    if (hashlen != md_len || prefix_len + hashlen > *outlen) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    memcpy(out, prefix, prefix_len);
    memcpy(out + prefix_len, hash, hashlen);
    *outlen = prefix_len + hashlen;
    return 0;
}

int openssl_mbedtls_rsa_gen_key(mbedtls_rsa_context *ctx,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng,
                                unsigned int nbits,
                                int exponent) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_p = NULL, *bn_q = NULL;
    int rc = MBEDTLS_ERR_RSA_KEY_GEN_FAILED;
    (void) f_rng;
    (void) p_rng;
    if (ctx == NULL || (nbits != 1024 && nbits != 2048 && nbits != 3072 && nbits != 4096) ||
        (exponent != 3 && exponent != 65537)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    {
        BIGNUM *e = BN_new();
        if (e == NULL) {
            goto out;
        }
        if (BN_set_word(e, (BN_ULONG) exponent) != 1) {
            BN_free(e);
            goto out;
        }
        if (pctx == NULL ||
            EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, (int) nbits) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_pubexp(pctx, e) <= 0) {
            BN_free(e);
            goto out;
        }
        /* ownership transferred to pctx on success */
    }

    rc = EVP_PKEY_keygen(pctx, &pkey);
    if (rc <= 0) {
        goto out;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &bn_d) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn_p) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn_q) != 1) {
        goto out;
    }
#else
    {
        RSA *rsa = EVP_PKEY_get1_RSA(pkey);
        const BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
        if (rsa == NULL) {
            goto out;
        }
        RSA_get0_key(rsa, &n, &e, &d);
        RSA_get0_factors(rsa, &p, &q);
        if (n == NULL || e == NULL || d == NULL || p == NULL || q == NULL) {
            RSA_free(rsa);
            goto out;
        }
        bn_n = BN_dup(n);
        bn_e = BN_dup(e);
        bn_d = BN_dup(d);
        bn_p = BN_dup(p);
        bn_q = BN_dup(q);
        RSA_free(rsa);
        if (bn_n == NULL || bn_e == NULL || bn_d == NULL || bn_p == NULL || bn_q == NULL) {
            goto out;
        }
    }
#endif

    if (bn_to_mpi(bn_n, &ctx->MBEDTLS_PRIVATE(N)) != 0 ||
        bn_to_mpi(bn_e, &ctx->MBEDTLS_PRIVATE(E)) != 0 ||
        bn_to_mpi(bn_d, &ctx->MBEDTLS_PRIVATE(D)) != 0 ||
        bn_to_mpi(bn_p, &ctx->MBEDTLS_PRIVATE(P)) != 0 ||
        bn_to_mpi(bn_q, &ctx->MBEDTLS_PRIVATE(Q)) != 0) {
        goto out;
    }
    rc = mbedtls_rsa_complete(ctx);
    if (rc != 0) {
        goto out;
    }
    rc = mbedtls_rsa_check_privkey(ctx);
out:
    BN_free(bn_n);
    BN_free(bn_e);
    BN_free(bn_d);
    BN_free(bn_p);
    BN_free(bn_q);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static int ec_nid_from_group(mbedtls_ecp_group_id gid) {
    const mbedtls_ecp_curve_info *info = NULL;
    int nid = NID_undef;
    switch (gid) {
        case MBEDTLS_ECP_DP_SECP192R1: return NID_X9_62_prime192v1;
        case MBEDTLS_ECP_DP_SECP224R1: return NID_secp224r1;
        case MBEDTLS_ECP_DP_SECP256R1: return NID_X9_62_prime256v1;
        case MBEDTLS_ECP_DP_SECP192K1: return NID_secp192k1;
        case MBEDTLS_ECP_DP_SECP224K1: return NID_secp224k1;
        case MBEDTLS_ECP_DP_SECP256K1: return NID_secp256k1;
        case MBEDTLS_ECP_DP_SECP384R1: return NID_secp384r1;
        case MBEDTLS_ECP_DP_SECP521R1: return NID_secp521r1;
        case MBEDTLS_ECP_DP_BP256R1: return NID_brainpoolP256r1;
        case MBEDTLS_ECP_DP_BP384R1: return NID_brainpoolP384r1;
        case MBEDTLS_ECP_DP_BP512R1: return NID_brainpoolP512r1;
        default: break;
    }
    info = openssl_mbedtls_ecp_curve_info_from_grp_id(gid);
    if (info != NULL && info->name != NULL) {
        nid = OBJ_sn2nid(info->name);
        if (nid == NID_undef) {
            nid = OBJ_ln2nid(info->name);
        }
    }
    return nid;
}

static EC_KEY *ec_key_from_private(const mbedtls_ecp_group *grp, const mbedtls_mpi *d) {
    int nid = ec_nid_from_group(grp->id);
    EC_KEY *key = NULL;
    EC_POINT *pub = NULL;
    BIGNUM *bn_d = NULL;
    if (nid == NID_undef || d == NULL) {
        return NULL;
    }
    key = EC_KEY_new_by_curve_name(nid);
    bn_d = mpi_to_bn(d);
    if (key == NULL || bn_d == NULL) {
        EC_KEY_free(key);
        BN_free(bn_d);
        return NULL;
    }
    if (EC_KEY_set_private_key(key, bn_d) != 1) {
        EC_KEY_free(key);
        BN_free(bn_d);
        return NULL;
    }
    pub = EC_POINT_new(EC_KEY_get0_group(key));
    if (pub == NULL || EC_POINT_mul(EC_KEY_get0_group(key), pub, bn_d, NULL, NULL, NULL) != 1 ||
        EC_KEY_set_public_key(key, pub) != 1) {
        EC_POINT_free(pub);
        EC_KEY_free(key);
        BN_free(bn_d);
        return NULL;
    }
    EC_POINT_free(pub);
    BN_free(bn_d);
    return key;
}

static EC_KEY *ec_key_from_public(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *Q) {
    int nid = ec_nid_from_group(grp->id);
    EC_KEY *key = NULL;
    EC_POINT *pub = NULL;
    BIGNUM *x = NULL, *y = NULL;
    if (nid == NID_undef || Q == NULL) {
        return NULL;
    }
    key = EC_KEY_new_by_curve_name(nid);
    x = mpi_to_bn(&Q->MBEDTLS_PRIVATE(X));
    y = mpi_to_bn(&Q->MBEDTLS_PRIVATE(Y));
    if (key == NULL || x == NULL || y == NULL) {
        EC_KEY_free(key);
        BN_free(x);
        BN_free(y);
        return NULL;
    }
    pub = EC_POINT_new(EC_KEY_get0_group(key));
    if (pub == NULL ||
        EC_POINT_set_affine_coordinates(EC_KEY_get0_group(key), pub, x, y, NULL) != 1 ||
        EC_KEY_set_public_key(key, pub) != 1) {
        EC_POINT_free(pub);
        EC_KEY_free(key);
        BN_free(x);
        BN_free(y);
        return NULL;
    }
    EC_POINT_free(pub);
    BN_free(x);
    BN_free(y);
    return key;
}

int openssl_mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id,
                                mbedtls_ecp_keypair *key,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_d = NULL;
    int rc = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    int nid = ec_nid_from_group(grp_id);
    (void) f_rng;
    (void) p_rng;
    if (key == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    rc = mbedtls_ecp_group_load(&key->MBEDTLS_PRIVATE(grp), grp_id);
    if (rc != 0) {
        return rc;
    }

    if (nid != NID_undef) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    }
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
        goto out;
    }
    if (nid != NID_undef && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
        goto out;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        goto out;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d) != 1) {
        goto out;
    }
    rc = bn_to_mpi(bn_d, &key->MBEDTLS_PRIVATE(d));
#else
    {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
        const BIGNUM *d = ec != NULL ? EC_KEY_get0_private_key(ec) : NULL;
        if (d == NULL) {
            EC_KEY_free(ec);
            goto out;
        }
        bn_d = BN_dup(d);
        EC_KEY_free(ec);
        if (bn_d == NULL) {
            goto out;
        }
        rc = bn_to_mpi(bn_d, &key->MBEDTLS_PRIVATE(d));
    }
#endif
    if (rc != 0) {
        goto out;
    }
    rc = mbedtls_ecp_mul(&key->MBEDTLS_PRIVATE(grp), &key->MBEDTLS_PRIVATE(Q),
                         &key->MBEDTLS_PRIVATE(d), &key->MBEDTLS_PRIVATE(grp).G,
                         f_rng, p_rng);
out:
    BN_free(bn_d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int openssl_mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx,
                                 mbedtls_ecp_group_id gid,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng) {
    return openssl_mbedtls_ecp_gen_key(gid, (mbedtls_ecp_keypair *) ctx, f_rng, p_rng);
}

int openssl_mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                               const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                               mbedtls_f_rng_t *f_rng, void *p_rng) {
    EC_KEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *sr = NULL, *ss = NULL;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    (void) f_rng;
    (void) p_rng;
    if (grp == NULL || r == NULL || s == NULL || d == NULL || buf == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    key = ec_key_from_private(grp, d);
    if (key == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    sig = ECDSA_do_sign(buf, (int) blen, key);
    if (sig == NULL) {
        EC_KEY_free(key);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    ECDSA_SIG_get0(sig, &sr, &ss);
    if (bn_to_mpi(sr, r) != 0 || bn_to_mpi(ss, s) != 0) {
        rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    else {
        rc = 0;
    }
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    return rc;
}

int openssl_mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                                 const unsigned char *buf, size_t blen,
                                 const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                                 const mbedtls_mpi *s) {
    EC_KEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *br = NULL, *bs = NULL;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (grp == NULL || buf == NULL || Q == NULL || r == NULL || s == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    key = ec_key_from_public(grp, Q);
    br = mpi_to_bn(r);
    bs = mpi_to_bn(s);
    if (key == NULL || br == NULL || bs == NULL) {
        EC_KEY_free(key);
        BN_free(br);
        BN_free(bs);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    sig = ECDSA_SIG_new();
    if (sig == NULL || ECDSA_SIG_set0(sig, br, bs) != 1) {
        ECDSA_SIG_free(sig);
        EC_KEY_free(key);
        BN_free(br);
        BN_free(bs);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    br = NULL;
    bs = NULL;
    rc = ECDSA_do_verify(buf, (int) blen, sig, key);
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    if (rc == 1) {
        return 0;
    }
    return MBEDTLS_ERR_ECP_VERIFY_FAILED;
}

int openssl_mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                          mbedtls_md_type_t md_alg,
                                          const unsigned char *hash, size_t hlen,
                                          unsigned char *sig, size_t sig_size, size_t *slen,
                                          mbedtls_f_rng_t *f_rng,
                                          void *p_rng) {
    mbedtls_mpi r, s;
    ECDSA_SIG *osig = NULL;
    BIGNUM *br = NULL, *bs = NULL;
    unsigned char *p = sig;
    int der_len = 0;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    (void) md_alg;
    if (ctx == NULL || hash == NULL || sig == NULL || slen == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    rc = openssl_mbedtls_ecdsa_sign(&ctx->MBEDTLS_PRIVATE(grp), &r, &s, &ctx->MBEDTLS_PRIVATE(d),
                                    hash, hlen, f_rng, p_rng);
    if (rc != 0) {
        goto out;
    }
    br = mpi_to_bn(&r);
    bs = mpi_to_bn(&s);
    osig = ECDSA_SIG_new();
    if (br == NULL || bs == NULL || osig == NULL || ECDSA_SIG_set0(osig, br, bs) != 1) {
        BN_free(br);
        BN_free(bs);
        rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto out;
    }
    br = NULL;
    bs = NULL;
    der_len = i2d_ECDSA_SIG(osig, NULL);
    if (der_len <= 0 || (size_t) der_len > sig_size) {
        rc = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto out;
    }
    if (i2d_ECDSA_SIG(osig, &p) != der_len) {
        rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto out;
    }
    *slen = (size_t) der_len;
    rc = 0;
out:
    ECDSA_SIG_free(osig);
    BN_free(br);
    BN_free(bs);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return rc;
}

#if defined(MBEDTLS_EDDSA_C)
static int eddsa_key_bytes_from_group(const mbedtls_ecp_group *grp) {
    if (grp->id == MBEDTLS_ECP_DP_ED25519) {
        return 32;
    }
    if (grp->id == MBEDTLS_ECP_DP_ED448) {
        return 57;
    }
    return 0;
}

static EVP_PKEY *eddsa_pkey_from_private(const mbedtls_ecp_group *grp, const mbedtls_mpi *d) {
    int klen = eddsa_key_bytes_from_group(grp);
    unsigned char raw[57];
    EVP_PKEY *pkey = NULL;
    if (klen == 0 || d == NULL) {
        return NULL;
    }
    memset(raw, 0, sizeof(raw));
    if (mbedtls_mpi_write_binary_le(d, raw, (size_t) klen) != 0) {
        return NULL;
    }
    if (grp->id == MBEDTLS_ECP_DP_ED25519) {
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, (size_t) klen);
    }
    else if (grp->id == MBEDTLS_ECP_DP_ED448) {
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL, raw, (size_t) klen);
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    return pkey;
}

int openssl_mbedtls_eddsa_sign(mbedtls_ecp_group *grp,
                               mbedtls_mpi *r, mbedtls_mpi *s,
                               const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                               mbedtls_eddsa_id eddsa_id,
                               const unsigned char *ed_ctx, size_t ed_ctx_len,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    unsigned char sig[114];
    size_t siglen = sizeof(sig);
    int plen = 0;
    (void) f_rng;
    (void) p_rng;
    (void) ed_ctx;
    (void) ed_ctx_len;
    if (grp == NULL || r == NULL || s == NULL || d == NULL || buf == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (eddsa_id != MBEDTLS_EDDSA_PURE) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    pkey = eddsa_pkey_from_private(grp, d);
    if (pkey == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL || EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) <= 0 ||
        EVP_DigestSign(mctx, sig, &siglen, buf, blen) <= 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    plen = eddsa_key_bytes_from_group(grp);
    if ((size_t) (2 * plen) > siglen || mbedtls_mpi_read_binary_le(r, sig, (size_t) plen) != 0 ||
        mbedtls_mpi_read_binary_le(s, sig + plen, (size_t) plen) != 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(sig, sizeof(sig));
    return 0;
}

int openssl_mbedtls_eddsa_write_signature(mbedtls_ecp_keypair *ctx,
                                          const unsigned char *hash, size_t hlen,
                                          unsigned char *sig, size_t sig_size, size_t *slen,
                                          mbedtls_eddsa_id eddsa_id,
                                          const unsigned char *ed_ctx, size_t ed_ctx_len,
                                          int (*f_rng)(void *, unsigned char *, size_t),
                                          void *p_rng) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    size_t out_len = sig_size;
    (void) f_rng;
    (void) p_rng;
    (void) ed_ctx;
    (void) ed_ctx_len;
    if (ctx == NULL || hash == NULL || sig == NULL || slen == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (eddsa_id != MBEDTLS_EDDSA_PURE) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    pkey = eddsa_pkey_from_private(&ctx->MBEDTLS_PRIVATE(grp), &ctx->MBEDTLS_PRIVATE(d));
    if (pkey == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL || EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) <= 0 ||
        EVP_DigestSign(mctx, sig, &out_len, hash, hlen) <= 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    *slen = out_len;
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return 0;
}
#endif

int openssl_mbedtls_rsa_private(mbedtls_rsa_context *ctx,
                                mbedtls_f_rng_t *f_rng,
                                void *p_rng,
                                const unsigned char *input,
                                unsigned char *output) {
    BIGNUM *bn_n = NULL, *bn_d = NULL, *bn_in = NULL, *bn_out = NULL;
    BN_CTX *bnctx = NULL;
    size_t klen = 0;
    int out_len = 0;
    (void) f_rng;
    (void) p_rng;
    if (ctx == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    klen = mbedtls_rsa_get_len(ctx);
    bn_n = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(N));
    bn_d = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(D));
    bn_in = BN_bin2bn(input, (int) klen, NULL);
    bn_out = BN_new();
    bnctx = BN_CTX_new();
    if (bn_n == NULL || bn_d == NULL || bn_in == NULL || bn_out == NULL || bnctx == NULL) {
        BN_free(bn_n); BN_free(bn_d); BN_free(bn_in); BN_free(bn_out); BN_CTX_free(bnctx);
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }
    if (BN_cmp(bn_in, bn_n) >= 0 || BN_mod_exp(bn_out, bn_in, bn_d, bn_n, bnctx) != 1) {
        BN_free(bn_n); BN_free(bn_d); BN_free(bn_in); BN_free(bn_out); BN_CTX_free(bnctx);
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }
    out_len = BN_num_bytes(bn_out);
    if ((size_t) out_len > klen) {
        BN_free(bn_n); BN_free(bn_d); BN_free(bn_in); BN_free(bn_out); BN_CTX_free(bnctx);
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }
    memset(output, 0, klen);
    BN_bn2bin(bn_out, output + (klen - (size_t) out_len));
    BN_free(bn_n); BN_free(bn_d); BN_free(bn_in); BN_free(bn_out); BN_CTX_free(bnctx);
    return 0;
}

int openssl_mbedtls_rsa_pkcs1_sign(mbedtls_rsa_context *ctx,
                                   mbedtls_f_rng_t *f_rng,
                                   void *p_rng,
                                   mbedtls_md_type_t md_alg,
                                   unsigned int hashlen,
                                   const unsigned char *hash,
                                   unsigned char *sig) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char digest_info[19 + 64];
    const unsigned char *sign_input = hash;
    size_t sign_input_len = hashlen;
    size_t siglen = 0;
    int rc = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    (void) f_rng;
    (void) p_rng;
    if (ctx == NULL || hash == NULL || sig == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    pkey = rsa_pkey_from_ctx(ctx, 1);
    if (pkey == NULL) {
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_sign_init(pctx) <= 0) {
        goto out;
    }
    if (ctx->MBEDTLS_PRIVATE(padding) == MBEDTLS_RSA_PKCS_V15) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
            rc = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
            goto out;
        }
        if (md_alg != MBEDTLS_MD_NONE) {
            size_t di_len = sizeof(digest_info);
            rc = pkcs1_build_digest_info(md_alg, hash, hashlen, digest_info, &di_len);
            if (rc != 0) {
                goto out;
            }
            sign_input = digest_info;
            sign_input_len = di_len;
        }
    }
    else {
        rc = set_rsa_sig_params(pctx, ctx, md_alg);
        if (rc != 0) {
            goto out;
        }
    }
    siglen = mbedtls_rsa_get_len(ctx);
    if (EVP_PKEY_sign(pctx, sig, &siglen, sign_input, sign_input_len) <= 0) {
        rc = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto out;
    }
    rc = 0;
out:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int openssl_mbedtls_rsa_rsassa_pkcs1_v15_sign(mbedtls_rsa_context *ctx,
                                              mbedtls_f_rng_t *f_rng,
                                              void *p_rng,
                                              mbedtls_md_type_t md_alg,
                                              unsigned int hashlen,
                                              const unsigned char *hash,
                                              unsigned char *sig) {
    int saved_padding = ctx->MBEDTLS_PRIVATE(padding);
    int rc = 0;
    ctx->MBEDTLS_PRIVATE(padding) = MBEDTLS_RSA_PKCS_V15;
    rc = openssl_mbedtls_rsa_pkcs1_sign(ctx, f_rng, p_rng, md_alg, hashlen, hash, sig);
    ctx->MBEDTLS_PRIVATE(padding) = saved_padding;
    return rc;
}

int openssl_mbedtls_rsa_pkcs1_verify(mbedtls_rsa_context *ctx,
                                     mbedtls_md_type_t md_alg,
                                     unsigned int hashlen,
                                     const unsigned char *hash,
                                     const unsigned char *sig) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char digest_info[19 + 64];
    const unsigned char *verify_input = hash;
    size_t verify_input_len = hashlen;
    int rc = MBEDTLS_ERR_RSA_VERIFY_FAILED;
    if (ctx == NULL || hash == NULL || sig == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    pkey = rsa_pkey_from_ctx(ctx, 0);
    if (pkey == NULL) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_verify_init(pctx) <= 0) {
        goto out;
    }
    if (ctx->MBEDTLS_PRIVATE(padding) == MBEDTLS_RSA_PKCS_V15) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
            rc = MBEDTLS_ERR_RSA_VERIFY_FAILED;
            goto out;
        }
        if (md_alg != MBEDTLS_MD_NONE) {
            size_t di_len = sizeof(digest_info);
            if (pkcs1_build_digest_info(md_alg, hash, hashlen, digest_info, &di_len) != 0) {
                rc = MBEDTLS_ERR_RSA_VERIFY_FAILED;
                goto out;
            }
            verify_input = digest_info;
            verify_input_len = di_len;
        }
    }
    else {
        rc = set_rsa_sig_params(pctx, ctx, md_alg);
        if (rc != 0) {
            rc = MBEDTLS_ERR_RSA_VERIFY_FAILED;
            goto out;
        }
    }
    if (EVP_PKEY_verify(pctx, sig, mbedtls_rsa_get_len(ctx), verify_input, verify_input_len) <= 0) {
        rc = MBEDTLS_ERR_RSA_VERIFY_FAILED;
        goto out;
    }
    rc = 0;
out:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int openssl_mbedtls_rsa_pkcs1_decrypt(mbedtls_rsa_context *ctx,
                                      mbedtls_f_rng_t *f_rng,
                                      void *p_rng,
                                      size_t *olen,
                                      const unsigned char *input,
                                      unsigned char *output,
                                      size_t output_max_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_len = 0;
    int padding = 0;
    const EVP_MD *oaep_md = NULL;
    int rc = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    (void) f_rng;
    (void) p_rng;
    if (ctx == NULL || olen == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    pkey = rsa_pkey_from_ctx(ctx, 1);
    if (pkey == NULL) {
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_decrypt_init(pctx) <= 0) {
        goto out;
    }
    if (ctx->MBEDTLS_PRIVATE(padding) == MBEDTLS_RSA_PKCS_V15) {
        padding = RSA_PKCS1_PADDING;
    }
    else if (ctx->MBEDTLS_PRIVATE(padding) == MBEDTLS_RSA_PKCS_V21) {
        padding = RSA_PKCS1_OAEP_PADDING;
    }
    else {
        rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto out;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, padding) <= 0) {
        goto out;
    }
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        if (ctx->MBEDTLS_PRIVATE(hash_id) != MBEDTLS_MD_NONE) {
            oaep_md = evp_md_from_type((mbedtls_md_type_t) ctx->MBEDTLS_PRIVATE(hash_id));
        }
        if (oaep_md == NULL) {
            oaep_md = EVP_sha1();
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, oaep_md) <= 0) {
            goto out;
        }
    }
    if (EVP_PKEY_decrypt(pctx, NULL, &out_len, input, mbedtls_rsa_get_len(ctx)) <= 0) {
        goto out;
    }
    if (out_len > output_max_len) {
        rc = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
        goto out;
    }
    if (EVP_PKEY_decrypt(pctx, output, &out_len, input, mbedtls_rsa_get_len(ctx)) <= 0) {
        goto out;
    }
    *olen = out_len;
    rc = 0;
out:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return rc;
}

void openssl_mbedtls_rsa_init(mbedtls_rsa_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(N));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(E));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(D));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(P));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(Q));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(DP));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(DQ));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(QP));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(RN));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(RP));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(RQ));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(Vi));
    openssl_mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(Vf));
    ctx->MBEDTLS_PRIVATE(padding) = MBEDTLS_RSA_PKCS_V15;
    ctx->MBEDTLS_PRIVATE(hash_id) = MBEDTLS_MD_NONE;
}

void openssl_mbedtls_rsa_free(mbedtls_rsa_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(N));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(E));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(D));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(P));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(Q));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(DP));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(DQ));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(QP));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(RN));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(RP));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(RQ));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(Vi));
    openssl_mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(Vf));
    memset(ctx, 0, sizeof(*ctx));
}

int openssl_mbedtls_rsa_set_padding(mbedtls_rsa_context *ctx, int padding,
                                    mbedtls_md_type_t hash_id) {
    if (ctx == NULL || (padding != MBEDTLS_RSA_PKCS_V15 && padding != MBEDTLS_RSA_PKCS_V21)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    ctx->MBEDTLS_PRIVATE(padding) = padding;
    ctx->MBEDTLS_PRIVATE(hash_id) = hash_id;
    return 0;
}

size_t openssl_mbedtls_rsa_get_len(const mbedtls_rsa_context *ctx) {
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->MBEDTLS_PRIVATE(len) != 0) {
        return ctx->MBEDTLS_PRIVATE(len);
    }
    return openssl_mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(N));
}

int openssl_mbedtls_rsa_import(mbedtls_rsa_context *ctx,
                               const mbedtls_mpi *N,
                               const mbedtls_mpi *P, const mbedtls_mpi *Q,
                               const mbedtls_mpi *D, const mbedtls_mpi *E) {
    if (ctx == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    if (N != NULL && openssl_mbedtls_mpi_copy(&ctx->MBEDTLS_PRIVATE(N), N) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    if (P != NULL && openssl_mbedtls_mpi_copy(&ctx->MBEDTLS_PRIVATE(P), P) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    if (Q != NULL && openssl_mbedtls_mpi_copy(&ctx->MBEDTLS_PRIVATE(Q), Q) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    if (D != NULL && openssl_mbedtls_mpi_copy(&ctx->MBEDTLS_PRIVATE(D), D) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    if (E != NULL && openssl_mbedtls_mpi_copy(&ctx->MBEDTLS_PRIVATE(E), E) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    ctx->MBEDTLS_PRIVATE(len) = openssl_mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(N));
    return 0;
}

int openssl_mbedtls_rsa_complete(mbedtls_rsa_context *ctx) {
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dp = NULL, *dq = NULL, *qp = NULL;
    BIGNUM *one = NULL, *pm1 = NULL, *qm1 = NULL, *phi = NULL;
    BN_CTX *bnctx = NULL;
    int rc = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    if (ctx == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    e = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(E));
    if (e == NULL || BN_is_zero(e)) {
        goto out;
    }
    p = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(P));
    q = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(Q));
    n = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(N));
    d = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(D));
    bnctx = BN_CTX_new();
    one = BN_new();
    if (bnctx == NULL || one == NULL || BN_one(one) != 1) {
        goto out;
    }

    if ((n == NULL || BN_is_zero(n)) && p != NULL && q != NULL && !BN_is_zero(p) && !BN_is_zero(q)) {
        BN_free(n);
        n = BN_new();
        if (n == NULL || BN_mul(n, p, q, bnctx) != 1) {
            goto out;
        }
    }
    if (d == NULL || BN_is_zero(d)) {
        if (p == NULL || q == NULL || BN_is_zero(p) || BN_is_zero(q)) {
            goto out;
        }
        pm1 = BN_dup(p);
        qm1 = BN_dup(q);
        phi = BN_new();
        if (pm1 == NULL || qm1 == NULL || phi == NULL ||
            BN_sub(pm1, pm1, one) != 1 ||
            BN_sub(qm1, qm1, one) != 1 ||
            BN_mul(phi, pm1, qm1, bnctx) != 1) {
            goto out;
        }
        BN_free(d);
        d = BN_mod_inverse(NULL, e, phi, bnctx);
        if (d == NULL) {
            goto out;
        }
    }
    if (p != NULL && !BN_is_zero(p) && d != NULL && !BN_is_zero(d)) {
        BN_free(dp);
        pm1 = BN_dup(p);
        dp = BN_new();
        if (pm1 == NULL || dp == NULL || BN_sub(pm1, pm1, one) != 1 || BN_mod(dp, d, pm1, bnctx) != 1) {
            goto out;
        }
    }
    if (q != NULL && !BN_is_zero(q) && d != NULL && !BN_is_zero(d)) {
        BN_free(dq);
        qm1 = BN_dup(q);
        dq = BN_new();
        if (qm1 == NULL || dq == NULL || BN_sub(qm1, qm1, one) != 1 || BN_mod(dq, d, qm1, bnctx) != 1) {
            goto out;
        }
    }
    if (q != NULL && !BN_is_zero(q) && p != NULL && !BN_is_zero(p)) {
        BN_free(qp);
        qp = BN_mod_inverse(NULL, q, p, bnctx);
        if (qp == NULL) {
            goto out;
        }
    }

    if (n != NULL && bn_to_mpi(n, &ctx->MBEDTLS_PRIVATE(N)) != 0) {
        goto out;
    }
    if (d != NULL && bn_to_mpi(d, &ctx->MBEDTLS_PRIVATE(D)) != 0) {
        goto out;
    }
    if (dp != NULL && bn_to_mpi(dp, &ctx->MBEDTLS_PRIVATE(DP)) != 0) {
        goto out;
    }
    if (dq != NULL && bn_to_mpi(dq, &ctx->MBEDTLS_PRIVATE(DQ)) != 0) {
        goto out;
    }
    if (qp != NULL && bn_to_mpi(qp, &ctx->MBEDTLS_PRIVATE(QP)) != 0) {
        goto out;
    }
    ctx->MBEDTLS_PRIVATE(len) = openssl_mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(N));
    rc = 0;
out:
    BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
    BN_free(dp); BN_free(dq); BN_free(qp);
    BN_free(one); BN_free(pm1); BN_free(qm1); BN_free(phi);
    BN_CTX_free(bnctx);
    return rc;
}

int openssl_mbedtls_rsa_check_pubkey(const mbedtls_rsa_context *ctx) {
    BIGNUM *n = NULL, *e = NULL;
    int rc = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    if (ctx == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    n = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(N));
    e = mpi_to_bn(&ctx->MBEDTLS_PRIVATE(E));
    if (n == NULL || e == NULL || BN_is_zero(n) || BN_is_zero(e) || !BN_is_odd(n) || !BN_is_odd(e)) {
        goto out;
    }
    if (BN_num_bits(n) < 128 || BN_cmp(e, BN_value_one()) <= 0) {
        goto out;
    }
    rc = 0;
out:
    BN_free(n);
    BN_free(e);
    return rc;
}

int openssl_mbedtls_rsa_check_privkey(const mbedtls_rsa_context *ctx) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    if (ctx == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
    pkey = rsa_pkey_from_ctx(ctx, 1);
    if (pkey == NULL) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_private_check(pctx) <= 0) {
        goto out;
    }
    rc = 0;
out:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return rc;
}

static const mbedtls_ecp_curve_info g_ec_curve_info[] = {
    { MBEDTLS_ECP_DP_SECP192R1, 19, 192, "secp192r1" },
    { MBEDTLS_ECP_DP_SECP224R1, 21, 224, "secp224r1" },
    { MBEDTLS_ECP_DP_SECP192K1, 18, 192, "secp192k1" },
    { MBEDTLS_ECP_DP_SECP224K1, 20, 224, "secp224k1" },
    { MBEDTLS_ECP_DP_SECP256R1, 23, 256, "secp256r1" },
    { MBEDTLS_ECP_DP_SECP384R1, 24, 384, "secp384r1" },
    { MBEDTLS_ECP_DP_SECP521R1, 25, 521, "secp521r1" },
    { MBEDTLS_ECP_DP_SECP256K1, 22, 256, "secp256k1" },
    { MBEDTLS_ECP_DP_BP256R1, 26, 256, "brainpoolP256r1" },
    { MBEDTLS_ECP_DP_BP384R1, 27, 384, "brainpoolP384r1" },
    { MBEDTLS_ECP_DP_BP512R1, 28, 512, "brainpoolP512r1" },
    { MBEDTLS_ECP_DP_CURVE25519, 29, 255, "x25519" },
    { MBEDTLS_ECP_DP_CURVE448, 30, 448, "x448" },
    { MBEDTLS_ECP_DP_ED25519, 31, 256, "ed25519" },
    { MBEDTLS_ECP_DP_ED448, 32, 456, "ed448" },
    { MBEDTLS_ECP_DP_NONE, 0, 0, NULL },
};

const mbedtls_ecp_curve_info *openssl_mbedtls_ecp_curve_info_from_grp_id(mbedtls_ecp_group_id grp_id) {
    size_t i;
    for (i = 0; g_ec_curve_info[i].grp_id != MBEDTLS_ECP_DP_NONE; i++) {
        if (g_ec_curve_info[i].grp_id == grp_id) {
            return &g_ec_curve_info[i];
        }
    }
    return NULL;
}

mbedtls_ecp_curve_type openssl_mbedtls_ecp_get_type(const mbedtls_ecp_group *grp) {
    mbedtls_ecp_group_id gid;
    if (grp == NULL) {
        return MBEDTLS_ECP_TYPE_NONE;
    }
    gid = grp->id;
    switch (gid) {
        case MBEDTLS_ECP_DP_CURVE25519:
        case MBEDTLS_ECP_DP_CURVE448:
            return MBEDTLS_ECP_TYPE_MONTGOMERY;
        case MBEDTLS_ECP_DP_ED25519:
        case MBEDTLS_ECP_DP_ED448:
            return MBEDTLS_ECP_TYPE_EDWARDS;
        case MBEDTLS_ECP_DP_NONE:
            return MBEDTLS_ECP_TYPE_NONE;
        default:
            return MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS;
    }
}

void openssl_mbedtls_ecp_point_init(mbedtls_ecp_point *pt) {
    if (pt == NULL) {
        return;
    }
    openssl_mbedtls_mpi_init(&pt->MBEDTLS_PRIVATE(X));
    openssl_mbedtls_mpi_init(&pt->MBEDTLS_PRIVATE(Y));
    openssl_mbedtls_mpi_init(&pt->MBEDTLS_PRIVATE(Z));
}

void openssl_mbedtls_ecp_point_free(mbedtls_ecp_point *pt) {
    if (pt == NULL) {
        return;
    }
    openssl_mbedtls_mpi_free(&pt->MBEDTLS_PRIVATE(X));
    openssl_mbedtls_mpi_free(&pt->MBEDTLS_PRIVATE(Y));
    openssl_mbedtls_mpi_free(&pt->MBEDTLS_PRIVATE(Z));
}

void openssl_mbedtls_ecp_group_init(mbedtls_ecp_group *grp) {
    if (grp == NULL) {
        return;
    }
    memset(grp, 0, sizeof(*grp));
    grp->id = MBEDTLS_ECP_DP_NONE;
    openssl_mbedtls_mpi_init(&grp->P);
    openssl_mbedtls_mpi_init(&grp->A);
    openssl_mbedtls_mpi_init(&grp->B);
    openssl_mbedtls_ecp_point_init(&grp->G);
    openssl_mbedtls_mpi_init(&grp->N);
}

void openssl_mbedtls_ecp_group_free(mbedtls_ecp_group *grp) {
    if (grp == NULL) {
        return;
    }
    openssl_mbedtls_mpi_free(&grp->P);
    openssl_mbedtls_mpi_free(&grp->A);
    openssl_mbedtls_mpi_free(&grp->B);
    openssl_mbedtls_ecp_point_free(&grp->G);
    openssl_mbedtls_mpi_free(&grp->N);
    grp->id = MBEDTLS_ECP_DP_NONE;
    grp->pbits = 0;
    grp->nbits = 0;
}

void openssl_mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key) {
    if (key == NULL) {
        return;
    }
    openssl_mbedtls_ecp_group_init(&key->MBEDTLS_PRIVATE(grp));
    openssl_mbedtls_mpi_init(&key->MBEDTLS_PRIVATE(d));
    openssl_mbedtls_ecp_point_init(&key->MBEDTLS_PRIVATE(Q));
}

void openssl_mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key) {
    if (key == NULL) {
        return;
    }
    openssl_mbedtls_ecp_group_free(&key->MBEDTLS_PRIVATE(grp));
    openssl_mbedtls_mpi_free(&key->MBEDTLS_PRIVATE(d));
    openssl_mbedtls_ecp_point_free(&key->MBEDTLS_PRIVATE(Q));
}

void openssl_mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx) {
    openssl_mbedtls_ecp_keypair_init((mbedtls_ecp_keypair *) ctx);
}

void openssl_mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx) {
    openssl_mbedtls_ecp_keypair_free((mbedtls_ecp_keypair *) ctx);
}

static int point_to_ec(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *P, EC_POINT *out, const EC_GROUP *ecgrp) {
    BIGNUM *x = NULL, *y = NULL;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    (void) grp;
    x = mpi_to_bn(&P->MBEDTLS_PRIVATE(X));
    y = mpi_to_bn(&P->MBEDTLS_PRIVATE(Y));
    if (x == NULL || y == NULL) {
        goto out;
    }
    if (EC_POINT_set_affine_coordinates(ecgrp, out, x, y, NULL) != 1) {
        goto out;
    }
    rc = 0;
out:
    BN_free(x);
    BN_free(y);
    return rc;
}

static int ec_to_point(const EC_GROUP *ecgrp, const EC_POINT *in, mbedtls_ecp_point *P) {
    BIGNUM *x = NULL, *y = NULL;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL ||
        EC_POINT_get_affine_coordinates(ecgrp, in, x, y, NULL) != 1) {
        goto out;
    }
    if (bn_to_mpi(x, &P->MBEDTLS_PRIVATE(X)) != 0 ||
        bn_to_mpi(y, &P->MBEDTLS_PRIVATE(Y)) != 0 ||
        openssl_mbedtls_mpi_lset(&P->MBEDTLS_PRIVATE(Z), 1) != 0) {
        goto out;
    }
    rc = 0;
out:
    BN_free(x);
    BN_free(y);
    return rc;
}

int openssl_mbedtls_ecp_group_load(mbedtls_ecp_group *grp, mbedtls_ecp_group_id id) {
    const mbedtls_ecp_curve_info *info;
    EC_GROUP *ecgrp = NULL;
    const EC_POINT *gen = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *n = NULL;
    int nid;
    int rc = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    if (grp == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    openssl_mbedtls_ecp_group_free(grp);
    openssl_mbedtls_ecp_group_init(grp);
    grp->id = id;
    info = openssl_mbedtls_ecp_curve_info_from_grp_id(id);
    if (info == NULL) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    grp->nbits = info->bit_size;
    grp->pbits = info->bit_size;

    if (openssl_mbedtls_ecp_get_type(grp) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return 0;
    }
    nid = ec_nid_from_group(id);
    if (nid == NID_undef) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    ecgrp = EC_GROUP_new_by_curve_name(nid);
    p = BN_new();
    a = BN_new();
    b = BN_new();
    n = BN_new();
    if (ecgrp == NULL || p == NULL || a == NULL || b == NULL || n == NULL ||
        EC_GROUP_get_curve(ecgrp, p, a, b, NULL) != 1 ||
        EC_GROUP_get_order(ecgrp, n, NULL) != 1) {
        goto out;
    }
    gen = EC_GROUP_get0_generator(ecgrp);
    if (gen == NULL ||
        bn_to_mpi(p, &grp->P) != 0 ||
        bn_to_mpi(a, &grp->A) != 0 ||
        bn_to_mpi(b, &grp->B) != 0 ||
        bn_to_mpi(n, &grp->N) != 0 ||
        ec_to_point(ecgrp, gen, &grp->G) != 0) {
        goto out;
    }
    grp->pbits = (size_t) BN_num_bits(p);
    grp->nbits = (size_t) BN_num_bits(n);
    rc = 0;
out:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(n);
    EC_GROUP_free(ecgrp);
    return rc;
}

int openssl_mbedtls_ecp_read_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                                 const unsigned char *buf, size_t buflen) {
    mbedtls_ecp_curve_type t;
    size_t nbytes;
    int rc;
    if (key == NULL || buf == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    rc = openssl_mbedtls_ecp_group_load(&key->MBEDTLS_PRIVATE(grp), grp_id);
    if (rc != 0) {
        return rc;
    }
    t = openssl_mbedtls_ecp_get_type(&key->MBEDTLS_PRIVATE(grp));
    nbytes = (key->MBEDTLS_PRIVATE(grp).nbits + 7u) / 8u;
    if (nbytes == 0 || buflen > nbytes + 1u) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (t == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        rc = openssl_mbedtls_mpi_read_binary(&key->MBEDTLS_PRIVATE(d), buf, buflen);
    } else {
        rc = openssl_mbedtls_mpi_read_binary_le(&key->MBEDTLS_PRIVATE(d), buf, buflen);
    }
    return rc;
}

int openssl_mbedtls_ecp_write_key_ext(const mbedtls_ecp_keypair *key,
                                      size_t *olen, unsigned char *buf, size_t buflen) {
    mbedtls_ecp_curve_type t;
    size_t nbytes;
    int rc;
    if (key == NULL || olen == NULL || buf == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    nbytes = (key->MBEDTLS_PRIVATE(grp).nbits + 7u) / 8u;
    if (nbytes == 0 || buflen < nbytes) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    t = openssl_mbedtls_ecp_get_type(&key->MBEDTLS_PRIVATE(grp));
    if (t == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        rc = openssl_mbedtls_mpi_write_binary(&key->MBEDTLS_PRIVATE(d), buf, nbytes);
    } else {
        rc = openssl_mbedtls_mpi_write_binary_le(&key->MBEDTLS_PRIVATE(d), buf, nbytes);
    }
    if (rc != 0) {
        return rc;
    }
    *olen = nbytes;
    return 0;
}

int openssl_mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng) {
    mbedtls_ecp_curve_type t;
    int nid;
    EC_GROUP *ecgrp = NULL;
    EC_POINT *ecp = NULL, *ecr = NULL;
    BIGNUM *k = NULL;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    unsigned char raw_priv[64], raw_pub[64];
    size_t priv_len = 0, pub_len = sizeof(raw_pub);
    EVP_PKEY *pkey = NULL;
    int ptype = 0;
    (void) f_rng;
    (void) p_rng;
    if (grp == NULL || R == NULL || m == NULL || P == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    t = openssl_mbedtls_ecp_get_type(grp);
    if (t == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        nid = ec_nid_from_group(grp->id);
        if (nid == NID_undef) {
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        ecgrp = EC_GROUP_new_by_curve_name(nid);
        ecp = EC_POINT_new(ecgrp);
        ecr = EC_POINT_new(ecgrp);
        k = mpi_to_bn(m);
        if (ecgrp == NULL || ecp == NULL || ecr == NULL || k == NULL) {
            goto out;
        }
        if (point_to_ec(grp, P, ecp, ecgrp) != 0 ||
            EC_POINT_mul(ecgrp, ecr, NULL, ecp, k, NULL) != 1 ||
            ec_to_point(ecgrp, ecr, R) != 0) {
            goto out;
        }
        rc = 0;
        goto out;
    }

    memset(raw_priv, 0, sizeof(raw_priv));
    priv_len = (grp->nbits + 7u) / 8u;
    if (priv_len == 0 || priv_len > sizeof(raw_priv) ||
        openssl_mbedtls_mpi_write_binary_le(m, raw_priv, priv_len) != 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (grp->id == MBEDTLS_ECP_DP_ED25519) {
        ptype = EVP_PKEY_ED25519;
    } else if (grp->id == MBEDTLS_ECP_DP_ED448) {
        ptype = EVP_PKEY_ED448;
    } else if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {
        ptype = EVP_PKEY_X25519;
    } else if (grp->id == MBEDTLS_ECP_DP_CURVE448) {
        ptype = EVP_PKEY_X448;
    } else {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    pkey = EVP_PKEY_new_raw_private_key(ptype, NULL, raw_priv, priv_len);
    if (pkey == NULL || EVP_PKEY_get_raw_public_key(pkey, raw_pub, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (openssl_mbedtls_mpi_read_binary_le(&R->MBEDTLS_PRIVATE(X), raw_pub, pub_len) != 0 ||
        openssl_mbedtls_mpi_lset(&R->MBEDTLS_PRIVATE(Y), 0) != 0 ||
        openssl_mbedtls_mpi_lset(&R->MBEDTLS_PRIVATE(Z), 1) != 0) {
        EVP_PKEY_free(pkey);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    EVP_PKEY_free(pkey);
    rc = 0;
out:
    BN_free(k);
    EC_POINT_free(ecp);
    EC_POINT_free(ecr);
    EC_GROUP_free(ecgrp);
    OPENSSL_cleanse(raw_priv, sizeof(raw_priv));
    OPENSSL_cleanse(raw_pub, sizeof(raw_pub));
    return rc;
}

int openssl_mbedtls_ecp_point_edwards(mbedtls_ecp_group *grp,
                                      mbedtls_ecp_point *R,
                                      const mbedtls_mpi *m,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng) {
    return openssl_mbedtls_ecp_mul(grp, R, m, &grp->G, f_rng, p_rng);
}

int openssl_mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                           const mbedtls_ecp_point *P,
                                           int format, size_t *olen,
                                           unsigned char *buf, size_t buflen) {
    mbedtls_ecp_curve_type t;
    int nid;
    EC_GROUP *ecgrp = NULL;
    EC_POINT *ecp = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    size_t len;
    if (grp == NULL || P == NULL || olen == NULL || buf == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    t = openssl_mbedtls_ecp_get_type(grp);
    if (t == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        nid = ec_nid_from_group(grp->id);
        if (nid == NID_undef) {
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        ecgrp = EC_GROUP_new_by_curve_name(nid);
        ecp = EC_POINT_new(ecgrp);
        if (ecgrp == NULL || ecp == NULL || point_to_ec(grp, P, ecp, ecgrp) != 0) {
            EC_POINT_free(ecp);
            EC_GROUP_free(ecgrp);
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
        if (format == MBEDTLS_ECP_PF_COMPRESSED) {
            form = POINT_CONVERSION_COMPRESSED;
        }
        len = EC_POINT_point2oct(ecgrp, ecp, form, NULL, 0, NULL);
        if (len == 0 || len > buflen) {
            EC_POINT_free(ecp);
            EC_GROUP_free(ecgrp);
            return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        }
        if (EC_POINT_point2oct(ecgrp, ecp, form, buf, len, NULL) != len) {
            EC_POINT_free(ecp);
            EC_GROUP_free(ecgrp);
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
        *olen = len;
        EC_POINT_free(ecp);
        EC_GROUP_free(ecgrp);
        return 0;
    }

    len = (grp->nbits + 7u) / 8u;
    if (len == 0 || buflen < len) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    if (openssl_mbedtls_mpi_write_binary_le(&P->MBEDTLS_PRIVATE(X), buf, len) != 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    *olen = len;
    return 0;
}

int openssl_mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                          mbedtls_ecp_point *pt,
                                          const unsigned char *buf, size_t ilen) {
    mbedtls_ecp_curve_type t;
    int nid;
    EC_GROUP *ecgrp = NULL;
    EC_POINT *ecp = NULL;
    int rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (grp == NULL || pt == NULL || buf == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    t = openssl_mbedtls_ecp_get_type(grp);
    if (t == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        nid = ec_nid_from_group(grp->id);
        if (nid == NID_undef) {
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        ecgrp = EC_GROUP_new_by_curve_name(nid);
        ecp = EC_POINT_new(ecgrp);
        if (ecgrp == NULL || ecp == NULL ||
            EC_POINT_oct2point(ecgrp, ecp, buf, ilen, NULL) != 1 ||
            ec_to_point(ecgrp, ecp, pt) != 0) {
            goto out;
        }
        rc = 0;
        goto out;
    }
    if (openssl_mbedtls_mpi_read_binary_le(&pt->MBEDTLS_PRIVATE(X), buf, ilen) != 0 ||
        openssl_mbedtls_mpi_lset(&pt->MBEDTLS_PRIVATE(Y), 0) != 0 ||
        openssl_mbedtls_mpi_lset(&pt->MBEDTLS_PRIVATE(Z), 1) != 0) {
        goto out;
    }
    rc = 0;
out:
    EC_POINT_free(ecp);
    EC_GROUP_free(ecgrp);
    return rc;
}

int openssl_mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp,
                                     const mbedtls_ecp_point *pt) {
    mbedtls_ecp_curve_type t;
    int nid;
    EC_GROUP *ecgrp = NULL;
    EC_POINT *ecp = NULL;
    int ok = 0;
    if (grp == NULL || pt == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    t = openssl_mbedtls_ecp_get_type(grp);
    if (t != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return openssl_mbedtls_mpi_cmp_int(&pt->MBEDTLS_PRIVATE(X), 0) == 0 ?
               MBEDTLS_ERR_ECP_INVALID_KEY : 0;
    }
    nid = ec_nid_from_group(grp->id);
    if (nid == NID_undef) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    ecgrp = EC_GROUP_new_by_curve_name(nid);
    ecp = EC_POINT_new(ecgrp);
    if (ecgrp == NULL || ecp == NULL || point_to_ec(grp, pt, ecp, ecgrp) != 0) {
        EC_POINT_free(ecp);
        EC_GROUP_free(ecgrp);
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    ok = EC_POINT_is_on_curve(ecgrp, ecp, NULL);
    EC_POINT_free(ecp);
    EC_GROUP_free(ecgrp);
    return ok == 1 ? 0 : MBEDTLS_ERR_ECP_INVALID_KEY;
}

int openssl_mbedtls_ecp_check_pub_priv(const mbedtls_ecp_keypair *pub,
                                       const mbedtls_ecp_keypair *prv,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng) {
    mbedtls_ecp_point q;
    unsigned char a[MBEDTLS_ECP_MAX_PT_LEN], b[MBEDTLS_ECP_MAX_PT_LEN];
    size_t alen = 0, blen = 0;
    int rc;
    if (pub == NULL || prv == NULL || pub->MBEDTLS_PRIVATE(grp).id != prv->MBEDTLS_PRIVATE(grp).id) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    openssl_mbedtls_ecp_point_init(&q);
    rc = openssl_mbedtls_ecp_mul((mbedtls_ecp_group *) &prv->MBEDTLS_PRIVATE(grp), &q,
                                 &prv->MBEDTLS_PRIVATE(d), &prv->MBEDTLS_PRIVATE(grp).G,
                                 f_rng, p_rng);
    if (rc != 0) {
        openssl_mbedtls_ecp_point_free(&q);
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    rc = openssl_mbedtls_ecp_point_write_binary(&pub->MBEDTLS_PRIVATE(grp), &pub->MBEDTLS_PRIVATE(Q),
                                                MBEDTLS_ECP_PF_UNCOMPRESSED, &alen, a, sizeof(a));
    if (rc == 0) {
        rc = openssl_mbedtls_ecp_point_write_binary(&prv->MBEDTLS_PRIVATE(grp), &q,
                                                    MBEDTLS_ECP_PF_UNCOMPRESSED, &blen, b, sizeof(b));
    }
    openssl_mbedtls_ecp_point_free(&q);
    if (rc != 0 || alen != blen || memcmp(a, b, alen) != 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    return 0;
}

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
#define ECDH_GRP(ctx) (&(ctx)->MBEDTLS_PRIVATE(grp))
#define ECDH_D(ctx) (&(ctx)->MBEDTLS_PRIVATE(d))
#define ECDH_Q(ctx) (&(ctx)->MBEDTLS_PRIVATE(Q))
#define ECDH_QP(ctx) (&(ctx)->MBEDTLS_PRIVATE(Qp))
#define ECDH_Z(ctx) (&(ctx)->MBEDTLS_PRIVATE(z))
#else
#define ECDH_GRP(ctx) (&(ctx)->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(grp))
#define ECDH_D(ctx) (&(ctx)->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(d))
#define ECDH_Q(ctx) (&(ctx)->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(Q))
#define ECDH_QP(ctx) (&(ctx)->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(Qp))
#define ECDH_Z(ctx) (&(ctx)->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(z))
#endif

void openssl_mbedtls_ecdh_init(mbedtls_ecdh_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
#if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    ctx->MBEDTLS_PRIVATE(var) = MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
#endif
    openssl_mbedtls_ecp_group_init(ECDH_GRP(ctx));
    openssl_mbedtls_mpi_init(ECDH_D(ctx));
    openssl_mbedtls_ecp_point_init(ECDH_Q(ctx));
    openssl_mbedtls_ecp_point_init(ECDH_QP(ctx));
    openssl_mbedtls_mpi_init(ECDH_Z(ctx));
}

void openssl_mbedtls_ecdh_free(mbedtls_ecdh_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    openssl_mbedtls_ecp_group_free(ECDH_GRP(ctx));
    openssl_mbedtls_mpi_free(ECDH_D(ctx));
    openssl_mbedtls_ecp_point_free(ECDH_Q(ctx));
    openssl_mbedtls_ecp_point_free(ECDH_QP(ctx));
    openssl_mbedtls_mpi_free(ECDH_Z(ctx));
    memset(ctx, 0, sizeof(*ctx));
}

int openssl_mbedtls_ecdh_setup(mbedtls_ecdh_context *ctx,
                               mbedtls_ecp_group_id grp_id) {
    if (ctx == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    ctx->MBEDTLS_PRIVATE(grp_id) = grp_id;
#endif
    return openssl_mbedtls_ecp_group_load(ECDH_GRP(ctx), grp_id);
}

int openssl_mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                    mbedtls_f_rng_t *f_rng,
                                    void *p_rng) {
    size_t nbytes;
    unsigned char rnd[MBEDTLS_ECP_MAX_BYTES + 8];
    int rc;
    if (grp == NULL || d == NULL || Q == NULL || f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    nbytes = (grp->nbits + 7u) / 8u;
    if (nbytes == 0 || nbytes > sizeof(rnd) || f_rng(p_rng, rnd, nbytes) != 0) {
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    if (openssl_mbedtls_mpi_read_binary(d, rnd, nbytes) != 0) {
        OPENSSL_cleanse(rnd, sizeof(rnd));
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    OPENSSL_cleanse(rnd, sizeof(rnd));
    if (openssl_mbedtls_mpi_cmp_int(d, 0) == 0) {
        openssl_mbedtls_mpi_lset(d, 1);
    }
    if (openssl_mbedtls_mpi_cmp_int(&grp->N, 0) > 0) {
        rc = openssl_mbedtls_mpi_mod_mpi(d, d, &grp->N);
        if (rc != 0) {
            return rc;
        }
        if (openssl_mbedtls_mpi_cmp_int(d, 0) == 0) {
            openssl_mbedtls_mpi_lset(d, 1);
        }
    }
    return openssl_mbedtls_ecp_mul(grp, Q, d, &grp->G, f_rng, p_rng);
}

int openssl_mbedtls_ecdh_read_public(mbedtls_ecdh_context *ctx,
                                     const unsigned char *input, size_t ilen) {
    const unsigned char *pt = input;
    size_t pt_len = ilen;
    if (ctx == NULL || input == NULL || ilen == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    /* Accept both [point] and TLS-style [len || point] */
    if (ilen > 1 && (size_t) input[0] == ilen - 1) {
        pt = input + 1;
        pt_len = ilen - 1;
    }
    return openssl_mbedtls_ecp_point_read_binary(ECDH_GRP(ctx), ECDH_QP(ctx), pt, pt_len);
}

int openssl_mbedtls_ecdh_calc_secret(mbedtls_ecdh_context *ctx, size_t *olen,
                                     unsigned char *output, size_t output_size,
                                     mbedtls_f_rng_t *f_rng,
                                     void *p_rng) {
    mbedtls_ecp_point s;
    size_t nbytes;
    int rc;
    if (ctx == NULL || olen == NULL || output == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    nbytes = (ECDH_GRP(ctx)->nbits + 7u) / 8u;
    if (output_size < nbytes) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    openssl_mbedtls_ecp_point_init(&s);
    rc = openssl_mbedtls_ecp_mul(ECDH_GRP(ctx), &s, ECDH_D(ctx), ECDH_QP(ctx), f_rng, p_rng);
    if (rc == 0) {
        rc = openssl_mbedtls_mpi_copy(ECDH_Z(ctx), &s.MBEDTLS_PRIVATE(X));
    }
    if (rc == 0) {
        rc = openssl_mbedtls_mpi_write_binary(ECDH_Z(ctx), output, nbytes);
    }
    openssl_mbedtls_ecp_point_free(&s);
    if (rc != 0) {
        return rc;
    }
    *olen = nbytes;
    return 0;
}

static int asn1_get_len_local(unsigned char **p, const unsigned char *end, size_t *len) {
    size_t i, n;
    if (p == NULL || *p == NULL || end == NULL || len == NULL || *p >= end) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }
    if ((**p & 0x80u) == 0) {
        *len = *(*p)++;
        if (*len > (size_t) (end - *p)) {
            return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
        }
        return 0;
    }
    n = (size_t) (*(*p)++ & 0x7Fu);
    if (n == 0 || n > sizeof(size_t) || (size_t) (end - *p) < n) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    *len = 0;
    for (i = 0; i < n; i++) {
        *len = (*len << 8) | *(*p)++;
    }
    if (*len > (size_t) (end - *p)) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }
    return 0;
}

int openssl_mbedtls_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len,
                                 int tag) {
    if (p == NULL || *p == NULL || end == NULL || *p >= end) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }
    if (**p != (unsigned char) tag) {
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }
    (*p)++;
    return asn1_get_len_local(p, end, len);
}

int openssl_mbedtls_asn1_get_int(unsigned char **p, const unsigned char *end, int *val) {
    size_t len, i;
    int ret;
    if (val == NULL) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    ret = openssl_mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (ret != 0) {
        return ret;
    }
    if (len == 0 || len > sizeof(int) || *p + len > end) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    *val = 0;
    for (i = 0; i < len; i++) {
        *val = (*val << 8) | (*p)[i];
    }
    *p += len;
    return 0;
}

int openssl_mbedtls_asn1_get_alg_null(unsigned char **p, const unsigned char *end,
                                      mbedtls_asn1_buf *alg) {
    size_t len = 0, params_len = 0;
    const unsigned char *seq_end;
    int ret;
    if (p == NULL || *p == NULL || end == NULL || alg == NULL) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    ret = openssl_mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    seq_end = *p + len;
    ret = openssl_mbedtls_asn1_get_tag(p, seq_end, &alg->len, MBEDTLS_ASN1_OID);
    if (ret != 0) {
        return ret;
    }
    alg->tag = MBEDTLS_ASN1_OID;
    alg->p = *p;
    *p += alg->len;
    if (*p == seq_end) {
        return 0;
    }
    ret = openssl_mbedtls_asn1_get_tag(p, seq_end, &params_len, MBEDTLS_ASN1_NULL);
    if (ret != 0 || params_len != 0 || *p != seq_end) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    return 0;
}

static int oid_eq(const mbedtls_asn1_buf *oid, const char *val, size_t len) {
    return oid != NULL && oid->p != NULL && oid->len == len && memcmp(oid->p, val, len) == 0;
}

int openssl_mbedtls_oid_get_md_hmac(const mbedtls_asn1_buf *oid, mbedtls_md_type_t *md_hmac) {
    if (oid == NULL || md_hmac == NULL) {
        return MBEDTLS_ERR_OID_BUF_TOO_SMALL;
    }
    if (oid_eq(oid, OID_HMAC_SHA1, sizeof(OID_HMAC_SHA1) - 1)) {
        *md_hmac = MBEDTLS_MD_SHA1;
        return 0;
    }
    if (oid_eq(oid, OID_HMAC_SHA224, sizeof(OID_HMAC_SHA224) - 1)) {
        *md_hmac = MBEDTLS_MD_SHA224;
        return 0;
    }
    if (oid_eq(oid, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256) - 1)) {
        *md_hmac = MBEDTLS_MD_SHA256;
        return 0;
    }
    if (oid_eq(oid, OID_HMAC_SHA384, sizeof(OID_HMAC_SHA384) - 1)) {
        *md_hmac = MBEDTLS_MD_SHA384;
        return 0;
    }
    if (oid_eq(oid, OID_HMAC_SHA512, sizeof(OID_HMAC_SHA512) - 1)) {
        *md_hmac = MBEDTLS_MD_SHA512;
        return 0;
    }
    return MBEDTLS_ERR_OID_NOT_FOUND;
}

int openssl_mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type,
                                          const unsigned char *password,
                                          size_t plen,
                                          const unsigned char *salt,
                                          size_t slen,
                                          unsigned int iteration_count,
                                          uint32_t key_length,
                                          unsigned char *output) {
    const EVP_MD *md = evp_md_from_type(md_type);
    if (md == NULL || password == NULL || salt == NULL || output == NULL || key_length == 0) {
        return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
    }
    if (PKCS5_PBKDF2_HMAC((const char *) password, (int) plen,
                          salt, (int) slen, (int) iteration_count,
                          md, (int) key_length, output) != 1) {
        return MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH;
    }
    return 0;
}

static const EVP_CIPHER *cipher_from_oid(const mbedtls_asn1_buf *oid) {
    if (oid_eq(oid, OID_AES128_CBC, sizeof(OID_AES128_CBC) - 1)) return EVP_aes_128_cbc();
    if (oid_eq(oid, OID_AES192_CBC, sizeof(OID_AES192_CBC) - 1)) return EVP_aes_192_cbc();
    if (oid_eq(oid, OID_AES256_CBC, sizeof(OID_AES256_CBC) - 1)) return EVP_aes_256_cbc();
    if (oid_eq(oid, OID_AES128_CFB, sizeof(OID_AES128_CFB) - 1)) return EVP_aes_128_cfb128();
    if (oid_eq(oid, OID_AES192_CFB, sizeof(OID_AES192_CFB) - 1)) return EVP_aes_192_cfb128();
    if (oid_eq(oid, OID_AES256_CFB, sizeof(OID_AES256_CFB) - 1)) return EVP_aes_256_cfb128();
    if (oid_eq(oid, OID_AES128_OFB, sizeof(OID_AES128_OFB) - 1)) return EVP_aes_128_ofb();
    if (oid_eq(oid, OID_AES192_OFB, sizeof(OID_AES192_OFB) - 1)) return EVP_aes_192_ofb();
    if (oid_eq(oid, OID_AES256_OFB, sizeof(OID_AES256_OFB) - 1)) return EVP_aes_256_ofb();
    return NULL;
}

int openssl_mbedtls_pkcs5_pbes2_ext(const mbedtls_asn1_buf *pbe_params, int mode,
                                    const unsigned char *pwd, size_t pwdlen,
                                    const unsigned char *data, size_t datalen,
                                    unsigned char *output, size_t output_size, size_t *output_len) {
    unsigned char *p;
    const unsigned char *end, *seq_end, *kdf_end, *kdf_params_end, *enc_end;
    size_t len = 0, iv_len = 0;
    mbedtls_asn1_buf kdf_oid = {0}, prf_oid = {0}, enc_oid = {0};
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
    mbedtls_asn1_buf salt = {0};
    int iterations = 0;
    int keylen = 0;
    unsigned char key[32];
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    int outl = 0, outl2 = 0;
    const unsigned char *iv = NULL;
    int rc = MBEDTLS_ERR_PKCS5_INVALID_FORMAT;

    if (pbe_params == NULL || pwd == NULL || data == NULL || output == NULL || output_len == NULL) {
        return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
    }
    p = pbe_params->p;
    end = pbe_params->p + pbe_params->len;
    if (pbe_params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    if (openssl_mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    seq_end = p + len;

    if (openssl_mbedtls_asn1_get_tag(&p, seq_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    kdf_end = p + len;
    if (openssl_mbedtls_asn1_get_tag(&p, kdf_end, &kdf_oid.len, MBEDTLS_ASN1_OID) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    kdf_oid.p = p;
    kdf_oid.tag = MBEDTLS_ASN1_OID;
    p += kdf_oid.len;
    if (!oid_eq(&kdf_oid, OID_PKCS5_PBKDF2, sizeof(OID_PKCS5_PBKDF2) - 1) ||
        openssl_mbedtls_asn1_get_tag(&p, kdf_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }
    kdf_params_end = p + len;
    if (openssl_mbedtls_asn1_get_tag(&p, kdf_params_end, &salt.len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    salt.p = p;
    salt.tag = MBEDTLS_ASN1_OCTET_STRING;
    p += salt.len;
    if (openssl_mbedtls_asn1_get_int(&p, kdf_params_end, &iterations) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    if (p < kdf_params_end && openssl_mbedtls_asn1_get_int(&p, kdf_params_end, &keylen) != 0) {
        keylen = 0;
    }
    if (p < kdf_params_end) {
        if (openssl_mbedtls_asn1_get_alg_null(&p, kdf_params_end, &prf_oid) != 0 ||
            openssl_mbedtls_oid_get_md_hmac(&prf_oid, &md_type) != 0) {
            return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
        }
    }
    if (p != kdf_end) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }

    if (openssl_mbedtls_asn1_get_tag(&p, seq_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    enc_end = p + len;
    if (openssl_mbedtls_asn1_get_tag(&p, enc_end, &enc_oid.len, MBEDTLS_ASN1_OID) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    enc_oid.p = p;
    enc_oid.tag = MBEDTLS_ASN1_OID;
    p += enc_oid.len;
    cipher = cipher_from_oid(&enc_oid);
    if (cipher == NULL) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }
    if (openssl_mbedtls_asn1_get_tag(&p, enc_end, &iv_len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }
    iv = p;
    p += iv_len;
    if (p != enc_end || enc_end != seq_end) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }

    if (keylen == 0) {
        keylen = EVP_CIPHER_get_key_length(cipher);
    }
    if (keylen <= 0 || (size_t) keylen > sizeof(key)) {
        return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
    }
    rc = openssl_mbedtls_pkcs5_pbkdf2_hmac_ext(md_type, pwd, pwdlen, salt.p, salt.len,
                                               (unsigned int) iterations, (uint32_t) keylen, key);
    if (rc != 0) {
        return rc;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL ||
        EVP_CipherInit_ex(cctx, cipher, NULL, key, iv, mode == MBEDTLS_PKCS5_ENCRYPT ? 1 : 0) != 1 ||
        EVP_CipherUpdate(cctx, output, &outl, data, (int) datalen) != 1 ||
        EVP_CipherFinal_ex(cctx, output + outl, &outl2) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        OPENSSL_cleanse(key, sizeof(key));
        return MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH;
    }
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_cleanse(key, sizeof(key));
    *output_len = (size_t) (outl + outl2);
    if (*output_len > output_size) {
        return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
    }
    return 0;
}

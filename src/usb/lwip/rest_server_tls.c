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

#include "picokeys.h"
#include "rest_server_tls.h"

#ifdef _MSC_VER
#include <string.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

extern void rest_close_conn(rest_conn_t *conn);
extern void rest_handle_request(rest_conn_t *conn);

static const int tls_ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    0
};

static bool tls_ctx_ready = false;
mbedtls_ssl_config tls_conf;
mbedtls_x509_crt tls_cert;
mbedtls_pk_context tls_key;
tls_credentials_t tls_credentials = {0};

int tls_init_tls_context(const tls_credentials_t *tls_creds) {
    int ret;
    if (tls_ctx_ready) {
        return 0;
    }
    if (tls_creds == NULL || tls_creds->tls_key_pem == NULL || tls_creds->tls_cert_pem == NULL) {
        return -1;
    }

    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_x509_crt_init(&tls_cert);
    mbedtls_pk_init(&tls_key);
    mbedtls_pk_setup(&tls_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

    ret = mbedtls_x509_crt_parse(&tls_cert, (const unsigned char *)tls_creds->tls_cert_pem, tls_creds->tls_cert_pem_len);
    if (ret != 0) {
        return ret;
    }
    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(tls_key), (const unsigned char *)tls_creds->tls_key_pem, tls_creds->tls_key_pem_len);
    if (ret != 0) {
        return ret;
    }
    mbedtls_ecp_check_privkey(&mbedtls_pk_ec(tls_key)->grp, &mbedtls_pk_ec(tls_key)->d);
    mbedtls_ecp_mul(&mbedtls_pk_ec(tls_key)->grp, &mbedtls_pk_ec(tls_key)->Q, &mbedtls_pk_ec(tls_key)->d, &mbedtls_pk_ec(tls_key)->grp.G, random_fill_iterator, NULL);
    mbedtls_ecp_check_pubkey(&mbedtls_pk_ec(tls_key)->grp, &mbedtls_pk_ec(tls_key)->Q);
    ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        return ret;
    }

    mbedtls_ssl_conf_rng(&tls_conf, random_fill_iterator, NULL);
    mbedtls_ssl_conf_min_tls_version(&tls_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&tls_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&tls_conf, tls_ciphersuites);
    ret = mbedtls_ssl_conf_own_cert(&tls_conf, &tls_cert, &tls_key);
    if (ret != 0) {
        return ret;
    }

    tls_ctx_ready = true;
    return 0;
}

static const char *find_header_end(const char *request, size_t request_len) {
    if (request == NULL || request_len < 4) {
        return NULL;
    }
    return strstr(request, "\r\n\r\n");
}

static int parse_content_length(const char *request, size_t request_len, size_t *content_len) {
    const char *line = request;
    const char *header_end = find_header_end(request, request_len);
    if (header_end == NULL) {
        return 0;
    }

    *content_len = 0;
    while (line < header_end) {
        const char *next = strstr(line, "\r\n");
        const char *colon;
        if (next == NULL || next > header_end) {
            break;
        }
        if (next == line) {
            break;
        }
        colon = memchr(line, ':', (size_t)(next - line));
        if (colon != NULL) {
            size_t name_len = (size_t)(colon - line);
            const char *value = colon + 1;
            while (value < next && (*value == ' ' || *value == '\t')) {
                value++;
            }
            if (name_len == 14 && strncasecmp(line, "Content-Length", 14) == 0) {
                char *endptr = NULL;
                unsigned long v = strtoul(value, &endptr, 10);
                if (endptr == value || endptr > next) {
                    return -1;
                }
                *content_len = (size_t)v;
                return 1;
            }
        }
        line = next + 2;
    }
    return 1;
}

static int request_is_complete(const char *request, size_t request_len, size_t *payload_offset, size_t *payload_len) {
    const char *header_end = find_header_end(request, request_len);
    size_t content_len = 0;
    int rc;
    if (header_end == NULL) {
        return 0;
    }
    *payload_offset = (size_t)((header_end + 4) - request);
    rc = parse_content_length(request, request_len, &content_len);
    if (rc < 0) {
        return -1;
    }
    *payload_len = content_len;
    if (request_len < *payload_offset + content_len) {
        return 0;
    }
    return 1;
}

#ifdef ENABLE_EMULATION

#ifdef _MSC_VER
#include "compat/pthread_win32.h"
typedef SOCKET socket_t;
typedef int socklen_t;
#define close closesocket
#include <string.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
typedef int socket_t;
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

socket_t tls_listener_sock = -1;

int emulation_rest_tls_port(void) {
    const char *port_env = getenv("PICO_REST_TLS_PORT");
    long v;
    if (port_env == NULL || *port_env == '\0') {
        return REST_TLS_PORT;
    }
    errno = 0;
    v = strtol(port_env, NULL, 10);
    if (errno != 0 || v < 1 || v > 65535) {
        return REST_TLS_PORT;
    }
    return (int)v;
}

int tls_send_cb(void *ctx, const unsigned char *buf, size_t len) {
    const socket_t fd = (socket_t)(*(const intptr_t *)ctx);
    int r = send(fd, (const char *)buf, (int)len, 0);
    if (r >= 0) {
        return r;
    }
#ifdef _MSC_VER
    {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
    }
#else
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
#endif
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

int tls_recv_cb(void *ctx, unsigned char *buf, size_t len) {
    const socket_t fd = (socket_t)(*(const intptr_t *)ctx);
    int r = recv(fd, (char *)buf, (int)len, 0);
    if (r > 0) {
        return r;
    }
    if (r == 0) {
        return MBEDTLS_ERR_SSL_CONN_EOF;
    }
#ifdef _MSC_VER
    {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
    }
#else
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
#endif
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

#else

#include "lwip/def.h"
#include "lwip/tcp.h"

struct tcp_pcb *tls_listener_pcb = NULL;

int tls_send_cb(void *ctx, const unsigned char *buf, size_t len) {
    rest_conn_t *conn = (rest_conn_t *)ctx;
    size_t chunk;
    u16_t snd_avail;
    err_t err;
    if (conn == NULL || conn->pcb == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if (len == 0) {
        return 0;
    }
    snd_avail = tcp_sndbuf(conn->pcb);
    if (snd_avail == 0) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    chunk = (len > snd_avail) ? snd_avail : len;
    if (chunk > TCP_MSS) {
        chunk = TCP_MSS;
    }
    err = tcp_write(conn->pcb, buf, (uint16_t)chunk, TCP_WRITE_FLAG_COPY);
    if (err == ERR_MEM) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (err != ERR_OK) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    (void)tcp_output(conn->pcb);
    return (int)chunk;
}

int tls_recv_cb(void *ctx, unsigned char *buf, size_t len) {
    rest_conn_t *conn = (rest_conn_t *)ctx;
    size_t n;
    if (conn == NULL || buf == NULL || len == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (conn->rx_cipher_len == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    n = (len < conn->rx_cipher_len) ? len : conn->rx_cipher_len;
    memcpy(buf, conn->rx_cipher, n);
    conn->rx_cipher_len -= n;
    if (conn->rx_cipher_len > 0) {
        memmove(conn->rx_cipher, conn->rx_cipher + n, conn->rx_cipher_len);
    }
    return (int)n;
}

#endif

err_t tls_progress_conn(rest_conn_t *conn) {
    int ret;
    if (conn == NULL
#ifdef ENABLE_EMULATION
        || conn->sock < 0
#else
        || conn->pcb == NULL
#endif
    ) {
        return ERR_OK;
    }

    if (!conn->handshake_done) {
        while ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                return ERR_OK;
            }
            rest_close_conn(conn);
            return ERR_ABRT;
        }
        conn->handshake_done = true;
    }

    while (!conn->request_complete) {
        size_t payload_offset, payload_len;
        ret = mbedtls_ssl_read(&conn->ssl, (unsigned char *)conn->request + conn->request_len, REST_MAX_REQUEST_SIZE - conn->request_len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return ERR_OK;
        }
        if (ret <= 0) {
            rest_close_conn(conn);
            return ERR_ABRT;
        }
        conn->request_len += (size_t)ret;
        conn->request[conn->request_len] = '\0';
        ret = request_is_complete(conn->request, conn->request_len, &payload_offset, &payload_len);
        if (ret < 0) {
            rest_close_conn(conn);
            return ERR_ABRT;
        }
        if (ret == 0) {
            if (conn->request_len >= REST_MAX_REQUEST_SIZE) {
                rest_close_conn(conn);
                return ERR_ABRT;
            }
            continue;
        }
        conn->request_complete = true;
    }

    if (!conn->request_dispatched) {
        conn->request_dispatched = true;
        rest_handle_request(conn);
    }
    return ERR_OK;
}

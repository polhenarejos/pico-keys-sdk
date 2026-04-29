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

#ifndef REST_SERVER_TLS_H
#define REST_SERVER_TLS_H

#ifdef ENABLE_EMULATION
typedef int err_t;
#define ERR_OK 0
#else
#include "lwip/err.h"
#endif

#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "random.h"
#include "rest_server.h"

#define REST_TLS_PORT 443

typedef struct {
    char *tls_key_pem;
    size_t tls_key_pem_len;
    char *tls_cert_pem;
    size_t tls_cert_pem_len;
} tls_credentials_t;

extern tls_credentials_t tls_credentials;

extern mbedtls_ssl_config tls_conf;
extern mbedtls_x509_crt tls_cert;
extern mbedtls_pk_context tls_key;
extern int tls_send_cb(void *ctx, const unsigned char *buf, size_t len);
extern int tls_recv_cb(void *ctx, unsigned char *buf, size_t len);
extern err_t tls_progress_conn(rest_conn_t *conn);
extern int tls_init_tls_context(const tls_credentials_t *tls_credentials);

#ifdef ENABLE_EMULATION
extern int emulation_rest_tls_port(void);
extern void tls_handle_client(int client_fd);
#else
extern struct tcp_pcb *tls_listener_pcb;
#endif

#endif // REST_SERVER_TLS_H

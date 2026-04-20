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


#ifndef REST_SERVER_H
#define REST_SERVER_H

#ifdef ENABLE_EMULATION
typedef int err_t;
#define ERR_OK 0
#define ERR_VAL -6
#define ERR_ABRT -13
#else
#include "lwip/err.h"
#endif
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"
#include <stdbool.h>
#include "mbedtls/ssl.h"
#include "rest.h"

#define REST_PORT 80
#define REST_MAX_CONNS 4
#define REST_MAX_REQUEST_SIZE 1024
#define REST_MAX_METHOD_SIZE 8
#define REST_MAX_CONTENT_TYPE_SIZE 64
#define REST_MAX_PATH_SIZE 192

#define EF_TLS_KEY       0xD500
#define EF_TLS_CERT      0xD501

typedef enum {
    REST_CONN_PLAIN = 0x1,
    REST_CONN_TLS = 0x2,
    REST_CONN_ALL = REST_CONN_PLAIN | REST_CONN_TLS
} rest_conn_type_t;

typedef struct {
    bool in_use;
#ifdef ENABLE_EMULATION
    int sock;
#else
    struct tcp_pcb *pcb;
#endif
    char request[REST_MAX_REQUEST_SIZE + 1];
    size_t request_len;
    rest_conn_type_t conn_type;
    mbedtls_ssl_context ssl;
    unsigned char rx_cipher[REST_MAX_REQUEST_SIZE];
    size_t rx_cipher_len;
    bool handshake_done;
    bool request_complete;
    bool request_dispatched;
} rest_conn_t;

err_t rest_server_init(rest_conn_type_t conn_type);
int lwip_itf_init(void);

extern int rest_server_error(rest_response_t *response, int status_code, const char *message);

#endif

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


#ifndef PICO_KEYS_REST_SERVER_H
#define PICO_KEYS_REST_SERVER_H

#ifdef ENABLE_EMULATION
typedef int err_t;
#define ERR_OK 0
#else
#include "lwip/err.h"
#endif
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

#define REST_MAX_PATH_SIZE 192

typedef enum {
    REST_HTTP_GET = 0,
    REST_HTTP_POST,
    REST_HTTP_PUT,
    REST_HTTP_DELETE
} rest_http_method_t;

typedef struct {
    rest_http_method_t method;
    char path[REST_MAX_PATH_SIZE];
    const char *body;
    size_t body_len;
    const char *content_type;
} rest_request_t;

typedef struct {
    uint16_t status_code;
    const char *content_type;
    char *body; // heap !
    size_t body_len;
    cJSON *json;
} rest_response_t;

typedef int (*rest_route_handler_t)(const rest_request_t *request, rest_response_t *response);

typedef struct {
    rest_http_method_t method;
    const char *path;
    rest_route_handler_t handler;
} rest_route_t;

const rest_route_t *rest_get_routes(size_t *count);

err_t rest_server_init(void);
int lwip_itf_init(void);

#endif

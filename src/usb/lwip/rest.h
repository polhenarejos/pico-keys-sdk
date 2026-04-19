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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "cJSON.h"

#define REST_MAX_REQUEST_SIZE 1024
#define REST_MAX_METHOD_SIZE 8
#define REST_MAX_CONTENT_TYPE_SIZE 64
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


extern int rest_execute_route_handler(const rest_request_t *request, rest_route_handler_t handler, rest_response_t *response);
extern int rest_response_set_error(rest_response_t *response, int status_code, const char *message);
const char *rest_status_text_from_code(uint16_t code);
const char *rest_method_to_string(rest_http_method_t method);
bool rest_content_type_is_json(const char *content_type);

const rest_route_t *rest_get_routes(size_t *count);

#ifdef DEBUG_APDU
extern void rest_debug_dump_payload(const char *tag, const char *buffer, size_t len);
#define REST_DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define rest_debug_dump_payload(tag, buffer, len) do { (void)(tag); (void)(buffer); (void)(len); } while (0)
#define REST_DEBUG_LOG(...) do {} while (0)
#endif

#endif

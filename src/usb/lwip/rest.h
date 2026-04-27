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

#ifndef REST_H
#define REST_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "cJSON.h"
#include "mbedtls/base64.h"

#define REST_MAX_REQUEST_SIZE 1024
#define REST_MAX_METHOD_SIZE 8
#define REST_MAX_CONTENT_TYPE_SIZE 64
#define REST_MAX_PATH_SIZE 192
#define REST_MAX_REQUEST_PARAMS 4

typedef enum {
    REST_HTTP_UNKNOWN = 0x0,
    REST_HTTP_GET = 0x1,
    REST_HTTP_POST = 0x2,
    REST_HTTP_PUT = 0x4,
    REST_HTTP_DELETE = 0x8,
    REST_HTTP_GET_POST = REST_HTTP_GET | REST_HTTP_POST,
    REST_HTTP_GET_PUT = REST_HTTP_GET | REST_HTTP_PUT,
    REST_HTTP_GET_DELETE = REST_HTTP_GET | REST_HTTP_DELETE,
    REST_HTTP_POST_PUT = REST_HTTP_POST | REST_HTTP_PUT,
    REST_HTTP_POST_DELETE = REST_HTTP_POST | REST_HTTP_DELETE,
    REST_HTTP_PUT_DELETE = REST_HTTP_PUT | REST_HTTP_DELETE,
    REST_HTTP_GET_POST_PUT = REST_HTTP_GET | REST_HTTP_POST | REST_HTTP_PUT,
    REST_HTTP_GET_POST_DELETE = REST_HTTP_GET | REST_HTTP_POST | REST_HTTP_DELETE,
    REST_HTTP_GET_PUT_DELETE = REST_HTTP_GET | REST_HTTP_PUT | REST_HTTP_DELETE,
    REST_HTTP_POST_PUT_DELETE = REST_HTTP_POST | REST_HTTP_PUT | REST_HTTP_DELETE,
    REST_HTTP_GET_POST_PUT_DELETE = REST_HTTP_GET | REST_HTTP_POST | REST_HTTP_PUT | REST_HTTP_DELETE
} rest_http_method_t;

typedef enum {
    REST_HEADER_USER_AGENT = 0,
    REST_HEADER_AUTHORIZATION,
    REST_HEADER_CONTENT_TYPE,
    REST_HEADER_CONTENT_LENGTH,
    REST_HEADER_HOST,
    REST_HEADER_LOCATION,
    REST_HEADER_ACCEPT,
    REST_HEADER_X_SESSION_ID,
    REST_HEADER_X_SEQ,
    REST_HEADER_X_SIGNATURE,
    REST_HEADER_TOTAL_COUNT
} rest_header_id_t;

typedef enum {
    REST_PARAM_UNKNOWN = 0,
    REST_PARAM_INTEGER,
    REST_PARAM_STRING
} rest_param_type_t;

typedef struct {
    union {
        int32_t int_param;
        char *str_param;
    } param;
    rest_param_type_t type;
} rest_param_t;

typedef enum {
    REST_ROUTE_NONE         = 0x0,
    REST_ROUTE_REQUIRE_AUTH = 0x1,
    REST_ROUTE_REQUIRE_TLS  = 0x2,
} rest_route_flags_t;

typedef int (*rest_route_param_parser_t)(const char *str, const char *param_str, rest_param_t params_out[REST_MAX_REQUEST_PARAMS]);

typedef enum {
    REST_SESSION_ROLE_NONE = 0,
    REST_SESSION_ROLE_USER = 0x1,
    REST_SESSION_ROLE_ADMIN = 0x2
} rest_session_role_t;

typedef enum {
    REST_REQUEST_CONN_TYPE_PLAIN = 0,
    REST_REQUEST_CONN_TYPE_TLS = 1
} rest_request_conn_type_t;

typedef enum {
    REST_SESSION_UNKNOWN = 0,
    REST_SESSION_AUTH_PENDING = 0x1,
    REST_SESSION_AUTHENTICATED = 0x2,
    REST_SESSION_AUTH_FAILED = 0x3,
    REST_SESSION_EXPIRED = 0x4,
    REST_SESSION_INVALID = 0x5,
    REST_SESSION_TERMINATED = 0x6,
} rest_session_status_t;

typedef struct {
    uint8_t public_key[32];
    uint8_t id[16];
    uint8_t id_str[25];
    time_t last_activity_timestamp;
    time_t created_at;
    uint32_t last_seq;
    rest_session_role_t role;
    rest_session_status_t status;
    uint8_t token[32];
    uint8_t user_id;
} rest_session_t;

typedef struct {
    rest_http_method_t method;
    char path[REST_MAX_PATH_SIZE];
    const char *body;
    size_t body_len;
    const char *content_type;
    char *headers[REST_HEADER_TOTAL_COUNT];
    rest_param_t params[REST_MAX_REQUEST_PARAMS];
    rest_session_t *session;
    rest_request_conn_type_t conn_type;
} rest_request_t;

typedef struct {
    uint16_t status_code;
    const char *content_type;
    char *body; // heap !
    size_t body_len;
    cJSON *json;
    char *headers[REST_HEADER_TOTAL_COUNT];
} rest_response_t;

typedef int (*rest_route_handler_t)(const rest_request_t *request, rest_response_t *response);

typedef struct {
    rest_http_method_t method;
    const char *path;
    rest_route_handler_t handler;
    rest_route_flags_t flags;
    rest_route_param_parser_t param_parser;
    rest_session_role_t role; // Minimum required role to access this route (only relevant if REST_ROUTE_REQUIRE_AUTH flag is set)
} rest_route_t;

extern int rest_execute_route_handler(const rest_request_t *request, rest_route_handler_t handler, rest_response_t *response);
extern int rest_response_set_error(rest_response_t *response, int status_code, const char *message);
const char *rest_status_text_from_code(uint16_t code);
const char *rest_method_to_string(rest_http_method_t method);
bool rest_content_type_is_json(const char *content_type);

const rest_route_t *rest_get_routes(size_t *count);

extern rest_session_t *rest_session_create(const rest_session_role_t role, rest_session_status_t status, const uint8_t public_key[32]);
extern rest_session_t *rest_session_get(const uint8_t *id, size_t id_len);
extern rest_session_t *rest_session_get_by_id_str(const char *id_str);
extern int rest_session_terminate(const uint8_t *id, size_t id_len);
extern int rest_session_update_activity(const uint8_t *id, size_t id_len);
extern int rest_session_set_status(const uint8_t *id, size_t id_len, rest_session_status_t status);
extern int rest_session_set_role(const uint8_t *id, size_t id_len, rest_session_role_t role);
extern int rest_session_cleanup_expired(time_t expiration_time);
extern void rest_session_clear_all(void);
extern int rest_session_derive_key(const rest_session_t *session, uint8_t sk[32]);
extern int rest_session_derive_shared(const rest_session_t *session, uint8_t derived_key[32]);

#ifdef DEBUG_APDU
extern void rest_debug_dump_payload(const char *tag, const char *buffer, size_t len);
#define REST_DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define rest_debug_dump_payload(tag, buffer, len) do { (void)(tag); (void)(buffer); (void)(len); } while (0)
#define REST_DEBUG_LOG(...) do {} while (0)
#endif

#ifdef ENABLE_EMULATION
#define REST_ABSOLUTE_HTTP_URI "http://127.0.0.1"
#define REST_ABSOLUTE_HTTPS_URI "https://127.0.0.1"
#else
#define REST_ABSOLUTE_HTTP_URI "http://192.168.7.1"
#define REST_ABSOLUTE_HTTPS_URI "https://192.168.7.2"
#endif

#endif

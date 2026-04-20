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

#include "rest.h"
#include <strings.h>
#include "random.h"

#define REST_MAX_SESSIONS 4

static rest_session_t rest_sessions[REST_MAX_SESSIONS] = {0};

rest_session_t *rest_session_create(const rest_session_role_t role, rest_session_status_t status) {
    for (int i = 0; i < REST_MAX_SESSIONS; i++) {
        if (rest_sessions[i].status == REST_SESSION_UNKNOWN || rest_sessions[i].status == REST_SESSION_EXPIRED || rest_sessions[i].status == REST_SESSION_TERMINATED) {
            memset(&rest_sessions[i], 0, sizeof(rest_session_t));
            rest_sessions[i].status = status;
            rest_sessions[i].role = role;
            random_fill_buffer(rest_sessions[i].id, sizeof(rest_sessions[i].id));
            rest_sessions[i].created_at = get_rtc_time();
            rest_sessions[i].last_activity_timestamp = rest_sessions[i].created_at;
            return &rest_sessions[i];
        }
    }
    return NULL;
}

rest_session_t *rest_session_get(const uint8_t *id, size_t id_len) {
    if (id == NULL || id_len != 16) {
        return NULL;
    }
    for (int i = 0; i < REST_MAX_SESSIONS; i++) {
        if (rest_sessions[i].status != REST_SESSION_UNKNOWN && rest_sessions[i].status != REST_SESSION_EXPIRED && rest_sessions[i].status != REST_SESSION_TERMINATED) {
            if (memcmp(rest_sessions[i].id, id, sizeof(rest_sessions[i].id)) == 0) {
                return &rest_sessions[i];
            }
        }
    }
    return NULL;
}

int rest_session_terminate(const uint8_t *id, size_t id_len) {
    rest_session_t *session = rest_session_get(id, id_len);
    if (session == NULL) {
        return -1;
    }
    session->status = REST_SESSION_TERMINATED;
    return 0;
}

int rest_session_update_activity(const uint8_t *id, size_t id_len) {
    rest_session_t *session = rest_session_get(id, id_len);
    if (session == NULL) {
        return -1;
    }
    session->last_activity_timestamp = get_rtc_time();
    return 0;
}

int rest_session_set_status(const uint8_t *id, size_t id_len, rest_session_status_t status) {
    rest_session_t *session = rest_session_get(id, id_len);
    if (session == NULL) {
        return -1;
    }
    session->status = status;
    return 0;
}

int rest_session_set_role(const uint8_t *id, size_t id_len, rest_session_role_t role) {
    rest_session_t *session = rest_session_get(id, id_len);
    if (session == NULL) {
        return -1;
    }
    session->role = role;
    return 0;
}

int rest_session_cleanup_expired(time_t expiration_time) {
    int count = 0;
    time_t now = get_rtc_time();
    for (int i = 0; i < REST_MAX_SESSIONS; i++) {
        if (rest_sessions[i].status != REST_SESSION_UNKNOWN && rest_sessions[i].status != REST_SESSION_EXPIRED && rest_sessions[i].status != REST_SESSION_TERMINATED) {
            if (now - rest_sessions[i].last_activity_timestamp > expiration_time) {
                rest_sessions[i].status = REST_SESSION_EXPIRED;
                count++;
            }
        }
    }
    return count;
}

#ifdef DEBUG_APDU
void rest_debug_dump_payload(const char *tag, const char *buffer, size_t len) {
    size_t i;
    if (buffer == NULL) {
        printf("[rest] %s: <null>\n", tag);
        return;
    }

    printf("[rest] %s (%lu bytes): \"", tag, (unsigned long)len);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buffer[i];
        if (c == '\r') {
            printf("\\r");
        }
        else if (c == '\n') {
            printf("\\n");
        }
        else if (c == '\t') {
            printf("\\t");
        }
         else if (c >= 32 && c <= 126) {
            putchar((int)c);
        }
         else {
            printf("\\x%02X", c);
        }
    }
    printf("\"\n");
    if (tag[2] == 's') {
        printf("\n");
    }
}
#endif

int rest_execute_route_handler(const rest_request_t *request, rest_route_handler_t handler, rest_response_t *response) {
    if (request == NULL || handler == NULL || response == NULL) {
        return -1;
    }

    memset(response, 0, sizeof(*response));
    response->status_code = 200;
    response->content_type = "application/json";
    response->body = "{\"ok\":true}";
    response->json = cJSON_CreateObject();
    if (response->json == NULL) {
        return -1;
    }

    if (handler(request, response) != 0) {
        cJSON_Delete(response->json);
        response->json = NULL;
        return -1;
    }
    if (response->content_type == NULL || response->body == NULL) {
        cJSON_Delete(response->json);
        response->json = NULL;
        return -1;
    }
    if (response->status_code == 0 || response->status_code == 200) {
        char *body = cJSON_PrintUnformatted(response->json);
        cJSON_Delete(response->json);
        response->json = NULL;
        if (body == NULL) {
            return -1;
        }
        response->body = body;
    }

    response->status_code = (response->status_code == 0) ? 200 : response->status_code;
    response->body_len = (response->body_len == 0) ? strlen(response->body) : response->body_len;
    return 0;
}

int rest_response_set_error(rest_response_t *response, int status_code, const char *message) {
    char json_template[256];
    int json_len;
    if (response == NULL) {
        return -1;
    }
    json_len = snprintf(json_template, sizeof(json_template), "{\"error\":\"%s\"}", message);
    if (json_len <= 0 || (size_t)json_len >= sizeof(json_template)) {
        return -1;
    }
    response->status_code = (uint16_t)status_code;
    response->content_type = "application/json";
    response->body = strdup(json_template);
    if (response->body == NULL) {
        return -1;
    }
    response->body_len = (size_t)json_len;
    return 0;
}

const char *rest_status_text_from_code(uint16_t code) {
    switch (code) {
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 413:
            return "Payload Too Large";
        case 415:
            return "Unsupported Media Type";
        case 500:
            return "Internal Server Error";
        case 503:
            return "Service Unavailable";
        default:
            return "OK";
    }
}

const char *rest_method_to_string(rest_http_method_t method) {
    switch (method) {
        case REST_HTTP_GET:
            return "GET";
        case REST_HTTP_POST:
            return "POST";
        case REST_HTTP_PUT:
            return "PUT";
        case REST_HTTP_DELETE:
            return "DELETE";
        default:
            return "UNKNOWN";
    }
}

bool rest_content_type_is_json(const char *content_type) {
    if (content_type == NULL) {
        return false;
    }
    return strncasecmp(content_type, "application/json", 16) == 0;
}

__attribute__((weak)) const rest_route_t *rest_get_routes(size_t *count) {
    if (count != NULL) {
        *count = 0;
    }
    return NULL;
}

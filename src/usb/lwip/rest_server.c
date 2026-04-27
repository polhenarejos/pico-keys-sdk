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
#include "rest_server.h"
#include "rest_server_tls.h"
#include "usb.h"
#include "pico_time.h"
#include "serial.h"

#include <ctype.h>
#include <strings.h>
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "crypto_utils.h"

#ifdef ENABLE_EMULATION
#ifndef _MSC_VER
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#else
#include "lwip/tcp.h"
#include "lwip/def.h"
#endif

#define REST_SESSION_TIMEOUT_INACTIVITY_MS (10 * 60 * 1000) // 10 minutes
#define REST_SESSION_TIMEOUT_TOTAL_MS (2 * 60 * 60 * 1000) // 2 hours

#ifndef ENABLE_EMULATION
static struct tcp_pcb *listener_pcb = NULL;
#else
static int listener_sock = -1;
#ifndef _MSC_VER
static pthread_t rest_thread;
#endif
#endif
static rest_conn_t conns[REST_MAX_CONNS];

typedef struct {
    bool pending;
    rest_conn_t *conn;
    rest_route_handler_t handler;
    rest_request_t request;
} rest_core1_job_t;

typedef struct {
    bool ready;
    rest_response_t response;
} rest_core1_result_t;

static rest_core1_job_t rest_core1_job = {0};
static rest_core1_result_t rest_core1_result = {0};

typedef struct {
    rest_header_id_t id;
    const char *name;
} rest_header_descriptor_t;

static const rest_header_descriptor_t rest_http_headers[REST_HEADER_TOTAL_COUNT] = {
    { REST_HEADER_USER_AGENT, "User-Agent" },
    { REST_HEADER_AUTHORIZATION, "Authorization" },
    { REST_HEADER_CONTENT_TYPE, "Content-Type" },
    { REST_HEADER_CONTENT_LENGTH, "Content-Length" },
    { REST_HEADER_HOST, "Host" },
    { REST_HEADER_LOCATION, "Location" },
    { REST_HEADER_ACCEPT, "Accept" },
    { REST_HEADER_X_SESSION_ID, "X-Session-ID" },
    { REST_HEADER_X_SEQ, "X-Seq" },
    { REST_HEADER_X_SIGNATURE, "X-Signature" }
};

static void *rest_core1_thread(void *arg);
static void send_response(rest_conn_t *conn, int status_code, const char *status_text, const char *content_type, const char *body, size_t body_len, char *headers[REST_HEADER_TOTAL_COUNT]);
void rest_close_conn(rest_conn_t *conn);

static int rest_start_core1_job(rest_conn_t *conn, const rest_request_t *request, rest_route_handler_t handler) {
    if (request == NULL || handler == NULL || rest_core1_job.pending) {
        return -1;
    }

    memset(&rest_core1_result, 0, sizeof(rest_core1_result));

    rest_core1_job.pending = true;
    rest_core1_job.conn = conn;
    rest_core1_job.handler = handler;

    card_start(ITF_LWIP, rest_core1_thread);
    usb_send_event(EV_CMD_AVAILABLE);
    return 0;
}

static void *rest_core1_thread(void *arg) {
    (void)arg;
    card_init_core1();
    while (1) {
        uint32_t m = 0;
        uint32_t flag;
        queue_remove_blocking(&usb_to_card_q, &m);
        flag = m + 1;
        if (m != EV_CMD_AVAILABLE) {
            queue_add_blocking(&card_to_usb_q, &flag);
        }
        if (m == EV_EXIT) {
            break;
        }
        if (m == EV_CMD_AVAILABLE) {
            rest_core1_result.ready = false;
            memset(&rest_core1_result.response, 0, sizeof(rest_core1_result.response));
            if (!rest_core1_job.pending || rest_core1_job.handler == NULL || rest_execute_route_handler(&rest_core1_job.request, rest_core1_job.handler, &rest_core1_result.response) != 0) {
                rest_server_error(&rest_core1_result.response, 500, "internal_error");
            }
            rest_core1_result.ready = true;
            flag = EV_EXEC_FINISHED;
            queue_add_blocking(&card_to_usb_q, &flag);
        }
#ifdef ESP_PLATFORM
        vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
    return NULL;
}

static void send_json(rest_conn_t *conn, int status_code, const char *status_text, const char *json_body) {
    send_response(conn, status_code, status_text, "application/json", json_body, strlen(json_body), NULL);
}

static void send_json_error(rest_conn_t *conn, int status_code, const char *error_message) {
    char json[256];
    int json_len = snprintf(json, sizeof(json), "{\"error\":\"%s\"}", error_message);
    if (json_len <= 0 || (size_t)json_len >= sizeof(json)) {
        rest_close_conn(conn);
        return;
    }
    send_json(conn, status_code, rest_status_text_from_code(status_code), json);
}

void rest_task(void) {
    int status;
    rest_conn_t *conn;
    if (!rest_core1_job.pending) {
        return;
    }
    status = card_status(ITF_LWIP);
    if (status != PICOKEYS_OK) {
        return;
    }

    conn = rest_core1_job.conn;
    if (conn == NULL) {
        return;
    }
    rest_response_t *response = &rest_core1_result.response;
    if (response == NULL) {
        return;
    }
    if (conn != NULL) {
        if (rest_core1_result.ready && response->body != NULL && response->content_type != NULL) {
            uint16_t code = response->status_code == 0 ? 200 : response->status_code;
            send_response(conn, code, rest_status_text_from_code(code), response->content_type, response->body, response->body_len, response->headers);
        }
        else {
            send_json_error(conn, 500, "internal_error");
        }
    }

    if (response->body != NULL) {
        free(response->body);
    }
    memset(&rest_core1_result, 0, sizeof(rest_core1_result));
    memset(&rest_core1_job, 0, sizeof(rest_core1_job));
}

static rest_conn_t *alloc_conn(
#ifdef ENABLE_EMULATION
    int sock
#else
    struct tcp_pcb *pcb
#endif
) {
    size_t i;
    uint16_t local_port = REST_PORT;
    for (i = 0; i < REST_MAX_CONNS; i++) {
        if (!conns[i].in_use) {
            memset(&conns[i], 0, sizeof(conns[i]));
            conns[i].in_use = true;
#ifdef ENABLE_EMULATION
            conns[i].sock = sock;
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            if (getsockname(sock, (struct sockaddr *)&addr, &len) == 0) {
                local_port = ntohs(addr.sin_port);
            }
#else
            conns[i].pcb = pcb;
            local_port = pcb->local_port;
#endif
            conns[i].conn_type = (local_port == REST_TLS_PORT) ? REST_CONN_TLS : REST_CONN_PLAIN;
            return &conns[i];
        }
    }
    return NULL;
}

static void clear_conn(rest_conn_t *conn) {
    if (conn == NULL) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
#ifdef ENABLE_EMULATION
    conn->sock = -1;
#endif
}

void rest_close_conn(rest_conn_t *conn) {
#ifdef ENABLE_EMULATION
    if (conn == NULL) {
        return;
    }
    if (conn->conn_type == REST_CONN_TLS) {
        mbedtls_ssl_free(&conn->ssl);
    }
    if (conn->sock >= 0) {
#ifndef _MSC_VER
        (void)close(conn->sock);
#endif
    }
    clear_conn(conn);
#else
    err_t err;
    if (conn == NULL || conn->pcb == NULL) {
        clear_conn(conn);
        return;
    }
    err = tcp_close(conn->pcb);
    if (err == ERR_MEM) {
        (void)tcp_output(conn->pcb);
        return;
    }
    if (err != ERR_OK) {
        tcp_abort(conn->pcb);
    }
    tcp_arg(conn->pcb, NULL);
    tcp_recv(conn->pcb, NULL);
    tcp_sent(conn->pcb, NULL);
    tcp_poll(conn->pcb, NULL, 0);
    tcp_err(conn->pcb, NULL);
    if (conn->conn_type == REST_CONN_TLS) {
        mbedtls_ssl_free(&conn->ssl);
    }
    clear_conn(conn);
#endif
}

static void send_response(rest_conn_t *conn, int status_code, const char *status_text, const char *content_type, const char *body, size_t body_len, char *headers[REST_HEADER_TOTAL_COUNT]) {
    char headers_buf[256];
    int header_len;
#ifdef ENABLE_EMULATION
    size_t sent_total = 0;
#else
    err_t err;
    int retries;
#endif
    if (
        conn == NULL
#ifdef ENABLE_EMULATION
        || conn->sock < 0
#else
        || conn->pcb == NULL
#endif
    ) {
        return;
    }

    REST_DEBUG_LOG(
        "[rest %s] response: status=%d content_type=%s body_len=%lu\n",
        (conn->conn_type == REST_CONN_TLS) ? "TLS" : "PLAIN",
        status_code,
        (content_type != NULL) ? content_type : "(null)",
        (unsigned long)body_len
    );
    rest_debug_dump_payload("response-body", body, body_len);

    char *p = headers_buf;
    header_len = snprintf(p, sizeof(headers_buf),
                          "HTTP/1.0 %d %s\r\n"
                          "Content-Type: %s\r\n"
                          "Content-Length: %lu\r\n"
                          "Connection: close\r\n",
                          status_code, status_text, content_type, (unsigned long)body_len);
    if (headers) {
        for (int i = 0; i < REST_HEADER_TOTAL_COUNT; i++) {
            if (headers[i] != NULL) {
                int n = snprintf(p + header_len, sizeof(headers_buf) - (size_t)header_len, "%s: %s\r\n", rest_http_headers[i].name, headers[i]);
                free(headers[i]);
                headers[i] = NULL;
                if (n <= 0 || header_len + n >= (int)sizeof(headers_buf)) {
                    rest_close_conn(conn);
                    return;
                }
                header_len += n;
            }
        }
    }
    if (header_len + 2 >= (int)sizeof(headers_buf)) {
        rest_close_conn(conn);
        return;
    }
    memcpy(p + header_len, "\r\n", 2);
    header_len += 2;
    if (header_len <= 0 || (size_t)header_len >= sizeof(headers_buf)) {
        rest_close_conn(conn);
        return;
    }

    if (conn->conn_type == REST_CONN_TLS) {
        size_t written = 0;
        int ret;
        int want_retries = 0;

        while (written < (size_t)header_len) {
            ret = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)headers_buf + written, (size_t)header_len - written);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (++want_retries > 2048) {
                    rest_close_conn(conn);
                    return;
                }
                continue;
            }
            if (ret <= 0) {
                rest_close_conn(conn);
                return;
            }
            want_retries = 0;
            written += (size_t)ret;
        }

        written = 0;
        while (written < body_len) {
            ret = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)body + written, body_len - written);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (++want_retries > 2048) {
                    rest_close_conn(conn);
                    return;
                }
                continue;
            }
            if (ret <= 0) {
                rest_close_conn(conn);
                return;
            }
            want_retries = 0;
            written += (size_t)ret;
        }

        (void)mbedtls_ssl_close_notify(&conn->ssl);
        rest_close_conn(conn);
        return;
    }
#ifdef ENABLE_EMULATION
    while (sent_total < (size_t)header_len) {
#ifndef _MSC_VER
        ssize_t n = send(conn->sock, headers_buf + sent_total, (size_t)header_len - sent_total, 0);
#else
        int n = -1;
#endif
        if (n <= 0) {
            rest_close_conn(conn);
            return;
        }
        sent_total += (size_t)n;
    }
    sent_total = 0;
    while (sent_total < body_len) {
#ifndef _MSC_VER
        ssize_t n = send(conn->sock, body + sent_total, body_len - sent_total, 0);
#else
        int n = -1;
#endif
        if (n <= 0) {
            rest_close_conn(conn);
            return;
        }
        sent_total += (size_t)n;
    }
#else
    /* lwIP guidance: check sndbuf for each tcp_write() call. */
    retries = 0;
    while (tcp_sndbuf(conn->pcb) < (u16_t)header_len) {
        if (retries >= 16) {
            rest_close_conn(conn);
            return;
        }
        (void)tcp_output(conn->pcb);
        retries++;
    }
    retries = 0;
    while (true) {
        err = tcp_write(conn->pcb, headers_buf, (uint16_t)header_len, TCP_WRITE_FLAG_COPY | (body_len > 0 ? TCP_WRITE_FLAG_MORE : 0));
        if (err == ERR_OK) {
            break;
        }
        if (err != ERR_MEM || retries >= 16) {
            rest_close_conn(conn);
            return;
        }
        (void)tcp_output(conn->pcb);
        retries++;
    }

    if (body_len > 0) {
        retries = 0;
        while (tcp_sndbuf(conn->pcb) < (u16_t)body_len) {
            if (retries >= 16) {
                rest_close_conn(conn);
                return;
            }
            (void)tcp_output(conn->pcb);
            retries++;
        }
        retries = 0;
        while (true) {
            err = tcp_write(conn->pcb, body, (uint16_t)body_len, TCP_WRITE_FLAG_COPY);
            if (err == ERR_OK) {
                break;
            }
            if (err != ERR_MEM || retries >= 16) {
                rest_close_conn(conn);
                return;
            }
            (void)tcp_output(conn->pcb);
            retries++;
        }
    }
    (void)tcp_output(conn->pcb);
#endif
#ifndef ENABLE_EMULATION
    if (conn->conn_type == REST_CONN_PLAIN) {
        return;
    }
#endif
    rest_close_conn(conn);
}

static void trim_ascii_ws_bounds(const char **start, const char **end) {
    while (*start < *end && isspace((unsigned char)**start)) {
        (*start)++;
    }
    while (*end > *start && isspace((unsigned char)*((*end) - 1))) {
        (*end)--;
    }
}

static bool split_header_line_span(const char *line, const char *line_end,
                                   const char **name_start, const char **name_end,
                                   const char **value_start, const char **value_end) {
    const char *colon;
    if (line == NULL || line_end == NULL || name_start == NULL || name_end == NULL || value_start == NULL || value_end == NULL || line >= line_end) {
        return false;
    }
    colon = memchr(line, ':', (size_t)(line_end - line));
    if (colon == NULL) {
        return false;
    }

    *name_start = line;
    *name_end = colon;
    *value_start = colon + 1;
    *value_end = line_end;
    trim_ascii_ws_bounds(name_start, name_end);
    trim_ascii_ws_bounds(value_start, value_end);
    return true;
}

static void trim_ascii_ws_cstr(char **s) {
    char *end;
    if (s == NULL || *s == NULL) {
        return;
    }
    while (**s != '\0' && isspace((unsigned char)**s)) {
        (*s)++;
    }
    end = *s + strlen(*s);
    while (end > *s && isspace((unsigned char)*(end - 1))) {
        *(--end) = '\0';
    }
}

static bool split_header_line(char *line, char **name, char **value) {
    char *colon;
    if (line == NULL || name == NULL || value == NULL) {
        return false;
    }
    colon = strchr(line, ':');
    if (colon == NULL) {
        return false;
    }
    *colon = '\0';
    *name = line;
    *value = colon + 1;
    trim_ascii_ws_cstr(name);
    trim_ascii_ws_cstr(value);
    return true;
}

static int parse_content_length(const char *request, const char *header_end, unsigned long *content_length) {
    const char *scan;
    const char *first_line_end;
    if (request == NULL || header_end == NULL || content_length == NULL) {
        return -1;
    }

    *content_length = 0;
    first_line_end = strstr(request, "\r\n");
    if (first_line_end == NULL || first_line_end > header_end) {
        return -1;
    }

    scan = first_line_end + 2;
    while (scan < header_end) {
        const char *next = strstr(scan, "\r\n");
        if (next == NULL || next > header_end) {
            return -1;
        }
        if (next == scan) {
            break;
        }

        const char *name_start, *name_end, *value_start, *value_end;
        char value_buf[32];
        size_t value_len;
        char *endptr;

        if (!split_header_line_span(scan, next, &name_start, &name_end, &value_start, &value_end)) {
            scan = next + 2;
            continue;
        }

        if ((size_t)(name_end - name_start) == strlen("Content-Length") &&
            strncasecmp(name_start, "Content-Length", strlen("Content-Length")) == 0) {
            value_len = (size_t)(value_end - value_start);
            if (value_len == 0 || value_len >= sizeof(value_buf)) {
                return -1;
            }
            memcpy(value_buf, value_start, value_len);
            value_buf[value_len] = '\0';
            *content_length = strtoul(value_buf, &endptr, 10);
            if (endptr == value_buf || *endptr != '\0' || *content_length > REST_MAX_REQUEST_SIZE) {
                return -1;
            }
        }
        scan = next + 2;
    }

    return 0;
}

static int parse_request(rest_conn_t *conn, rest_request_t *request) {
    char *header_end, *line_end, *cursor;
    size_t headers_size;
    unsigned long content_length;
    char method_str[REST_MAX_METHOD_SIZE] = {0};
    memset(request, 0, sizeof(rest_request_t));
    conn->request[conn->request_len] = '\0';

    if (!conn->request_headers_parsed) {
        header_end = strstr(conn->request, "\r\n\r\n");
        if (header_end == NULL) {
            return 0;
        }
        headers_size = (size_t)(header_end - conn->request) + 4;
        if (parse_content_length(conn->request, header_end, &content_length) != 0) {
            return -1;
        }
        conn->request_headers_size = headers_size;
        conn->request_content_length = (size_t)content_length;
        conn->request_headers_parsed = true;
    }

    if (conn->request_len < conn->request_headers_size + conn->request_content_length) {
        return 0;
    }

    headers_size = conn->request_headers_size;
    content_length = conn->request_content_length;
    header_end = conn->request + headers_size - 4;

    line_end = strstr(conn->request, "\r\n");
    if (line_end == NULL || line_end > header_end) {
        return -1;
    }
    *line_end = '\0';
    if (sscanf(conn->request, "%7s %191s", method_str, request->path) != 2) {
        return -1;
    }
    if (strcmp(method_str, "GET") == 0) {
        request->method = REST_HTTP_GET;
    }
    else if (strcmp(method_str, "POST") == 0) {
        request->method = REST_HTTP_POST;
    }
    else if (strcmp(method_str, "PUT") == 0) {
        request->method = REST_HTTP_PUT;
    }
    else if (strcmp(method_str, "DELETE") == 0) {
        request->method = REST_HTTP_DELETE;
    }
    else {
        return -1;
    }

    cursor = line_end + 2;
    while (cursor < header_end) {
        char *next = strstr(cursor, "\r\n"), *name, *value;
        if (next == NULL || next > header_end) {
            return -1;
        }
        if (next == cursor) {
            break;
        }
        *next = '\0';
        if (split_header_line(cursor, &name, &value)) {
            if (strcasecmp(name, "Content-Type") == 0) {
                request->content_type = value;
            }
            else {
                for (int i = 0; i < REST_HEADER_TOTAL_COUNT; i++) {
                    if (strcasecmp(name, rest_http_headers[i].name) == 0) {
                        request->headers[rest_http_headers[i].id] = value;
                        break;
                    }
                }
            }
        }
        cursor = next + 2;
    }
    request->body = conn->request + headers_size;
    request->body_len = (size_t)content_length;
    request->conn_type = (rest_request_conn_type_t)conn->conn_type;
    return 1;
}

static uint32_t rest_request_get_seq(const rest_request_t *request) {
    if (request == NULL || request->headers[REST_HEADER_X_SEQ] == NULL) {
        return 0;
    }
    return (uint32_t)strtoul(request->headers[REST_HEADER_X_SEQ], NULL, 10);
}

static int rest_verify_request_signature(const rest_request_t *request, const rest_session_t *session) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char hmac[32], hmac_x[32];
    size_t olen = 0;
    if (md_info == NULL) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (base64url_decode(hmac_x, sizeof(hmac_x), &olen, (const unsigned char *)request->headers[REST_HEADER_X_SIGNATURE], strlen(request->headers[REST_HEADER_X_SIGNATURE])) != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
        mbedtls_md_free(&ctx);
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    const char *body_empty = "{}";
    const char *body = request->body_len > 0 ? request->body : body_empty;
    const char *method_str = rest_method_to_string(request->method);
    size_t body_len = request->body_len > 0 ? request->body_len : strlen((const char *)body_empty);
    uint8_t derived_key[32];
    if (rest_session_derive_shared(session, derived_key) != 0) {
        mbedtls_md_free(&ctx);
        return PICOKEYS_EXEC_ERROR;
    }
    uint32_t seq = htonl(rest_request_get_seq(request));
    if (mbedtls_md_hmac_starts(&ctx, (const unsigned char *)derived_key, sizeof(derived_key)) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)session->id, sizeof(session->id)) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)method_str, strlen(method_str)) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)request->path, strlen(request->path)) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)&seq, sizeof(uint32_t)) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)body, body_len) != 0)
    {
        mbedtls_platform_zeroize(derived_key, sizeof(derived_key));
        mbedtls_md_free(&ctx);
        return PICOKEYS_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(derived_key, sizeof(derived_key));
    if (mbedtls_md_hmac_finish(&ctx, hmac) != 0) {
        mbedtls_platform_zeroize(derived_key, sizeof(derived_key));
        mbedtls_md_free(&ctx);
        return PICOKEYS_EXEC_ERROR;
    }
    mbedtls_md_free(&ctx);
    if (ct_memcmp(hmac, hmac_x, sizeof(hmac)) != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

void rest_handle_request(rest_conn_t *conn) {
    rest_request_t *request = &rest_core1_job.request;
    const rest_route_t *routes;
    size_t route_count = 0, i;
    bool path_exists_for_other_method = false;
    int parsed;

    if (rest_core1_job.pending) {
        send_json_error(conn, 503, "busy");
        return;
    }

    memset(&rest_core1_job, 0, sizeof(rest_core1_job));
    parsed = parse_request(conn, request);
    if (parsed <= 0) {
        if (parsed < 0) {
            send_json_error(conn, 400, "bad_request");
        }
        return;
    }

    REST_DEBUG_LOG(
        "[rest %s] request: %s %s\n",
        (conn->conn_type == REST_CONN_TLS) ? "TLS" : "PLAIN",
        rest_method_to_string(request->method),
        request->path
    );
    rest_debug_dump_payload("request-body", request->body, request->body_len);

    if (request->method == REST_HTTP_POST || request->method == REST_HTTP_PUT) {
        if (!rest_content_type_is_json(request->content_type)) {
            send_json_error(conn, 415, "content_type_must_be_application_json");
            return;
        }
    }
    routes = rest_get_routes(&route_count);
    for (i = 0; i < route_count; i++) {
        if (routes[i].path == NULL || routes[i].handler == NULL) {
            continue;
        }
        if (routes[i].param_parser != NULL) {
            int result = routes[i].param_parser(request->path, routes[i].path, request->params);
            if (result < 0) {
                continue;
            }
        }
        else if (strcmp(routes[i].path, request->path) != 0) {
            continue;
        }
        if (!(routes[i].method & request->method)) {
            path_exists_for_other_method = true;
            continue;
        }
        if (routes[i].flags & REST_ROUTE_REQUIRE_AUTH) {
            if (!request->headers[REST_HEADER_X_SESSION_ID] || strlen(request->headers[REST_HEADER_X_SESSION_ID]) == 0 ||!request->headers[REST_HEADER_X_SIGNATURE] || strlen(request->headers[REST_HEADER_X_SIGNATURE]) == 0 || !request->headers[REST_HEADER_X_SEQ] || strlen(request->headers[REST_HEADER_X_SEQ]) == 0) {
                send_json_error(conn, 401, "authentication_required");
                return;
            }
            rest_session_t *session = rest_session_get_by_id_str(request->headers[REST_HEADER_X_SESSION_ID]);
            if (!session) {
                send_json_error(conn, 401, "authentication_required");
                return;
            }
            if (session->status != REST_SESSION_AUTHENTICATED) {
                send_json_error(conn, 401, "authentication_required");
                return;
            }
            if (session->role < routes[i].role) {
                send_json_error(conn, 403, "insufficient_privileges");
                return;
            }
            if (session->last_activity_timestamp + REST_SESSION_TIMEOUT_INACTIVITY_MS < board_millis() || session->created_at + REST_SESSION_TIMEOUT_TOTAL_MS < board_millis()) {
                session->status = REST_SESSION_EXPIRED;
                send_json_error(conn, 401, "session_expired");
                return;
            }
            if (rest_request_get_seq(request) < session->last_seq) {
                send_json_error(conn, 401, "invalid_seq");
                return;
            }
            if (rest_verify_request_signature(request, session) != PICOKEYS_OK) {
                send_json_error(conn, 401, "invalid_signature");
                return;
            }
            request->session = session;
        }
        if (rest_start_core1_job(conn, request, routes[i].handler) != 0) {
            send_json_error(conn, 500, "internal_error");
        }
        return;
    }

    if (path_exists_for_other_method) {
        send_json_error(conn, 405, "method_not_allowed");
    }
    else {
        send_json_error(conn, 404, "not_found");
    }
}

void rest_check_and_load_credentials(void) {
    file_t *ef = file_new(EF_TLS_KEY);
    if (!file_has_data(ef)) {
        mbedtls_ecdsa_context ecdsa;
        size_t olen = 0;
        uint8_t pkey[MBEDTLS_ECP_MAX_BYTES];
        while (olen != 32) {
            mbedtls_ecdsa_init(&ecdsa);
            mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_SECP256R1;
            mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_fill_iterator, NULL);
            mbedtls_ecp_write_key_ext(&ecdsa, &olen, pkey, sizeof(pkey));
            mbedtls_ecdsa_free(&ecdsa);
        }
        file_put_data(ef, pkey, olen);
        mbedtls_platform_zeroize(pkey, sizeof(pkey));
        printf("TLS key generated and stored, length: %u bytes\n", (unsigned)olen);
    }
    tls_credentials.tls_key_pem = (char *)file_get_data(ef);
    tls_credentials.tls_key_pem_len = file_get_size(ef);
    printf("TLS key loaded, length: %u bytes\n", (unsigned)tls_credentials.tls_key_pem_len);
    ef = file_new(EF_TLS_CERT);
    if (!file_has_data(ef)) {
        mbedtls_x509write_cert crt;
        mbedtls_pk_context key;
        unsigned char cert_pem[2048] = {0};
        int ret = 0;
        file_t *ef_key = file_search(EF_TLS_KEY);
        const uint8_t *file = file_get_data(ef_key);
        size_t file_len = file_get_size(ef_key);

        mbedtls_x509write_crt_init(&crt);
        mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_pk_init(&key);
        ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0) goto out;
        mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), file, file_len);
        mbedtls_ecp_check_privkey(&mbedtls_pk_ec(key)->grp, &mbedtls_pk_ec(key)->d);
        mbedtls_ecp_mul(&mbedtls_pk_ec(key)->grp, &mbedtls_pk_ec(key)->Q, &mbedtls_pk_ec(key)->d, &mbedtls_pk_ec(key)->grp.G, random_fill_iterator, NULL);
        mbedtls_ecp_check_pubkey(&mbedtls_pk_ec(key)->grp, &mbedtls_pk_ec(key)->Q);

        mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&crt, &key);
        mbedtls_x509write_crt_set_issuer_key(&crt, &key); // self-signed

        mbedtls_x509write_crt_set_subject_key_identifier(&crt);
        mbedtls_x509write_crt_set_authority_key_identifier(&crt);
        ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=pico-novus");
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=pico-novus");
        if (ret != 0) goto out;
        uint8_t serial[16];
        random_fill_buffer(serial, sizeof(serial));
        mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_validity(&crt, "20260101000000", "20360101000000");
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, 0);
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
        if (ret != 0) goto out;

        ret = mbedtls_x509write_crt_pem(&crt, cert_pem, sizeof(cert_pem), random_fill_iterator, NULL);
        if (ret == 0) {
            file_put_data(ef, cert_pem, strlen((char *)cert_pem) + 1);
            printf("TLS certificate generated and stored, length: %u bytes\n", (unsigned)strlen((char *)cert_pem));
        }
out:
        mbedtls_x509write_crt_free(&crt);
        mbedtls_platform_zeroize(cert_pem, sizeof(cert_pem));
        mbedtls_pk_free(&key);
    }
    tls_credentials.tls_cert_pem = (char *)file_get_data(ef);
    tls_credentials.tls_cert_pem_len = file_get_size(ef);
    printf("TLS certificate loaded, length: %u bytes\n", (unsigned)tls_credentials.tls_cert_pem_len);
    flash_commit();
}

#ifndef ENABLE_EMULATION
static err_t rest_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    rest_conn_t *conn = (rest_conn_t *)arg;
    size_t *len = NULL;
    unsigned char *buffer = NULL;

    LWIP_UNUSED_ARG(pcb);
    if (err != ERR_OK) {
        if (p != NULL) {
            pbuf_free(p);
        }
        rest_close_conn(conn);
        return err;
    }
    if (p == NULL) {
        rest_close_conn(conn);
        return ERR_OK;
    }
    if (conn == NULL) {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }
    if (conn->conn_type == REST_CONN_TLS) {
        len = &conn->rx_cipher_len;
        buffer = conn->rx_cipher;
    }
    else {
        len = &conn->request_len;
        buffer = (unsigned char *)conn->request;
    }
    if (*len + p->tot_len > REST_MAX_REQUEST_SIZE) {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
        if (conn->conn_type == REST_CONN_TLS) {
            rest_close_conn(conn);
            return ERR_ABRT;
        }
        send_json_error(conn, 413, "payload_too_large");
        return ERR_OK;
    }
    pbuf_copy_partial(p, buffer + *len, p->tot_len, 0);
    *len += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    if (conn->conn_type == REST_CONN_TLS) {
        return tls_progress_conn(conn);
    }
    rest_handle_request(conn);
    return ERR_OK;
}

static err_t rest_poll(void *arg, struct tcp_pcb *pcb) {
    rest_conn_t *conn = (rest_conn_t *)arg;
    LWIP_UNUSED_ARG(pcb);
    if (rest_core1_job.pending && rest_core1_job.conn == conn) {
        return ERR_OK;
    }
    if (conn->conn_type == REST_CONN_TLS) {
        return tls_progress_conn(conn);
    }
    if (conn->request_len > 0) {
        if (!conn->request_headers_parsed) {
            return ERR_OK;
        }
        if (conn->request_len < conn->request_headers_size + conn->request_content_length) {
            return ERR_OK;
        }
    }
    return ERR_OK;
}

static err_t rest_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    rest_conn_t *conn = (rest_conn_t *)arg;
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(len);
    if (conn->conn_type == REST_CONN_TLS) {
        return tls_progress_conn(conn);
    }
    return ERR_OK;
}

static void rest_err(void *arg, err_t err) {
    rest_conn_t *conn = (rest_conn_t *)arg;
    LWIP_UNUSED_ARG(err);
    if (conn == NULL) {
        return;
    }
    rest_close_conn(conn);
}

static err_t rest_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    rest_conn_t *conn;
    LWIP_UNUSED_ARG(arg);
    if (err != ERR_OK || newpcb == NULL) {
        if (newpcb != NULL) {
            tcp_abort(newpcb);
        }
        return ERR_ABRT;
    }
    conn = alloc_conn(newpcb);
    if (conn == NULL) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    if (conn->conn_type == REST_CONN_TLS) {
        mbedtls_ssl_init(&conn->ssl);
        if (mbedtls_ssl_setup(&conn->ssl, &tls_conf) != 0) {
            rest_close_conn(conn);
            return ERR_ABRT;
        }
        mbedtls_ssl_set_bio(&conn->ssl, conn, tls_send_cb, tls_recv_cb, NULL);
        tcp_nagle_disable(newpcb);
    }
    tcp_arg(newpcb, conn);
    tcp_recv(newpcb, rest_recv);
    tcp_sent(newpcb, rest_sent);
    tcp_poll(newpcb, rest_poll, 8);
    tcp_err(newpcb, rest_err);
    return ERR_OK;
}

static err_t rest_server_init_conn(struct tcp_pcb **listener_pcb, uint16_t port, rest_conn_type_t conn_type, const tls_credentials_t *tls_credentials) {
    if (*listener_pcb != NULL) {
        return ERR_OK;
    }
    if (conn_type & REST_CONN_TLS) {
        if (tls_credentials == NULL || tls_credentials->tls_key_pem == NULL || tls_credentials->tls_cert_pem == NULL) {
            return ERR_VAL;
        }
        if (tls_init_tls_context(tls_credentials) != 0) {
            return ERR_VAL;
        }
    }

    *listener_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (*listener_pcb == NULL) {
        return ERR_MEM;
    }
    err_t err = tcp_bind(*listener_pcb, IP_ANY_TYPE, port);
    if (err != ERR_OK) {
        tcp_abort(*listener_pcb);
        *listener_pcb = NULL;
        return err;
    }
    *listener_pcb = tcp_listen_with_backlog(*listener_pcb, REST_MAX_CONNS);
    if (*listener_pcb == NULL) {
        return ERR_MEM;
    }
    tcp_accept(*listener_pcb, rest_accept);
    return ERR_OK;
}

err_t rest_server_init(rest_conn_type_t conn_type) {
    err_t err;
    if (conn_type & REST_CONN_PLAIN) {
        err = rest_server_init_conn(&listener_pcb, REST_PORT, REST_CONN_PLAIN, NULL);
        if (err != ERR_OK) {
            return err;
        }
    }
    if (conn_type & REST_CONN_TLS) {
        rest_check_and_load_credentials();
        err = rest_server_init_conn(&tls_listener_pcb, REST_TLS_PORT, REST_CONN_TLS, &tls_credentials);
        if (err != ERR_OK) {
            return err;
        }
    }
    return ERR_OK;
}
#else
static int emulation_rest_port(void) {
#ifndef _MSC_VER
    const char *port_env = getenv("PICO_REST_PORT");
    long v;
    if (port_env == NULL || *port_env == '\0') {
        return REST_PORT;
    }
    errno = 0;
    v = strtol(port_env, NULL, 10);
    if (errno != 0 || v < 1 || v > 65535) {
        return REST_PORT;
    }
    return (int)v;
#else
    return REST_PORT;
#endif
}

#ifndef _MSC_VER
static void *rest_emulation_thread(void *arg) {
    struct sockaddr_in peer;
    int listen_fd = (int)(intptr_t)arg;

    while (true) {
        socklen_t peer_len = sizeof(peer);
        int accepted = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        rest_conn_t *conn;
        if (accepted < 0) {
            continue;
        }
        conn = alloc_conn(accepted);
        if (conn == NULL) {
            (void)close(accepted);
            continue;
        }
        if (conn->conn_type == REST_CONN_TLS) {
            mbedtls_ssl_init(&conn->ssl);
            if (mbedtls_ssl_setup(&conn->ssl, &tls_conf) != 0) {
                rest_close_conn(conn);
                continue;
            }
            mbedtls_ssl_set_bio(&conn->ssl, &conn->sock, tls_send_cb, tls_recv_cb, NULL);
        }
        while (conn->in_use) {
            if (conn->conn_type == REST_CONN_TLS) {
                /* TLS on emulation reads directly from socket through mbedtls BIO callbacks. */
                if (tls_progress_conn(conn) != ERR_OK) {
                    rest_close_conn(conn);
                    break;
                }
            }
            else {
                ssize_t n = recv(conn->sock, conn->request + conn->request_len, REST_MAX_REQUEST_SIZE - conn->request_len, 0);
                if (n <= 0) {
                    rest_close_conn(conn);
                    break;
                }
                conn->request_len += (size_t)n;
                if (conn->request_len > REST_MAX_REQUEST_SIZE) {
                    send_json_error(conn, 413, "payload_too_large");
                    break;
                }
                rest_handle_request(conn);
            }
        }
    }
    return NULL;
}
#endif

static err_t rest_server_init_conn(int *listener_sock, int port, rest_conn_type_t conn_type, const tls_credentials_t *tls_credentials) {
#ifndef _MSC_VER
    struct sockaddr_in addr;
    int one = 1;

    if (*listener_sock >= 0) {
        return ERR_OK;
    }
    if (conn_type & REST_CONN_TLS) {
        if (tls_credentials == NULL || tls_credentials->tls_key_pem == NULL || tls_credentials->tls_cert_pem == NULL) {
            return ERR_VAL;
        }
        if (tls_init_tls_context(tls_credentials) != 0) {
            return ERR_VAL;
        }
    }
    *listener_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*listener_sock < 0) {
        return -1;
    }
    if (setsockopt(*listener_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        (void)close(*listener_sock);
        *listener_sock = -1;
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(*listener_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        (void)close(*listener_sock);
        *listener_sock = -1;
        return -1;
    }
    if (listen(*listener_sock, REST_MAX_CONNS) != 0) {
        (void)close(*listener_sock);
        *listener_sock = -1;
        return -1;
    }
    if (pthread_create(&rest_thread, NULL, rest_emulation_thread, (void *)(intptr_t)(*listener_sock)) != 0) {
        (void)close(*listener_sock);
        *listener_sock = -1;
        return -1;
    }
    (void)pthread_detach(rest_thread);
    return ERR_OK;
#else
    return -1;
#endif
}

err_t rest_server_init(rest_conn_type_t conn_type) {

    if (conn_type & REST_CONN_PLAIN) {
        if (rest_server_init_conn(&listener_sock, emulation_rest_port(), REST_CONN_PLAIN, NULL) != ERR_OK) {
            return -1;
        }
    }
    if (conn_type & REST_CONN_TLS) {
        rest_check_and_load_credentials();
        if (rest_server_init_conn(&tls_listener_sock, emulation_rest_tls_port(), REST_CONN_TLS, &tls_credentials) != ERR_OK) {
            return -1;
        }
    }
    return ERR_OK;

}

int lwip_itf_init(void) {
    err_t err = rest_server_init(REST_CONN_ALL);
    if (err != ERR_OK) {
        return err;
    }
    return ERR_OK;
}
#endif

int rest_server_error(rest_response_t *response, int status_code, const char *message) {
    return rest_response_set_error(response, status_code, message);
}

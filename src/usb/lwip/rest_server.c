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
#include "mbedtls/constant_time.h"

#include <ctype.h>
#ifdef _WIN32
#include "compat/pthread_win32.h"
#ifdef _MSC_VER
#include <windows.h>
#endif
typedef SOCKET socket_t;
typedef int socklen_t;
typedef SSIZE_T ssize_t;
#define close closesocket
#include <string.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#endif
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
extern socket_t tls_listener_sock;
static socket_t listener_sock = INVALID_SOCKET;
static pthread_t rest_thread;
#endif
static rest_conn_t conns[REST_MAX_CONNS];

typedef struct {
    volatile long pending;
    rest_conn_t *conn;
    rest_route_handler_t handler;
    rest_request_t request;
} rest_core1_job_t;

typedef struct {
    rest_response_t response;
    bool ready;
#ifdef _MSC_VER
    char _padding[sizeof(void *) - sizeof(bool)];
#endif
} rest_core1_result_t;

static rest_core1_job_t rest_core1_job = {0};
static rest_core1_result_t rest_core1_result = {0};

static bool rest_core1_job_pending_try_acquire(void) {
#ifdef _MSC_VER
    return InterlockedCompareExchange(&rest_core1_job.pending, 1, 0) == 0;
#else
    long expected = 0;
    return __atomic_compare_exchange_n(&rest_core1_job.pending, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif
}

static bool rest_core1_job_pending_load(void) {
#ifdef _MSC_VER
    return InterlockedCompareExchange(&rest_core1_job.pending, 0, 0) != 0;
#else
    return __atomic_load_n(&rest_core1_job.pending, __ATOMIC_ACQUIRE) != 0;
#endif
}

static void rest_core1_job_pending_store(bool pending) {
#ifdef _MSC_VER
    InterlockedExchange(&rest_core1_job.pending, pending ? 1 : 0);
#else
    __atomic_store_n(&rest_core1_job.pending, pending ? 1 : 0, __ATOMIC_RELEASE);
#endif
}

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

static int rest_start_core1_job(rest_conn_t *conn, rest_route_handler_t handler, const rest_request_t *request) {
    if (handler == NULL) {
        return -1;
    }
    if (!rest_core1_job_pending_try_acquire()) {
        return -1;
    }

    memset(&rest_core1_result, 0, sizeof(rest_core1_result));

    rest_core1_job.conn = conn;
    rest_core1_job.handler = handler;
    if (request != NULL) {
        rest_core1_job.request = *request;
    }
    else {
        memset(&rest_core1_job.request, 0, sizeof(rest_core1_job.request));
    }

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
            if (!rest_core1_job_pending_load() || rest_core1_job.handler == NULL || rest_execute_route_handler(&rest_core1_job.request, rest_core1_job.handler, &rest_core1_result.response) != 0) {
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
    send_json(conn, status_code, rest_status_text_from_code((uint16_t)status_code), json);
}

void rest_task(void) {
    if (!rest_core1_job_pending_load()) {
        rest_route_handler_t handler = rest_background_job_pop();
        if (handler != NULL) {
            if (rest_start_core1_job(NULL, handler, NULL) != 0) {
                // Failed to start background job, push it back to the queue
                rest_background_job_push(handler);
            }
        }
        return;
    }
    int status = card_status(ITF_LWIP);
    if (status != PICOKEYS_OK) {
        return;
    }

    rest_conn_t *conn = rest_core1_job.conn;
    rest_response_t *response = &rest_core1_result.response;
    rest_request_t *request = &rest_core1_job.request;
    bool ready = rest_core1_result.ready;

    uint16_t code = response->status_code == 0 ? 200 : response->status_code;
    const char *content_type = response->content_type;
    char *body = response->body;
    size_t body_len = response->body_len;
    char *headers[REST_HEADER_TOTAL_COUNT] = {0};
    for (size_t i = 0; i < REST_HEADER_TOTAL_COUNT; i++) {
        headers[i] = response->headers[i];
    }
    rest_query_t *query = request->query;

    // Release the shared core1 slot before doing potentially slow network I/O.
    memset(&rest_core1_result, 0, sizeof(rest_core1_result));
    rest_core1_job.conn = NULL;
    rest_core1_job.handler = NULL;
    memset(&rest_core1_job.request, 0, sizeof(rest_core1_job.request));
    rest_core1_job_pending_store(false);

    if (conn != NULL) {
        if (ready && body != NULL && content_type != NULL) {
            send_response(conn, code, rest_status_text_from_code(code), content_type, body, body_len, headers);
        }
        else {
            send_json_error(conn, 500, "internal_error");
        }
    }

    if (body != NULL) {
        free(body);
    }
    if (query != NULL) {
        free(query);
    }
}

static rest_conn_t *alloc_conn(
#ifdef ENABLE_EMULATION
    socket_t sock
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
        socket_t fd = (socket_t)conn->sock;
#ifdef _MSC_VER
        shutdown((SOCKET)fd, 1);
#endif
        (void)close(fd);
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
        ssize_t n = send((socket_t)conn->sock, headers_buf + sent_total, (int)((size_t)header_len - sent_total), 0);
        if (n <= 0) {
            rest_close_conn(conn);
            return;
        }
        sent_total += (size_t)n;
    }
    sent_total = 0;
    while (sent_total < body_len) {
        ssize_t n = send((socket_t)conn->sock, body + sent_total, (int)(body_len - sent_total), 0);
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
    content_length = (unsigned long)conn->request_content_length;
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
    if (mbedtls_ct_memcmp(hmac, hmac_x, sizeof(hmac)) != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

static int parse_query(rest_request_t *request, char *query_str) {
    uint8_t count = 1;
    for (const char *p = query_str; (p = strchr(p, '&')) != NULL && count < UINT8_MAX; p++, count++);
    if (count >= UINT8_MAX) {
        return PICOKEYS_EXEC_ERROR;
    }
    request->query = (rest_query_t *)calloc(count, sizeof(rest_query_t));
    if (request->query == NULL) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    request->query_count = count;
    count = 0;
    for (char *p = query_str; *p != '\0'; p++) {
        if (*p == '&') {
            *p++ = '\0';
            if (*p == '\0' || *p == '&' || *p == '=') {
                free(request->query);
                request->query = NULL;
                return PICOKEYS_ERR_NULL_PARAM;
            }
            if (request->query[count].key == NULL) {
                request->query[count++].key = query_str;
            }
            else {
                count++;
            }
            query_str = p;
        }
        else if (*p == '=') {
            if (p == query_str || request->query[count].key != NULL) {
                free(request->query);
                request->query = NULL;
                return PICOKEYS_ERR_NULL_PARAM;
            }
            *p++ = '\0';
            if (*p == '\0' || *p == '&' || *p == '=') {
                free(request->query);
                request->query = NULL;
                return PICOKEYS_ERR_NULL_PARAM;
            }
            request->query[count].key = query_str;
            request->query[count].value = p;
        }
    }
    if (count < request->query_count) {
        request->query[count++].key = query_str;
    }
    if (count != request->query_count) {
        free(request->query);
        request->query = NULL;
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    return PICOKEYS_OK;
}

void rest_handle_request(rest_conn_t *conn) {
    rest_request_t request_local = {0};
    rest_request_t *request = &request_local;
    const rest_route_t *routes;
    size_t route_count = 0, i;
    bool path_exists_for_other_method = false;
    int parsed;

    parsed = parse_request(conn, request);
    if (parsed <= 0) {
        if (parsed < 0) {
            send_json_error(conn, 400, "bad_request");
        }
        return;
    }

    if (rest_core1_job_pending_load() && !(request->method == REST_HTTP_POST && strcmp(request->path, "/device/jobs/cancel") == 0)) {
        if (request->query != NULL) {
            free(request->query);
            request->query = NULL;
        }
        send_json_error(conn, 503, "busy");
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
        if (!rest_supported_content_type(request->content_type)) {
            send_json_error(conn, 415, "content_type_not_supported");
            return;
        }
    }
    routes = rest_get_routes(&route_count);
    char *query_str = strchr(request->path, '?');
    if (query_str != NULL) {
        if (*(query_str + 1) == '\0') {
            send_json_error(conn, 400, "bad_request");
            return;
        }
    }
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
        else {
            if ((query_str ? strncmp(routes[i].path, request->path, (size_t)(query_str - request->path)) : strcmp(routes[i].path, request->path)) != 0) {
                continue;
            }
        }
        if (!(routes[i].method & request->method)) {
            path_exists_for_other_method = true;
            continue;
        }
        if (query_str && !(routes[i].flags & REST_ROUTE_ALLOW_QUERY)) {
            send_json_error(conn, 400, "query_not_allowed");
            return;
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
            uint32_t req_seq = rest_request_get_seq(request);
            if (req_seq <= session->last_seq) {
                send_json_error(conn, 401, "invalid_seq");
                return;
            }
            if (rest_verify_request_signature(request, session) != PICOKEYS_OK) {
                send_json_error(conn, 401, "invalid_signature");
                return;
            }
            session->last_activity_timestamp = board_millis();
            session->last_seq = req_seq;
            request->session = session;
        }
        if (request->method == REST_HTTP_POST && strcmp(request->path, "/device/jobs/cancel") == 0) {
            rest_response_t response = {0};
            if (routes[i].handler(request, &response) != 0) {
                send_json_error(conn, 500, "internal_error");
                return;
            }
            uint16_t code = response.status_code == 0 ? 200 : response.status_code;
            if (code == 204) {
                send_response(conn, code, rest_status_text_from_code(code), "application/json", "", 0, response.headers);
            }
            else if (response.body != NULL && response.content_type != NULL) {
                send_response(conn, code, rest_status_text_from_code(code), response.content_type, response.body, response.body_len, response.headers);
            }
            else {
                send_json_error(conn, 500, "internal_error");
            }
            if (response.body != NULL) {
                free(response.body);
            }
            return;
        }

        if (query_str != NULL && parse_query(request, query_str + 1) != PICOKEYS_OK) {
            send_json_error(conn, 400, "bad_request");
            return;
        }
        if (rest_start_core1_job(conn, routes[i].handler, request) != 0) {
            send_json_error(conn, 503, "busy");
            if (request->query != NULL) {
                free(request->query);
                request->query = NULL;
            }
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

int x509_set_random_serial(mbedtls_x509write_cert *crt) {
    uint8_t serial[16];
    random_fill_buffer(serial, sizeof(serial));
    serial[0] &= 0x7F;

    size_t off = 0;
    while (off < sizeof(serial) - 1 && serial[off] == 0x00) off++;

    return mbedtls_x509write_crt_set_serial_raw(crt, serial + off, sizeof(serial) - off);
}

static void rest_check_and_load_credentials(void) {
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
        file_put_data(ef, pkey, (uint16_t)olen);
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
        mbedtls_ecp_keypair_calc_public(mbedtls_pk_ec(key), random_fill_iterator, NULL);
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
        x509_set_random_serial(&crt);
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_validity(&crt, "20260101000000", "20360101000000");
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, 0);
        if (ret != 0) goto out;
        ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
        if (ret != 0) goto out;

        ret = mbedtls_x509write_crt_pem(&crt, cert_pem, sizeof(cert_pem), random_fill_iterator, NULL);
        if (ret == 0) {
            file_put_data(ef, cert_pem, (uint16_t)strlen((char *)cert_pem) + 1);
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
    if (rest_core1_job_pending_load() && rest_core1_job.conn == conn) {
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

static err_t rest_server_init_conn(struct tcp_pcb **list_pcb, uint16_t port, rest_conn_type_t conn_type, const tls_credentials_t *tls_creds) {
    if (*list_pcb != NULL) {
        return ERR_OK;
    }
    if (conn_type & REST_CONN_TLS) {
        if (tls_creds == NULL || tls_creds->tls_key_pem == NULL || tls_creds->tls_cert_pem == NULL) {
            return ERR_VAL;
        }
        if (tls_init_tls_context(tls_creds) != 0) {
            return ERR_VAL;
        }
    }

    *list_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (*list_pcb == NULL) {
        return ERR_MEM;
    }
    err_t err = tcp_bind(*list_pcb, IP_ANY_TYPE, port);
    if (err != ERR_OK) {
        tcp_abort(*list_pcb);
        *list_pcb = NULL;
        return err;
    }
    *list_pcb = tcp_listen_with_backlog(*list_pcb, REST_MAX_CONNS);
    if (*list_pcb == NULL) {
        return ERR_MEM;
    }
    tcp_accept(*list_pcb, rest_accept);
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
}

static void *rest_emulation_thread(void *arg) {
    struct sockaddr_in peer;
    socket_t listen_fd = (socket_t)(uintptr_t)arg;

    while (true) {
        socklen_t peer_len = sizeof(peer);
        socket_t accepted = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        rest_conn_t *conn;
        if (accepted == INVALID_SOCKET) {
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
                ssize_t n = recv((socket_t)conn->sock, conn->request + conn->request_len, (int)(REST_MAX_REQUEST_SIZE - conn->request_len), 0);
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

static err_t rest_server_init_conn(socket_t *list_sock, int port, rest_conn_type_t conn_type, const tls_credentials_t *tls_creds) {
    struct sockaddr_in addr;
#ifdef _MSC_VER
    char one = 1;
#else
    int one = 1;
#endif

    if (*list_sock != INVALID_SOCKET) {
        printf("Listener socket for port %d already initialized\n", port);
        return ERR_OK;
    }
    if (conn_type & REST_CONN_TLS) {
        if (tls_creds == NULL || tls_creds->tls_key_pem == NULL || tls_creds->tls_cert_pem == NULL) {
            return ERR_VAL;
        }
        if (tls_init_tls_context(tls_creds) != 0) {
            return ERR_VAL;
        }
    }
    *list_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*list_sock == INVALID_SOCKET) {
        printf("Failed to create listener socket for port %d\n", port);
        return -1;
    }
    if (setsockopt(*list_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one)) != 0) {
        printf("Failed to set SO_REUSEADDR on listener socket for port %d\n", port);
        (void)close(*list_sock);
        *list_sock = INVALID_SOCKET;
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(*list_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("Failed bind %d\n", errno);
        (void)close(*list_sock);
        *list_sock = INVALID_SOCKET;
        return -1;
    }
    if (listen(*list_sock, REST_MAX_CONNS) != 0) {
        printf("Failed listen %d\n", errno);
        (void)close(*list_sock);
        *list_sock = INVALID_SOCKET;
        return -1;
    }
    if (pthread_create(&rest_thread, NULL, rest_emulation_thread, (void *)(uintptr_t)(*list_sock)) != 0) {
        (void)close(*list_sock);
        *list_sock = INVALID_SOCKET;
        return -1;
    }
    (void)pthread_detach(rest_thread);
    return ERR_OK;
}

err_t rest_server_init(rest_conn_type_t conn_type) {
#ifdef _MSC_VER
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("winsock initialization failure\n");
    }
#endif
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

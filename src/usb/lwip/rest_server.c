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

#include <ctype.h>
#include <strings.h>

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

static void *rest_core1_thread(void *arg);
static void send_response(rest_conn_t *conn, int status_code, const char *status_text, const char *content_type, const char *body, size_t body_len);
static void send_json(rest_conn_t *conn, int status_code, const char *status_text, const char *json_body);

static int rest_start_core1_job(rest_conn_t *conn, const rest_request_t *request, rest_route_handler_t handler) {
    if (request == NULL || handler == NULL || rest_core1_job.pending) {
        return -1;
    }

    memset(&rest_core1_result, 0, sizeof(rest_core1_result));

    rest_core1_job.pending = true;
    rest_core1_job.conn = conn;
    rest_core1_job.handler = handler;
    rest_core1_job.request = *request;

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
            send_response(conn, code, rest_status_text_from_code(code), response->content_type, response->body, response->body_len);
        }
        else {
            send_json(conn, 500, "Internal Server Error", "{\"error\":\"internal_error\"}");
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
    tcp_arg(conn->pcb, NULL);
    tcp_recv(conn->pcb, NULL);
    tcp_sent(conn->pcb, NULL);
    tcp_poll(conn->pcb, NULL, 0);
    tcp_err(conn->pcb, NULL);
    err = tcp_close(conn->pcb);
    if (err != ERR_OK) {
        tcp_abort(conn->pcb);
    }
    if (conn->conn_type == REST_CONN_TLS) {
        mbedtls_ssl_free(&conn->ssl);
    }
    clear_conn(conn);
#endif
}

static void send_response(rest_conn_t *conn, int status_code, const char *status_text, const char *content_type, const char *body, size_t body_len) {
    char headers[256];
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

    header_len = snprintf(headers, sizeof(headers),
                          "HTTP/1.0 %d %s\r\n"
                          "Content-Type: %s\r\n"
                          "Content-Length: %lu\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          status_code, status_text, content_type, (unsigned long)body_len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(headers)) {
        rest_close_conn(conn);
        return;
    }

    if (conn->conn_type == REST_CONN_TLS) {
        size_t written = 0;
        int ret;
        int want_retries = 0;

        while (written < (size_t)header_len) {
            ret = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)headers + written, (size_t)header_len - written);
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
        ssize_t n = send(conn->sock, headers + sent_total, (size_t)header_len - sent_total, 0);
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
    err = tcp_write(conn->pcb, headers, (uint16_t)header_len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        rest_close_conn(conn);
        return;
    }
    retries = 0;
    while (body_len > 0) {
        err = tcp_write(conn->pcb, body, (uint16_t)body_len, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK) {
            break;
        }
        if (err != ERR_MEM || retries >= 4) {
            rest_close_conn(conn);
            return;
        }
        (void)tcp_output(conn->pcb);
        retries++;
    }
    (void)tcp_output(conn->pcb);
#endif
    rest_close_conn(conn);
}

static void send_json(rest_conn_t *conn, int status_code, const char *status_text, const char *json_body) {
    send_response(conn, status_code, status_text, "application/json", json_body, strlen(json_body));
}

static int parse_request(rest_conn_t *conn, rest_request_t *request) {
    char *header_end, *line_end, *cursor;
    size_t headers_size;
    unsigned long content_length = 0;
    char method_str[REST_MAX_METHOD_SIZE] = {0};
    memset(request, 0, sizeof(rest_request_t));
    conn->request[conn->request_len] = '\0';
    header_end = strstr(conn->request, "\r\n\r\n");
    if (header_end == NULL) {
        return 0;
    }
    headers_size = (size_t)(header_end - conn->request) + 4;
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
        char *next = strstr(cursor, "\r\n"), *colon, *name, *value, *endptr;
        if (next == NULL || next > header_end) {
            return -1;
        }
        if (next == cursor) {
            break;
        }
        *next = '\0';
        colon = strchr(cursor, ':');
        if (colon != NULL) {
            *colon = '\0';
            name = cursor;
            value = colon + 1;

            while (*name != '\0' && isspace((unsigned char)*name)) {
                name++;
            }
            while (*value != '\0' && isspace((unsigned char)*value)) {
                value++;
            }
            while (*name != '\0' && isspace((unsigned char)name[strlen(name) - 1])) {
                name[strlen(name) - 1] = '\0';
            }
            while (*value != '\0' && isspace((unsigned char)value[strlen(value) - 1])) {
                value[strlen(value) - 1] = '\0';
            }

            if (strcasecmp(name, "Content-Length") == 0) {
                content_length = strtoul(value, &endptr, 10);
                if ((endptr == value) || (*endptr != '\0') || (content_length > REST_MAX_REQUEST_SIZE)) {
                    return -1;
                }
            }
            else if (strcasecmp(name, "Content-Type") == 0) {
                request->content_type = value;
            }
        }
        cursor = next + 2;
    }
    if (conn->request_len < headers_size + content_length) {
        return 0;
    }
    request->body = conn->request + headers_size;
    request->body_len = (size_t)content_length;
    return 1;
}

void rest_handle_request(rest_conn_t *conn) {
    rest_request_t *request = &rest_core1_job.request;
    const rest_route_t *routes;
    size_t route_count = 0, i;
    bool path_exists_for_other_method = false;
    int parsed;

    if (rest_core1_job.pending) {
        send_json(conn, 503, "Service Unavailable", "{\"error\":\"busy\"}");
        return;
    }

    memset(&rest_core1_job, 0, sizeof(rest_core1_job));
    parsed = parse_request(conn, request);
    if (parsed <= 0) {
        if (parsed < 0) {
            send_json(conn, 400, "Bad Request", "{\"error\":\"bad_request\"}");
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
            send_json(conn, 415, "Unsupported Media Type", "{\"error\":\"content_type_must_be_application_json\"}");
            return;
        }
    }
    routes = rest_get_routes(&route_count);
    for (i = 0; i < route_count; i++) {
        if (routes[i].path == NULL || routes[i].handler == NULL) {
            continue;
        }
        if (strcmp(routes[i].path, request->path) != 0) {
            continue;
        }
        if (routes[i].method != request->method) {
            path_exists_for_other_method = true;
            continue;
        }
        if (rest_start_core1_job(conn, request, routes[i].handler) != 0) {
            send_json(conn, 500, "Internal Server Error", "{\"error\":\"internal_error\"}");
        }
        return;
    }

    if (path_exists_for_other_method) {
        send_json(conn, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}");
    }
    else {
        send_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}");
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
        file_t *ef_key = search_file(EF_TLS_KEY);
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
    }
    tls_credentials.tls_cert_pem = (char *)file_get_data(ef);
    tls_credentials.tls_cert_pem_len = file_get_size(ef);
    printf("TLS certificate loaded, length: %u bytes\n", (unsigned)tls_credentials.tls_cert_pem_len);
    low_flash_available();
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
        send_json(conn, 413, "Payload Too Large", "{\"error\":\"payload_too_large\"}");
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
    rest_close_conn(conn);
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
                    send_json(conn, 413, "Payload Too Large", "{\"error\":\"payload_too_large\"}");
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

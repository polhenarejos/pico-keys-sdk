#include "rest_server.h"
#include "pico_keys.h"
#include "usb.h"

#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define REST_PORT 80
#define REST_MAX_CONNS 4
#define REST_MAX_REQUEST_SIZE 1024
#define REST_MAX_METHOD_SIZE 8
#define REST_MAX_CONTENT_TYPE_SIZE 64

#ifdef DEBUG_APDU
static void debug_dump_payload(const char *tag, const char *buffer, size_t len) {
    size_t i;
    if (buffer == NULL) {
        printf("[rest-debug] %s: <null>\n", tag);
        return;
    }

    printf("[rest-debug] %s (%lu bytes): \"", tag, (unsigned long)len);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buffer[i];
        if (c == '\r') {
            printf("\\r");
        } else if (c == '\n') {
            printf("\\n");
        } else if (c == '\t') {
            printf("\\t");
        } else if (c >= 32 && c <= 126) {
            putchar((int)c);
        } else {
            printf("\\x%02X", c);
        }
    }
    printf("\"\n");
    if (tag[2] == 's') {
        printf("\n");
    }
}
#define REST_DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define debug_dump_payload(tag, buffer, len) do { (void)(tag); (void)(buffer); (void)(len); } while (0)
#define REST_DEBUG_LOG(...) do {} while (0)
#endif

typedef struct {
    bool in_use;
#ifdef ENABLE_EMULATION
    int sock;
#else
    struct tcp_pcb *pcb;
#endif
    char request[REST_MAX_REQUEST_SIZE + 1];
    size_t request_len;
} rest_conn_t;

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
    const rest_request_t *request;
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
static const char *status_text_from_code(uint16_t code);

static int execute_route_handler(const rest_request_t *request, rest_route_handler_t handler, rest_response_t *response) {
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

static int rest_start_core1_job(rest_conn_t *conn, const rest_request_t *request, rest_route_handler_t handler) {
    if (conn == NULL || request == NULL || handler == NULL || rest_core1_job.pending) {
        return -1;
    }

    memset(&rest_core1_job, 0, sizeof(rest_core1_job));
    memset(&rest_core1_result, 0, sizeof(rest_core1_result));

    rest_core1_job.pending = true;
    rest_core1_job.conn = conn;
    rest_core1_job.handler = handler;
    rest_core1_job.request = request;

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
            if (!rest_core1_job.pending || rest_core1_job.handler == NULL || execute_route_handler(rest_core1_job.request, rest_core1_job.handler, &rest_core1_result.response) != 0) {
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
    if (status != PICOKEY_OK) {
        return;
    }

    conn = rest_core1_job.conn;
    if (conn != NULL) {
        if (rest_core1_result.ready && rest_core1_result.response.body != NULL && rest_core1_result.response.content_type != NULL) {
            uint16_t code = rest_core1_result.response.status_code == 0 ? 200 : rest_core1_result.response.status_code;
            send_response(conn, code, status_text_from_code(code), rest_core1_result.response.content_type,
                          rest_core1_result.response.body, rest_core1_result.response.body_len);
        } else {
            send_json(conn, 500, "Internal Server Error", "{\"error\":\"internal_error\"}");
        }
    }

    if (rest_core1_result.response.body != NULL) {
        free(rest_core1_result.response.body);
    }
    memset(&rest_core1_result, 0, sizeof(rest_core1_result));
    memset(&rest_core1_job, 0, sizeof(rest_core1_job));
}

__attribute__((weak)) const rest_route_t *rest_get_routes(size_t *count) {
    if (count != NULL) {
        *count = 0;
    }
    return NULL;
}

static rest_conn_t *alloc_conn(
#ifdef ENABLE_EMULATION
    int sock
#else
    struct tcp_pcb *pcb
#endif
) {
    size_t i;
    for (i = 0; i < REST_MAX_CONNS; i++) {
        if (!conns[i].in_use) {
            memset(&conns[i], 0, sizeof(conns[i]));
            conns[i].in_use = true;
#ifdef ENABLE_EMULATION
            conns[i].sock = sock;
#else
            conns[i].pcb = pcb;
#endif
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

static void close_conn(rest_conn_t *conn) {
#ifdef ENABLE_EMULATION
    if (conn == NULL) {
        return;
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
        "[rest-debug] response: status=%d content_type=%s body_len=%lu\n",
        status_code,
        (content_type != NULL) ? content_type : "(null)",
        (unsigned long)body_len
    );
    debug_dump_payload("response-body", body, body_len);

    header_len = snprintf(headers, sizeof(headers),
                          "HTTP/1.0 %d %s\r\n"
                          "Content-Type: %s\r\n"
                          "Content-Length: %lu\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          status_code, status_text, content_type, (unsigned long)body_len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(headers)) {
        close_conn(conn);
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
            close_conn(conn);
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
            close_conn(conn);
            return;
        }
        sent_total += (size_t)n;
    }
#else
    err = tcp_write(conn->pcb, headers, (uint16_t)header_len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        close_conn(conn);
        return;
    }
    retries = 0;
    while (body_len > 0) {
        err = tcp_write(conn->pcb, body, (uint16_t)body_len, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK) {
            break;
        }
        if (err != ERR_MEM || retries >= 4) {
            close_conn(conn);
            return;
        }
        (void)tcp_output(conn->pcb);
        retries++;
    }
    (void)tcp_output(conn->pcb);
#endif
    close_conn(conn);
}

static void send_json(rest_conn_t *conn, int status_code, const char *status_text, const char *json_body) {
    send_response(conn, status_code, status_text, "application/json", json_body, strlen(json_body));
}

static const char *status_text_from_code(uint16_t code) {
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

static const char *method_str_from_request_method(rest_http_method_t method) {
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

static int is_json(const char *content_type) {
    if (content_type == NULL) {
        return 0;
    }
    return strncasecmp(content_type, "application/json", 16) == 0;
}

static void handle_request(rest_conn_t *conn) {
    rest_request_t request = {0};
    const rest_route_t *routes;
    size_t route_count = 0, i;
    bool path_exists_for_other_method = false;
    int parsed;

    if (rest_core1_job.pending) {
        send_json(conn, 503, "Service Unavailable", "{\"error\":\"busy\"}");
        return;
    }

    parsed = parse_request(conn, &request);
    if (parsed <= 0) {
        if (parsed < 0) {
            send_json(conn, 400, "Bad Request", "{\"error\":\"bad_request\"}");
        }
        return;
    }

    REST_DEBUG_LOG(
        "[rest-debug] request: %s %s\n",
        method_str_from_request_method(request.method),
        request.path
    );
    debug_dump_payload("request-body", request.body, request.body_len);

    if (request.method == REST_HTTP_POST || request.method == REST_HTTP_PUT) {
        if (!is_json(request.content_type)) {
            send_json(conn, 415, "Unsupported Media Type", "{\"error\":\"content_type_must_be_application_json\"}");
            return;
        }
    }
    routes = rest_get_routes(&route_count);
    for (i = 0; i < route_count; i++) {
        if (routes[i].path == NULL || routes[i].handler == NULL) {
            continue;
        }
        if (strcmp(routes[i].path, request.path) != 0) {
            continue;
        }
        if (routes[i].method != request.method) {
            path_exists_for_other_method = true;
            continue;
        }
        if (rest_start_core1_job(conn, &request, routes[i].handler) != 0) {
            send_json(conn, 500, "Internal Server Error", "{\"error\":\"internal_error\"}");
        }
        return;
    }

    if (path_exists_for_other_method) {
        send_json(conn, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}");
    } else {
        send_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}");
    }
}

#ifndef ENABLE_EMULATION
static err_t rest_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    rest_conn_t *conn = (rest_conn_t *)arg;

    LWIP_UNUSED_ARG(pcb);
    if (err != ERR_OK) {
        if (p != NULL) {
            pbuf_free(p);
        }
        close_conn(conn);
        return err;
    }
    if (p == NULL) {
        close_conn(conn);
        return ERR_OK;
    }
    if (conn == NULL) {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }
    if (conn->request_len + p->tot_len > REST_MAX_REQUEST_SIZE) {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
        send_json(conn, 413, "Payload Too Large", "{\"error\":\"payload_too_large\"}");
        return ERR_OK;
    }
    pbuf_copy_partial(p, conn->request + conn->request_len, p->tot_len, 0);
    conn->request_len += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    handle_request(conn);
    return ERR_OK;
}

static err_t rest_poll(void *arg, struct tcp_pcb *pcb) {
    rest_conn_t *conn = (rest_conn_t *)arg;
    LWIP_UNUSED_ARG(pcb);
    if (rest_core1_job.pending && rest_core1_job.conn == conn) {
        return ERR_OK;
    }
    close_conn(conn);
    return ERR_OK;
}

static void rest_err(void *arg, err_t err) {
    rest_conn_t *conn = (rest_conn_t *)arg;
    LWIP_UNUSED_ARG(err);
    clear_conn(conn);
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
    tcp_arg(newpcb, conn);
    tcp_recv(newpcb, rest_recv);
    tcp_poll(newpcb, rest_poll, 8);
    tcp_err(newpcb, rest_err);
    return ERR_OK;
}

err_t rest_server_init(void) {
    err_t err;
    if (listener_pcb != NULL) {
        return ERR_OK;
    }
    listener_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (listener_pcb == NULL) {
        return ERR_MEM;
    }
    err = tcp_bind(listener_pcb, IP_ANY_TYPE, REST_PORT);
    if (err != ERR_OK) {
        tcp_abort(listener_pcb);
        listener_pcb = NULL;
        return err;
    }
    listener_pcb = tcp_listen_with_backlog(listener_pcb, REST_MAX_CONNS);
    if (listener_pcb == NULL) {
        return ERR_MEM;
    }
    tcp_accept(listener_pcb, rest_accept);
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
    (void)arg;

    while (true) {
        socklen_t peer_len = sizeof(peer);
        int accepted = accept(listener_sock, (struct sockaddr *)&peer, &peer_len);
        rest_conn_t *conn;
        if (accepted < 0) {
            continue;
        }
        conn = alloc_conn(accepted);
        if (conn == NULL) {
            (void)close(accepted);
            continue;
        }
        while (conn->in_use) {
            ssize_t n = recv(conn->sock, conn->request + conn->request_len, REST_MAX_REQUEST_SIZE - conn->request_len, 0);
            if (n <= 0) {
                close_conn(conn);
                break;
            }
            conn->request_len += (size_t)n;
            if (conn->request_len > REST_MAX_REQUEST_SIZE) {
                send_json(conn, 413, "Payload Too Large", "{\"error\":\"payload_too_large\"}");
                break;
            }
            handle_request(conn);
        }
    }
    return NULL;
}
#endif

err_t rest_server_init(void) {
#ifndef _MSC_VER
    struct sockaddr_in addr;
    int one = 1;
    int port = emulation_rest_port();

    if (listener_sock >= 0) {
        return ERR_OK;
    }
    listener_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_sock < 0) {
        return -1;
    }
    if (setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        (void)close(listener_sock);
        listener_sock = -1;
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        (void)close(listener_sock);
        listener_sock = -1;
        return -1;
    }
    if (listen(listener_sock, REST_MAX_CONNS) != 0) {
        (void)close(listener_sock);
        listener_sock = -1;
        return -1;
    }
    if (pthread_create(&rest_thread, NULL, rest_emulation_thread, NULL) != 0) {
        (void)close(listener_sock);
        listener_sock = -1;
        return -1;
    }
    (void)pthread_detach(rest_thread);
    return ERR_OK;
#else
    return -1;
#endif
}

int lwip_itf_init(void) {
    return rest_server_init();
}
#endif

int rest_server_error(rest_response_t *response, int status_code, const char *message) {
    if (response == NULL) {
        return -1;
    }
    char json_template[256];
    int json_len = snprintf(json_template, sizeof(json_template), "{\"error\":\"%s\"}", message);
    if (json_len <= 0 || (size_t)json_len >= sizeof(json_template)) {
        return -1;
    }
    response->status_code = status_code;
    response->body = strdup(json_template);
    if (response->body == NULL) {
        return -1;
    }
    response->body_len = (size_t)json_len;
    return 0;
}

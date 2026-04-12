#include "rest_server.h"

#include "lwip/tcp.h"
#include "lwip/def.h"

#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define REST_PORT 80
#define REST_MAX_CONNS 4
#define REST_MAX_REQUEST_SIZE 8192
#define REST_MAX_METHOD_SIZE 8
#define REST_MAX_PATH_SIZE 192

typedef struct {
    bool in_use;
    struct tcp_pcb *pcb;
    char request[REST_MAX_REQUEST_SIZE + 1];
    size_t request_len;
} rest_conn_t;

static struct tcp_pcb *listener_pcb = NULL;
static rest_conn_t conns[REST_MAX_CONNS];

__attribute__((weak)) const rest_route_t *rest_get_routes(size_t *count) {
    if (count != NULL) {
        *count = 0;
    }
    return NULL;
}

static rest_conn_t *alloc_conn(struct tcp_pcb *pcb) {
    size_t i;
    for (i = 0; i < REST_MAX_CONNS; i++) {
        if (!conns[i].in_use) {
            memset(&conns[i], 0, sizeof(conns[i]));
            conns[i].in_use = true;
            conns[i].pcb = pcb;
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
}

static void close_conn(rest_conn_t *conn) {
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
}

static void send_response(rest_conn_t *conn, int status_code, const char *status_text, const char *content_type, const char *body, size_t body_len) {
    char headers[256];
    int header_len;
    err_t err;
    if (conn == NULL || conn->pcb == NULL) {
        return;
    }
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
    err = tcp_write(conn->pcb, headers, (uint16_t)header_len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK && body_len > 0) {
        err = tcp_write(conn->pcb, body, (uint16_t)body_len, TCP_WRITE_FLAG_COPY);
    }
    if (err == ERR_OK) {
        (void)tcp_output(conn->pcb);
    }
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
        default:
            return "OK";
    }
}

static int parse_request(rest_conn_t *conn, rest_http_method_t *method, char *path, size_t path_size, rest_request_t *request) {
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
    if (sscanf(conn->request, "%7s %191s", method_str, path) != 2) {
        return -1;
    }
    if (strcmp(method_str, "GET") == 0) {
        *method = REST_HTTP_GET;
    }
    else if (strcmp(method_str, "POST") == 0) {
        *method = REST_HTTP_POST;
    }
    else if (strcmp(method_str, "PUT") == 0) {
        *method = REST_HTTP_PUT;
    }
    else if (strcmp(method_str, "DELETE") == 0) {
        *method = REST_HTTP_DELETE;
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

static void handle_request(rest_conn_t *conn) {
    rest_http_method_t method;
    char path[REST_MAX_PATH_SIZE] = {0};
    rest_request_t request;
    rest_response_t response;
    const rest_route_t *routes;
    size_t route_count = 0, i;
    bool path_exists_for_other_method = false;
    int parsed;

    parsed = parse_request(conn, &method, path, sizeof(path), &request);
    if (parsed <= 0) {
        if (parsed < 0) {
            send_json(conn, 400, "Bad Request", "{\"error\":\"bad_request\"}");
        }
        return;
    }
    request.method = method;
    request.path = path;
    routes = rest_get_routes(&route_count);
    for (i = 0; i < route_count; i++) {
        if (routes[i].path == NULL || routes[i].handler == NULL) {
            continue;
        }
        if (strcmp(routes[i].path, path) != 0) {
            continue;
        }
        if (routes[i].method != method) {
            path_exists_for_other_method = true;
            continue;
        }
        response.status_code = 200;
        response.content_type = "application/json";
        response.body = "{\"ok\":true}";
        response.body_len = strlen(response.body);

        if (routes[i].handler(&request, &response) != 0) {
            send_json(conn, 500, "Internal Server Error", "{\"error\":\"internal_error\"}");
            return;
        }
        if (response.content_type == NULL || response.body == NULL) {
            send_json(conn, 500, "Internal Server Error", "{\"error\":\"invalid_response\"}");
            return;
        }
        send_response(conn, response.status_code, status_text_from_code(response.status_code), response.content_type, response.body, response.body_len);
        return;
    }

    if (path_exists_for_other_method) {
        send_json(conn, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}");
    } else {
        send_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}");
    }
}

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

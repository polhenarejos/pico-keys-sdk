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

static void send_response_and_close(rest_conn_t *conn, int status_code, const char *status_text,
                                    const char *content_type, const char *body, size_t body_len) {
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

static void send_json_and_close(rest_conn_t *conn, int status_code, const char *status_text, const char *json_body) {
    send_response_and_close(conn, status_code, status_text, "application/json", json_body, strlen(json_body));
}

static int parse_request(rest_conn_t *conn,
                         char *method,
                         size_t method_size,
                         char *path,
                         size_t path_size,
                         const char **body,
                         size_t *body_len,
                         bool *json_content_type) {
    char *header_end;
    char *line_end;
    char *cursor;
    size_t headers_size;
    unsigned long content_length = 0;

    *body = NULL;
    *body_len = 0;
    *json_content_type = false;

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
    if (sscanf(conn->request, "%7s %191s", method, path) != 2) {
        return -1;
    }

    cursor = line_end + 2;
    while (cursor < header_end) {
        char *next = strstr(cursor, "\r\n");
        char *colon;
        char *name;
        char *value;
        char *endptr;

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
            } else if (strcasecmp(name, "Content-Type") == 0) {
                if (strncasecmp(value, "application/json", 16) == 0) {
                    *json_content_type = true;
                }
            }
        }

        cursor = next + 2;
    }

    if (conn->request_len < headers_size + content_length) {
        return 0;
    }

    *body = conn->request + headers_size;
    *body_len = (size_t)content_length;
    return 1;
}

static void handle_request(rest_conn_t *conn) {
    char method[REST_MAX_METHOD_SIZE] = {0};
    char path[REST_MAX_PATH_SIZE] = {0};
    const char *body;
    size_t body_len;
    bool is_json;
    int parsed;

    parsed = parse_request(conn, method, sizeof(method), path, sizeof(path), &body, &body_len, &is_json);
    if (parsed <= 0) {
        if (parsed < 0) {
            send_json_and_close(conn, 400, "Bad Request", "{\"error\":\"bad_request\"}");
        }
        return;
    }

    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/health") == 0) {
            send_json_and_close(conn, 200, "OK", "{\"ok\":true}");
            return;
        }
        send_json_and_close(conn, 404, "Not Found", "{\"error\":\"not_found\"}");
        return;
    }

    if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) {
        if (strcmp(path, "/echo") != 0) {
            send_json_and_close(conn, 404, "Not Found", "{\"error\":\"not_found\"}");
            return;
        }

        if (!is_json) {
            send_json_and_close(conn, 415, "Unsupported Media Type", "{\"error\":\"content_type_must_be_application_json\"}");
            return;
        }

        send_response_and_close(conn, 200, "OK", "application/json", body, body_len);
        return;
    }

    if (strcmp(method, "DELETE") == 0) {
        if (strcmp(path, "/echo") == 0) {
            send_json_and_close(conn, 200, "OK", "{\"deleted\":true}");
            return;
        }
        send_json_and_close(conn, 404, "Not Found", "{\"error\":\"not_found\"}");
        return;
    }

    send_json_and_close(conn, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}");
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
        send_json_and_close(conn, 413, "Payload Too Large", "{\"error\":\"payload_too_large\"}");
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

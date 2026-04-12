#ifndef PICO_KEYS_REST_SERVER_H
#define PICO_KEYS_REST_SERVER_H

#include "lwip/err.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    REST_HTTP_GET = 0,
    REST_HTTP_POST,
    REST_HTTP_PUT,
    REST_HTTP_DELETE
} rest_http_method_t;

typedef struct {
    rest_http_method_t method;
    const char *path;
    const char *body;
    size_t body_len;
    const char *content_type;
} rest_request_t;

typedef struct {
    uint16_t status_code;
    const char *content_type;
    const char *body;
    size_t body_len;
} rest_response_t;

typedef int (*rest_route_handler_t)(const rest_request_t *request, rest_response_t *response);

typedef struct {
    rest_http_method_t method;
    const char *path;
    rest_route_handler_t handler;
} rest_route_t;

const rest_route_t *rest_get_routes(size_t *count);

err_t rest_server_init(void);

#endif

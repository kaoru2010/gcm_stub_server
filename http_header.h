#pragma once

#define HTTP_METHOD_GET 1
#define HTTP_METHOD_POST 2
#define HTTP_METHOD_HEAD 3
#define HTTP_METHOD_PUT 4
#define HTTP_METHOD_DELETE 5

#define HTTP_PROTOCOL_1_0 1
#define HTTP_PROTOCOL_1_1 2

#ifdef __cplusplus
#include <string>

struct http_header_context_t
{
    enum state_t {
        WAIT_NULL = 0, WAIT_CONTENT_LENGTH, WAIT_TRANSFER_CODING,
    };

    http_header_context_t()
    :   http_method()
    ,   path()
    ,   http_protocol()
    ,   state()
    ,   content_length()
    ,   chunked()
    {
    }

    int http_method;
    std::string path;
    int http_protocol;

    state_t state;
    int content_length;
    bool chunked;
};
#else
typedef struct http_header_context_tag http_header_context_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

void http_header_set_method(http_header_context_t *, int http_method);
void http_header_set_path(http_header_context_t *, char *path);
void http_header_set_protocol(http_header_context_t *, int http_protocol);
void http_header_accept_key(http_header_context_t *, char *key);
void http_header_accept_value(http_header_context_t *, char *value);
void http_header_accept_key_content_length(http_header_context_t *);
void http_header_accept_key_transfer_coding(http_header_context_t *);

int parse_status_line(http_header_context_t *context, const char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#include <string.h>
#include <stdlib.h>
#include <http_header.h>

extern "C" {

void http_header_set_method(http_header_context_t *ctx, int http_method)
{
    ctx->http_method = http_method;
}

void http_header_set_path(http_header_context_t *ctx, char *path)
{
    if (path) {
        ctx->path = path;
    }
}

void http_header_set_protocol(http_header_context_t *ctx, int http_protocol)
{
    ctx->http_protocol = http_protocol;
}

void http_header_accept_key(http_header_context_t *ctx, char *key)
{
    ctx->state = http_header_context_t::WAIT_NULL;
}

void http_header_accept_value(http_header_context_t *ctx, char *value)
{
    if (ctx->state == http_header_context_t::WAIT_CONTENT_LENGTH) {
        ctx->content_length = atoi(value);
    }
    else if (ctx->state == http_header_context_t::WAIT_TRANSFER_CODING && strcmp(value, "chunked") == 0) {
        ctx->chunked = true;
    }
}

void http_header_accept_key_content_length(http_header_context_t *ctx)
{
    ctx->state = http_header_context_t::WAIT_CONTENT_LENGTH;
}

void http_header_accept_key_transfer_coding(http_header_context_t *ctx)
{
    ctx->state = http_header_context_t::WAIT_TRANSFER_CODING;
}

}

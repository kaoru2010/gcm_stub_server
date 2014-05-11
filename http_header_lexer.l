%{
#include <http_header.h>
%}

%option 8bit noyywrap nounput noinput nodefault
%option extra-type="http_header_context_t *"
%option reentrant

%x path protocol header_key header_value

%%

GET http_header_set_method(yyextra, HTTP_METHOD_GET);
POST http_header_set_method(yyextra, HTTP_METHOD_POST);
" " BEGIN(path);

<path>{
    [^ ]+ http_header_set_path(yyextra, yytext);
    " " BEGIN(protocol);
}

<protocol>{
    "HTTP/1.0" http_header_set_protocol(yyextra, HTTP_PROTOCOL_1_0);
    "HTTP/1.1" http_header_set_protocol(yyextra, HTTP_PROTOCOL_1_1);
    \r\n|\n BEGIN(header_key);
}

<header_key>{
    (?i:Content-Length) http_header_accept_key_content_length(yyextra);
    (?i:Transfer-Coding) http_header_accept_key_transfer_coding(yyextra);
    [^:]* http_header_accept_key(yyextra, yytext);
    ":" BEGIN(header_value);
}

<header_value>{
    [^\r\n]* http_header_accept_value(yyextra, yytext);
    \r\n|\n BEGIN(header_key);
}

<*>{
    . ;
    \n ;
}

%%

int parse_status_line(http_header_context_t *context, const char *buf, size_t len)
{
    yyscan_t scanner;
    yylex_init_extra(context, &scanner);
    YY_BUFFER_STATE state = yy_scan_bytes(buf, len, scanner);
    yylex(scanner);
    yy_delete_buffer(state, scanner);
    yylex_destroy(scanner);
    return 0;
}

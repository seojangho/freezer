#ifndef CTX_H
#define CTX_H

#include <curl/curl.h>
#include <errno.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <utf8proc.h>

#define print_debug(message)                                                   \
    print_message_(true, false, __FILE__, __LINE__, (message))
#define print_debugv(format, ...)                                              \
    print_debug_v_(__FILE__, __LINE__, (format), __VA_ARGS__)
#define print_error(message)                                                   \
    print_message_(false, false, __FILE__, __LINE__, (message))
#define exit_error(message)                                                    \
    print_message_(false, true, __FILE__, __LINE__, (message))
// WARNING strerror is not therad-safe
#define exit_errno()                                                           \
    print_message_(false, true, __FILE__, __LINE__, strerror(errno))
#define exit_curl(curlcode)                                                    \
    print_message_(false, true, __FILE__, __LINE__,                            \
                   curl_easy_strerror(curlcode))
#define exit_openssl()                                                         \
    print_message_(false, true, __FILE__, __LINE__,                            \
                   ERR_error_string(ERR_peek_last_error(), NULL))
#define exit_utf8proc(code)                                                    \
    print_message_(false, true, __FILE__, __LINE__, utf8proc_errmsg(code))

#define AWS_S3 "s3"
#define AWS_GLACIER "glacier"
#define SHA256_BYTES 32
#define ONE_MEGA (1024 * 1024)

enum http_method {
    get,
    put,
    post,
};

enum service {
    s3,
    glacier,
};

typedef struct string_tuple {
    const uint8_t *key;
    const uint8_t *value;
} tuple_t;

typedef struct aws_master_ctx {
    char *id;
    char *region;
    enum service service;
    uint8_t *key;
    size_t chunk_size;
    char *bucket_name;
    char *object_name;
    uint8_t *upload_id;
    // starting from 0
    size_t next_part_number;
} master_ctx_t;

typedef struct aws_request_ctx {
    const master_ctx_t *master;

    // Host
    uint8_t *host;

    // GET|PUT|POST
    enum http_method http_method;

    // Include the leading slash
    uint8_t *resource;

    // Must be sorted by key (as encoded form)
    // Value is nullable
    size_t num_parameters;
    tuple_t *parameters;

    // Tuples whose values are not null should be sorted by key
    // Key should be lowercase, and value should be trimmed
    // Value can be null, and this forbids libcurl to implicitly send the
    // specified header
    size_t num_headers;
    tuple_t *headers;

    // payload (NOT null-terminated)
    uint8_t *payload;
    size_t payload_size;
    uint8_t *payload_sha256;

    // time: YYYYMMDD'\0'
    uint8_t *date;
    // time: 'T'HHMMSS'Z''\0'
    uint8_t *time;
} request_ctx_t;

typedef struct write_ctx {
    uint8_t *buffer;
    // actual buffer size is buffer_size * CURL_WRITE_BUFFER_SIZE
    size_t buffer_size;
    size_t write_idx;
    long response;
    bool curl_success;
} write_ctx_t;

void print_message_(const bool debug, const bool fatal, const char *const file,
                    const int line, const char *const message);
void print_debug_v_(const char *const file, const int line,
                    const char *const format, ...);
uint8_t *service_str(const enum service service);
uint8_t *http_method_str(const enum http_method method);
size_t copy(const uint8_t *const in, uint8_t *const out);
int len(const uint8_t *const in);
size_t uri_encode(const uint8_t *const in, uint8_t *const out,
                  bool encode_slash);
size_t hex(const uint8_t *const in, const size_t in_size, uint8_t *const out);
uint8_t *sha256(const uint8_t *const in, const size_t in_size);
char *authorization_header(const request_ctx_t *const ctx);
write_ctx_t *request(const request_ctx_t *const ctx, CURL *const handle,
                     char **addr_to_etag);
void upload_s3(master_ctx_t *const ctx, CURL *const handle,
               uint8_t *const payload_buffer);
void upload_glacier(master_ctx_t *const ctx, CURL *const handle,
                    uint8_t *const payload_buffer);

extern bool level_debug;

#endif

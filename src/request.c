#include <config.h>
#include <curl/curl.h>

#include "freezer.h"

typedef struct read_ctx {
    uint8_t *payload;
    size_t payload_size;
    size_t read_idx;
} read_ctx_t;

static write_ctx_t *request_(const request_ctx_t *const ctx, CURL *const handle,
                             char **addr_to_headervalue,
                             size_t (*header_callback)(const char *, size_t,
                                                       size_t, char **));
static size_t get_curlopt_url(const request_ctx_t *const ctx,
                              uint8_t *const out);
static char *get_header(const uint8_t *const key, const uint8_t *const value);
static size_t read_callback(char *const buffer, const size_t size,
                            const size_t n_items, read_ctx_t *payload);
static size_t write_callback(const char *const buffer, const size_t size,
                             const size_t nmemb, write_ctx_t *write_ctx);

/**
 * Retry logic
 */
write_ctx_t *request(const request_ctx_t *const ctx, CURL *const handle,
                     char **addr_to_headervalue,
                     size_t (*header_callback)(const char *, size_t, size_t,
                                               char **)) {
    write_ctx_t *recent_trial = NULL;
    for (size_t i = 0; i < NUM_RETRY; i++) {
        if (i != 0) {
            print_error("Retrying...");
        }
        recent_trial =
            request_(ctx, handle, addr_to_headervalue, header_callback);
        if (recent_trial->curl_success &&
            !(recent_trial->response >= 500 && recent_trial->response <= 599)) {
            return recent_trial;
        }
    }
    print_error("Maximum number of trials exceeded");
    return recent_trial;
}

/**
 * Make a request according to the given request context.
 */
static write_ctx_t *request_(const request_ctx_t *const ctx, CURL *const handle,
                             char **addr_to_headervalue,
                             size_t (*header_callback)(const char *, size_t,
                                                       size_t, char **)) {
    curl_easy_reset(handle);
    if (level_debug) {
        const CURLcode verbose_result =
            curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
        if (verbose_result != CURLE_OK) {
            exit_curl(verbose_result);
        }
    }

    const size_t curlopt_url_size = get_curlopt_url(ctx, NULL);
    uint8_t *curlopt_url = calloc(curlopt_url_size + 1, sizeof(uint8_t));
    if (curlopt_url == NULL) {
        exit_errno();
    }
    get_curlopt_url(ctx, curlopt_url);
    const CURLcode curlopt_url_result =
        curl_easy_setopt(handle, CURLOPT_URL, curlopt_url);
    if (curlopt_url_result != CURLE_OK) {
        exit_curl(curlopt_url_result);
    }
    free(curlopt_url);

    char *const authorization_header_str = authorization_header(ctx);
    struct curl_slist *headers =
        curl_slist_append(NULL, authorization_header_str);
    free(authorization_header_str);
    if (headers == NULL) {
        exit_error("curl_slist_append");
    }
    for (size_t i = 0; i < ctx->num_headers; i++) {
        const tuple_t *const header = &ctx->headers[i];
        char *const header_str = get_header(header->key, header->value);
        struct curl_slist *temp = curl_slist_append(headers, header_str);
        free(header_str);
        if (temp == NULL) {
            curl_slist_free_all(headers);
            exit_error("curl_slist_append");
        }
        headers = temp;
    }
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);

    read_ctx_t read_ctx;
    read_ctx.payload = ctx->payload;
    read_ctx.payload_size = ctx->payload_size;
    read_ctx.read_idx = 0;
    const CURLcode readdata_result =
        curl_easy_setopt(handle, CURLOPT_READDATA, &read_ctx);
    if (readdata_result != CURLE_OK) {
        exit_curl(readdata_result);
    }
    const CURLcode readfunc_result =
        curl_easy_setopt(handle, CURLOPT_READFUNCTION, read_callback);
    if (readfunc_result != CURLE_OK) {
        exit_curl(readfunc_result);
    }

    write_ctx_t *const write_ctx = calloc(1, sizeof(write_ctx_t));
    if (write_ctx == NULL) {
        exit_errno();
    }
    write_ctx->buffer = NULL;
    write_ctx->buffer_size = 0;
    write_ctx->write_idx = 0;
    write_ctx->response = -1;
    write_ctx->curl_success = true;
    const CURLcode writedata_result =
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, write_ctx);
    if (writedata_result != CURLE_OK) {
        exit_curl(writedata_result);
    }
    const CURLcode writefunc_result =
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    if (writefunc_result != CURLE_OK) {
        exit_curl(writefunc_result);
    }

    if (header_callback) {
        const CURLcode headerdata_result =
            curl_easy_setopt(handle, CURLOPT_HEADERDATA, addr_to_headervalue);
        if (headerdata_result != CURLE_OK) {
            exit_curl(headerdata_result);
        }
        const CURLcode headerfunc_result =
            curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_callback);
        if (headerfunc_result != CURLE_OK) {
            exit_curl(headerfunc_result);
        }
    }

    // POST
    if (ctx->http_method == post) {
        const CURLcode post_result =
            curl_easy_setopt(handle, CURLOPT_POSTFIELDS, NULL);
        if (post_result != CURLE_OK) {
            exit_curl(post_result);
        }
    }
    // PUT
    if (ctx->http_method == put) {
        const CURLcode put_result =
            curl_easy_setopt(handle, CURLOPT_UPLOAD, 1L);
        if (put_result != CURLE_OK) {
            exit_curl(put_result);
        }
    }

    const CURLcode perform_result = curl_easy_perform(handle);
    if (perform_result != CURLE_OK) {
        print_error("curl_easy_perform error");
        fprintf(stderr, "curl_easy_perform: %s\n",
                curl_easy_strerror(perform_result));
        write_ctx->curl_success = false;
    }
    long response_code = 0;
    const CURLcode info_result =
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
    if (info_result != CURLE_OK) {
        exit_curl(info_result);
    }
    if (write_ctx->buffer != NULL) {
        print_debug("===== BEGIN response =====");
        if (level_debug) {
            for (size_t i = 0; i < write_ctx->write_idx; i++) {
                fputc(write_ctx->buffer[i], stderr);
            }
            fputc('\n', stderr);
        }
        print_debug("===== END response =====");
    }
    if (response_code >= 500 && response_code <= 599) {
        print_error("Response is 5xx");
        fprintf(stderr, "Status code: %ld\n", response_code);
    }
    write_ctx->response = response_code;

    curl_slist_free_all(headers);
    return write_ctx;
}

static size_t get_curlopt_url(const request_ctx_t *const ctx,
                              uint8_t *const out) {
    static const uint8_t *const https = (const uint8_t *const) "https://";

    size_t out_idx = 0;
    out_idx += copy(https, out != NULL ? out + out_idx : NULL);
    out_idx += uri_encode(ctx->host, out != NULL ? out + out_idx : NULL, false);
    out_idx +=
        uri_encode(ctx->resource, out != NULL ? out + out_idx : NULL, false);
    for (size_t i = 0; i < ctx->num_parameters; i++) {
        const tuple_t *const param = &ctx->parameters[i];
        if (out != NULL) {
            out[out_idx] = i == 0 ? '?' : '&';
        }
        out_idx++;
        out_idx +=
            uri_encode(param->key, out != NULL ? out + out_idx : NULL, false);
        if (param->value == NULL) {
            continue;
        }
        if (out != NULL) {
            out[out_idx] = '=';
        }
        out_idx++;
        out_idx +=
            uri_encode(param->value, out != NULL ? out + out_idx : NULL, false);
    }
    return out_idx;
}

/**
 * Concat key and value to create header string
 * It's up to caller to release the allocated buffer
 */
static char *get_header(const uint8_t *const key, const uint8_t *const value) {
    static const uint8_t *const colon = (const uint8_t *const) ":";
    const int length_key = len(key);
    const int length = length_key + 1 + (value != NULL ? len(value) : 0);
    uint8_t *const header = calloc(length + 1, sizeof(uint8_t));
    if (header == NULL) {
        exit_errno();
    }
    copy(key, header);
    copy(colon, header + length_key);
    if (value != NULL) {
        copy(value, header + length_key + 1);
    }
    return (char *const)header;
}

static size_t read_callback(char *const buffer, const size_t size,
                            const size_t n_items, read_ctx_t *read_ctx) {
    if (read_ctx->payload == NULL) {
        return 0;
    }

    const size_t request_size = size * n_items;
    const size_t available = read_ctx->payload_size - read_ctx->read_idx;

    // length to actually read
    const size_t len = request_size < available ? request_size : available;
    memcpy(buffer, read_ctx->payload + read_ctx->read_idx, len);
    read_ctx->read_idx += len;
    return len;
}

static size_t write_callback(const char *const buffer, const size_t size,
                             const size_t nmemb, write_ctx_t *write_ctx) {
    const size_t len = size * nmemb;
    if (len == 0) {
        return 0;
    }

    // the number of bytes already written + the number of bytes to be written
    const size_t total = write_ctx->write_idx + len;
    const size_t buffers_needed =
        (total / CURL_WRITE_BUFFER_SIZE) + !!(total % CURL_WRITE_BUFFER_SIZE);
    if (buffers_needed != write_ctx->buffer_size) {
        write_ctx->buffer =
            realloc(write_ctx->buffer, buffers_needed * CURL_WRITE_BUFFER_SIZE);
        if (write_ctx->buffer == NULL) {
            exit_errno();
        }
    }
    write_ctx->buffer_size = buffers_needed;

    memcpy(write_ctx->buffer + write_ctx->write_idx, buffer, len);
    write_ctx->write_idx += len;
    return len;
}

#include <curl/curl.h>
#include <error.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "freezer.h"

struct etag {
    size_t part_number;
    char *etag;
    struct etag *next;
};

request_ctx_t *s3_ctx_new(const master_ctx_t *const master_ctx,
                          uint8_t *const payload_buffer);
static uint8_t *s3_init(const master_ctx_t *const master_ctx,
                        CURL *const handle, uint8_t *const payload_buffer);
static bool s3_upload(master_ctx_t *const master_ctx, CURL *const handle,
                      uint8_t *const payload_buffer, char **addr_to_etag);
static void s3_complete(master_ctx_t *const master_ctx, CURL *const handle,
                        uint8_t *const payload_buffer,
                        const struct etag *etags);
static void request_ctx_free0(request_ctx_t *const ctx);
static void request_ctx_free1(request_ctx_t *const ctx);
static uint8_t *set_time(request_ctx_t *const ctx);
static bool fill(request_ctx_t *const ctx);

static const uint8_t *const header_accept = (uint8_t *)"accept";
static const uint8_t *const header_user_agent = (uint8_t *)"user-agent";
static const uint8_t *const header_expect = (uint8_t *)"expect";
static const uint8_t *const header_content_type = (uint8_t *)"content-type";
static const uint8_t *const header_bin = (uint8_t *)"binary/octet-stream";
static const uint8_t *const header_content_length = (uint8_t *)"content-length";
static const uint8_t *const header_0 = (uint8_t *)"0";
static const uint8_t *const header_host = (uint8_t *)"host";
static const uint8_t *const header_x_sha256 = (uint8_t *)"x-amz-content-sha256";
static const uint8_t *const header_x_date = (uint8_t *)"x-amz-date";
static const uint8_t *const header_transfer_encoding =
    (uint8_t *)"transfer-encoding";

void upload_s3(master_ctx_t *const ctx, CURL *const handle,
               uint8_t *const payload_buffer) {
    struct etag *first = NULL;
    struct etag *last = NULL;
    ctx->upload_id = s3_init(ctx, handle, payload_buffer);
    char *addr_to_etag = NULL;
    while (true) {
        const bool to_continue =
            s3_upload(ctx, handle, payload_buffer, &addr_to_etag);
        if (addr_to_etag == NULL) {
            // This happens when STDIN gives nothing but EOF
            break;
        }
        struct etag *new = calloc(1, sizeof(struct etag));
        if (new == NULL) {
            exit_errno();
        }
        new->part_number = ctx->next_part_number;
        new->etag = addr_to_etag;
        addr_to_etag = NULL;
        new->next = NULL;
        if (first == NULL) {
            first = new;
        } else {
            last->next = new;
        }
        last = new;
        ctx->next_part_number++;
        if (!to_continue) {
            break;
        }
    }
    s3_complete(ctx, handle, payload_buffer, first);

    struct etag *next_etag = NULL;
    for (struct etag *etag = first; etag != NULL; etag = next_etag) {
        free(etag->etag);
        next_etag = etag->next;
        free(etag);
    }
    free(ctx->upload_id);
}

request_ctx_t *s3_ctx_new(const master_ctx_t *const master_ctx,
                          uint8_t *const payload_buffer) {
    static const uint8_t *const host_suffix =
        (const uint8_t *const) ".s3.amazonaws.com";
    request_ctx_t *const ctx = calloc(1, sizeof(request_ctx_t));
    if (ctx == NULL) {
        exit_errno();
    }
    ctx->master = master_ctx;
    const int bucket_name_len =
        len((const uint8_t *const)master_ctx->bucket_name);
    ctx->host = calloc(bucket_name_len + len(host_suffix) + 1, sizeof(uint8_t));
    if (ctx->host == NULL) {
        exit_errno();
    }
    copy((const uint8_t *const)master_ctx->bucket_name, ctx->host);
    copy(host_suffix, ctx->host + bucket_name_len);
    ctx->resource =
        calloc(1 + len((const uint8_t *const)master_ctx->object_name) + 1,
               sizeof(uint8_t));
    if (ctx->resource == NULL) {
        exit_errno();
    }
    ctx->resource[0] = '/';
    copy((const uint8_t *const)master_ctx->object_name, ctx->resource + 1);
    ctx->payload = payload_buffer;
    return ctx;
}

static uint8_t *s3_init(const master_ctx_t *const master_ctx,
                        CURL *const handle, uint8_t *const payload_buffer) {
    static const size_t num_params = 1;
    static const size_t num_headers = 9;

    request_ctx_t *const ctx = s3_ctx_new(master_ctx, payload_buffer);
    ctx->http_method = post;

    ctx->num_parameters = num_params;
    ctx->parameters = calloc(num_params, sizeof(tuple_t));
    if (ctx->parameters == NULL) {
        exit_errno();
    }
    ctx->parameters[0].key = (uint8_t *)"uploads";

    ctx->num_headers = num_headers;
    ctx->headers = calloc(num_headers, sizeof(tuple_t));
    if (ctx->headers == NULL) {
        exit_errno();
    }
    ctx->payload_sha256 = sha256(ctx->payload, ctx->payload_size);
    uint8_t *const sha256_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (sha256_hex == NULL) {
        exit_errno();
    }
    hex(ctx->payload_sha256, SHA256_BYTES, sha256_hex);
    uint8_t *const x_date_value = set_time(ctx);
    ctx->headers[0].key = header_accept;
    ctx->headers[1].key = header_user_agent;
    ctx->headers[2].key = header_expect;
    ctx->headers[3].key = header_transfer_encoding;
    ctx->headers[4].key = header_content_length;
    ctx->headers[4].value = header_0;
    ctx->headers[5].key = header_content_type;
    ctx->headers[5].value = header_bin;
    ctx->headers[6].key = header_host;
    ctx->headers[6].value = ctx->host;
    ctx->headers[7].key = header_x_sha256;
    ctx->headers[7].value = sha256_hex;
    ctx->headers[8].key = header_x_date;
    ctx->headers[8].value = x_date_value;

    write_ctx_t *const result = request(ctx, handle, NULL);
    if (result->response != 200) {
        error(1, 0, "Cannot initiate multipart upload: %ld", result->response);
    }
    if (result->buffer == NULL) {
        exit_error("Response is null");
    }
    const xmlDocPtr doc =
        xmlReadMemory((const char *const)result->buffer, result->write_idx,
                      "response.xml", NULL, 0);
    if (doc == NULL) {
        exit_error("Failed to parse the respones");
    }
    uint8_t *upload_id = NULL;
    const xmlNodePtr xmlRoot = xmlDocGetRootElement(doc);
    for (xmlNodePtr node = xmlRoot->children; node; node = node->next) {
        if (!xmlStrEqual((xmlChar *)"UploadId", node->name)) {
            continue;
        }
        xmlChar *const content = xmlNodeGetContent(node);
        const int len = xmlStrlen(content);
        upload_id = calloc(len + 1, sizeof(uint8_t));
        if (upload_id == NULL) {
            exit_errno();
        }
        memcpy(upload_id, content, len);
        xmlFree(content);
        break;
    }
    if (upload_id == NULL) {
        exit_error("UploadId not given");
    }
    xmlFreeDoc(doc);

    print_debug("===== BEGIN response =====");
    if (level_debug) {
        for (size_t i = 0; i < result->write_idx; i++) {
            fputc(result->buffer[i], stderr);
        }
        fputc('\n', stderr);
    }
    print_debug("===== response =====");
    print_debugv("Using UploadId %s", upload_id);
    free(result->buffer);
    free(result);
    free(sha256_hex);
    free(x_date_value);
    request_ctx_free0(ctx);
    request_ctx_free1(ctx);
    return upload_id;
}

static bool s3_upload(master_ctx_t *const master_ctx, CURL *const handle,
                      uint8_t *const payload_buffer, char **addr_to_etag) {
    static const size_t num_params = 2;
    static const size_t num_headers = 9;
    static const size_t partNumber_length = 20;
    static const size_t content_size_length = 100;

    request_ctx_t *const ctx = s3_ctx_new(master_ctx, payload_buffer);
    print_debugv("Trying to fill for #%zu...",
                 ctx->master->next_part_number + 1);
    const bool to_continue = fill(ctx);
    if (ctx->payload_size == 0) {
        request_ctx_free1(ctx);
        return to_continue;
    }

    ctx->http_method = put;

    ctx->num_parameters = num_params;
    ctx->parameters = calloc(num_params, sizeof(tuple_t));
    if (ctx->parameters == NULL) {
        exit_errno();
    }
    uint8_t *const part_number_str = calloc(partNumber_length, sizeof(uint8_t));
    if (part_number_str == NULL) {
        exit_errno();
    }
    snprintf((char *)part_number_str, partNumber_length, "%zu",
             ctx->master->next_part_number + 1);
    ctx->parameters[0].key = (uint8_t *)"partNumber";
    ctx->parameters[0].value = part_number_str;
    ctx->parameters[1].key = (uint8_t *)"uploadId";
    ctx->parameters[1].value = ctx->master->upload_id;

    ctx->num_headers = num_headers;
    ctx->headers = calloc(num_headers, sizeof(tuple_t));
    if (ctx->headers == NULL) {
        exit_errno();
    }
    ctx->payload_sha256 = sha256(ctx->payload, ctx->payload_size);
    uint8_t *const sha256_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (sha256_hex == NULL) {
        exit_errno();
    }
    hex(ctx->payload_sha256, SHA256_BYTES, sha256_hex);
    uint8_t *const content_size_str =
        calloc(content_size_length, sizeof(uint8_t));
    if (content_size_str == NULL) {
        exit_errno();
    }
    snprintf((char *)content_size_str, content_size_length, "%zu",
             ctx->payload_size);
    uint8_t *const x_date_value = set_time(ctx);
    ctx->headers[0].key = header_accept;
    ctx->headers[1].key = header_user_agent;
    ctx->headers[2].key = header_expect;
    ctx->headers[3].key = header_transfer_encoding;
    ctx->headers[4].key = header_content_length;
    ctx->headers[4].value = content_size_str;
    ctx->headers[5].key = header_content_type;
    ctx->headers[5].value = header_bin;
    ctx->headers[6].key = header_host;
    ctx->headers[6].value = ctx->host;
    ctx->headers[7].key = header_x_sha256;
    ctx->headers[7].value = sha256_hex;
    ctx->headers[8].key = header_x_date;
    ctx->headers[8].value = x_date_value;

    write_ctx_t *const result = request(ctx, handle, addr_to_etag);
    if (result->response != 200) {
        error(1, 0, "Failed to upload: %ld", result->response);
    }
    if (result->buffer != NULL) {
        print_debug("===== BEGIN response =====");
        if (level_debug) {
            for (size_t i = 0; i < result->write_idx; i++) {
                fputc(result->buffer[i], stderr);
            }
            fputc('\n', stderr);
        }
        print_debug("===== END response =====");
        free(result->buffer);
    }

    fprintf(stderr, "#%zu\tsha256=%s\tsize=%s\n",
            master_ctx->next_part_number + 1, sha256_hex, content_size_str);

    free(result);
    free(part_number_str);
    free(content_size_str);
    free(sha256_hex);
    free(x_date_value);
    request_ctx_free0(ctx);
    request_ctx_free1(ctx);
    return to_continue;
}

static void request_ctx_free0(request_ctx_t *const ctx) {
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
}

static void request_ctx_free1(request_ctx_t *const ctx) {
    free(ctx->host);
    free(ctx->resource);
    if (ctx->parameters != NULL) {
        free(ctx->parameters);
    }
    if (ctx->headers != NULL) {
        free(ctx->headers);
    }
    free(ctx);
}

void upload_glacier(master_ctx_t *const ctx, CURL *const handle,
                    uint8_t *const payload_buffer) {
}

/**
 * Set date and time by mutating the given context,
 * while returning time that can be used as x-amz-date.
 * It's up to the caller to release the allocated buffers.
 */
static uint8_t *set_time(request_ctx_t *const ctx) {
    static const char *const format_date = "%04d%02d%02d";
    static const char *const format_time = "T%02d%02d%02dZ";
    static const char *const format_all = "%04d%02d%02dT%02d%02d%02dZ";
    static const size_t size = 100;

    const time_t t = time(NULL);
    // WARNING gmtime is not thread-safe
    const struct tm *const tm = gmtime(&t);
    int year = tm->tm_year + 1900;
    int month = tm->tm_mon + 1;

    ctx->date = calloc(size, sizeof(uint8_t));
    if (ctx->date == NULL) {
        exit_errno();
    }
    snprintf((char *)ctx->date, size, format_date, year, month, tm->tm_mday);
    ctx->time = calloc(size, sizeof(uint8_t));
    if (ctx->time == NULL) {
        exit_errno();
    }
    snprintf((char *)ctx->time, size, format_time, tm->tm_hour, tm->tm_min,
             tm->tm_sec);
    uint8_t *amz_date = calloc(size, sizeof(uint8_t));
    if (amz_date == NULL) {
        exit_errno();
    }
    snprintf((char *)amz_date, size, format_all, year, month, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
    return amz_date;
}

static void s3_complete(master_ctx_t *const master_ctx, CURL *const handle,
                        uint8_t *const payload_buffer,
                        const struct etag *etags) {
    static const char *const chunk_small_message =
        "Chunk size too small to send completion message.";
    static const size_t num_params = 1;
    static const size_t num_headers = 9;
    static const size_t content_size_length = 100;

    request_ctx_t *const ctx = s3_ctx_new(master_ctx, payload_buffer);

    // begin prepare contents

    const int payload_prelude =
        snprintf((char *)ctx->payload + ctx->payload_size,
                 ctx->master->chunk_size - ctx->payload_size,
                 "<CompleteMultipartUpload>");
    if (ctx->payload_size + payload_prelude > ctx->master->chunk_size) {
        exit_error(chunk_small_message);
    }
    ctx->payload_size += payload_prelude;

    for (const struct etag *etag = etags; etag != NULL; etag = etag->next) {
        const int payload_part =
            snprintf((char *)ctx->payload + ctx->payload_size,
                     ctx->master->chunk_size - ctx->payload_size,
                     "<Part><PartNumber>%zu</PartNumber><ETag>%s</ETag></Part>",
                     etag->part_number + 1, etag->etag);
        if (ctx->payload_size + payload_part > ctx->master->chunk_size) {
            exit_error(chunk_small_message);
        }
        ctx->payload_size += payload_part;
    }

    const int payload_epilogue =
        snprintf((char *)ctx->payload + ctx->payload_size,
                 ctx->master->chunk_size - ctx->payload_size,
                 "</CompleteMultipartUpload>");
    if (ctx->payload_size + payload_epilogue > ctx->master->chunk_size) {
        exit_error(chunk_small_message);
    }
    ctx->payload_size += payload_epilogue;

    // end prepare contents
    print_debug("===== BEGIN request =====");
    if (level_debug) {
        for (size_t i = 0; i < ctx->payload_size; i++) {
            fputc(ctx->payload[i], stderr);
        }
        fputc('\n', stderr);
    }
    print_debug("===== END request =====");

    ctx->http_method = post;

    ctx->num_parameters = num_params;
    ctx->parameters = calloc(num_params, sizeof(tuple_t));
    if (ctx->parameters == NULL) {
        exit_errno();
    }
    ctx->parameters[0].key = (uint8_t *)"uploadId";
    ctx->parameters[0].value = ctx->master->upload_id;

    ctx->num_headers = num_headers;
    ctx->headers = calloc(num_headers, sizeof(tuple_t));
    if (ctx->headers == NULL) {
        exit_errno();
    }
    ctx->payload_sha256 = sha256(ctx->payload, ctx->payload_size);
    uint8_t *const sha256_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (sha256_hex == NULL) {
        exit_errno();
    }
    hex(ctx->payload_sha256, SHA256_BYTES, sha256_hex);
    uint8_t *const content_size_str =
        calloc(content_size_length, sizeof(uint8_t));
    if (content_size_str == NULL) {
        exit_errno();
    }
    snprintf((char *)content_size_str, content_size_length, "%zu",
             ctx->payload_size);
    uint8_t *const x_date_value = set_time(ctx);
    ctx->headers[0].key = header_accept;
    ctx->headers[1].key = header_user_agent;
    ctx->headers[2].key = header_expect;
    ctx->headers[3].key = header_transfer_encoding;
    ctx->headers[4].key = header_content_length;
    ctx->headers[4].value = content_size_str;
    ctx->headers[5].key = header_content_type;
    ctx->headers[5].value = header_bin;
    ctx->headers[6].key = header_host;
    ctx->headers[6].value = ctx->host;
    ctx->headers[7].key = header_x_sha256;
    ctx->headers[7].value = sha256_hex;
    ctx->headers[8].key = header_x_date;
    ctx->headers[8].value = x_date_value;

    write_ctx_t *const result = request(ctx, handle, NULL);
    if (result->response != 200) {
        error(1, 0, "Failed to complete: %ld", result->response);
    }
    if (result->buffer != NULL) {
        print_debug("===== BEGIN response =====");
        if (level_debug) {
            for (size_t i = 0; i < result->write_idx; i++) {
                fputc(result->buffer[i], stderr);
            }
            fputc('\n', stderr);
        }
        print_debug("===== END response =====");
        free(result->buffer);
    }

    fprintf(stderr, "Done.\n");

    free(result);
    free(content_size_str);
    free(sha256_hex);
    free(x_date_value);
    request_ctx_free0(ctx);
    request_ctx_free1(ctx);
}

/**
 * Reads from STDIN to fill the buffer.
 * Returns false if it met EOF
 */
static bool fill(request_ctx_t *const ctx) {
    size_t payload_size = 0;
    const size_t buffer_size = ctx->master->chunk_size;

    while (payload_size < buffer_size) {
        const size_t room = buffer_size - payload_size;
        ssize_t read_result =
            read(STDIN_FILENO, ctx->payload + payload_size, room);
        if (read_result == -1) {
            exit_errno();
            return false;
        }
        if (read_result == 0) {
            ctx->payload_size = payload_size;
            return false;
        }
        payload_size += read_result;
    }
    ctx->payload_size = payload_size;
    return true;
}

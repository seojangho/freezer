#include <curl/curl.h>
#include <error.h>
#include <inttypes.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "freezer.h"

#define MAX_NUM_PARTS 10000

struct etag {
    size_t part_number;
    char *etag;
    struct etag *next;
};

static request_ctx_t *s3_ctx_new(const master_ctx_t *const master_ctx,
                                 uint8_t *const payload_buffer);
static void s3_request_ctx_free(request_ctx_t *const ctx);
static uint8_t *s3_init(const master_ctx_t *const master_ctx,
                        CURL *const handle, uint8_t *const payload_buffer);
static bool s3_upload(master_ctx_t *const master_ctx, CURL *const handle,
                      uint8_t *const payload_buffer, char **addr_to_etag);
static void s3_complete(master_ctx_t *const master_ctx, CURL *const handle,
                        uint8_t *const payload_buffer,
                        const struct etag *etags);

static request_ctx_t *glacier_ctx_new(const master_ctx_t *const master_ctx,
                                      uint8_t *const payload_buffer);
static void glacier_request_ctx_free(request_ctx_t *const ctx);
static uint8_t *glacier_endpoint_multipart(const master_ctx_t *const ctx);
static uint8_t *glacier_endpoint_uploadid(const master_ctx_t *const ctx);
static void glacier_init(const master_ctx_t *const master_ctx,
                         CURL *const handle, uint8_t *const payload_buffer,
                         uint8_t **addr_to_uploadid);
static bool glacier_upload(const master_ctx_t *const master_ctx,
                           CURL *const handle, uint8_t *const payload_buffer,
                           size_t *payload_size, uint8_t *th_buffer,
                           uint8_t *addr_to_th);
static void glacier_complete(const master_ctx_t *const master_ctx,
                             CURL *const handle, uint8_t *const payload_buffer,
                             const uint64_t total_bytes,
                             const uint8_t *const th);

static uint8_t *set_time(request_ctx_t *const ctx);
static bool fill(request_ctx_t *const ctx);
static void tree_hash(uint8_t buffer[][SHA256_BYTES], const size_t in_size);
static void tree_hash_(uint8_t buffer[][SHA256_BYTES], const size_t in_size);
void tree_hash_sha256(const uint8_t in0[SHA256_BYTES],
                      const uint8_t in1[SHA256_BYTES], uint8_t *const out);

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
static const uint8_t *const header_x_part_size = (uint8_t *)"x-amz-part-size";
static const uint8_t *const header_x_archive_desc =
    (uint8_t *)"x-amz-archive-description";
static const uint8_t *const header_x_tree_hash =
    (uint8_t *)"x-amz-sha256-tree-hash";
static const uint8_t *const header_content_range = (uint8_t *)"content-range";
static const uint8_t *const header_x_archive_size =
    (uint8_t *)"x-amz-archive-size";
static const uint8_t *const header_glacier_version =
    (uint8_t *)"x-amz-glacier-version";
static const uint8_t *const header_glacier_version_value =
    (uint8_t *)"2012-06-01";

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

static request_ctx_t *s3_ctx_new(const master_ctx_t *const master_ctx,
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

    write_ctx_t *const result = request(ctx, handle, NULL, NULL);
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

    print_debugv("Using UploadId %s", upload_id);
    free(result->buffer);
    free(result);
    free(sha256_hex);
    free(x_date_value);
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
    s3_request_ctx_free(ctx);
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
        s3_request_ctx_free(ctx);
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

    write_ctx_t *const result =
        request(ctx, handle, addr_to_etag, header_callback_etag);
    if (result->response != 200) {
        error(1, 0, "Failed to upload: %ld", result->response);
    }

    fprintf(stderr, "#%zu\tsha256=%s\tsize=%s\n",
            master_ctx->next_part_number + 1, sha256_hex, content_size_str);

    if (result->buffer != NULL) {
        free(result->buffer);
    }
    free(result);
    free(part_number_str);
    free(content_size_str);
    free(sha256_hex);
    free(x_date_value);
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
    s3_request_ctx_free(ctx);
    return to_continue;
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

    write_ctx_t *const result = request(ctx, handle, NULL, NULL);
    if (result->response != 200) {
        error(1, 0, "Failed to complete: %ld", result->response);
    }

    fprintf(stderr, "Done.\n");

    if (result->buffer != NULL) {
        free(result->buffer);
    }
    free(result);
    free(content_size_str);
    free(sha256_hex);
    free(x_date_value);
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
    s3_request_ctx_free(ctx);
}

static void s3_request_ctx_free(request_ctx_t *const ctx) {
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
    // Buffer to compute tree hash for each upload part
    uint8_t *const th_buffer = calloc(ctx->chunk_size / ONE_MEGA, SHA256_BYTES);
    if (th_buffer == NULL) {
        exit_errno();
    }
    // Buffer to store tree hashes
    uint8_t th[MAX_NUM_PARTS][SHA256_BYTES];

    uint8_t *upload_id = NULL;
    glacier_init(ctx, handle, payload_buffer, &upload_id);
    ctx->upload_id = upload_id;

    size_t recent_payload_size = 0;
    uint64_t total_bytes = 0;
    while (true) {
        const bool to_continue =
            glacier_upload(ctx, handle, payload_buffer, &recent_payload_size,
                           th_buffer, th[ctx->next_part_number]);
        if (recent_payload_size == 0) {
            break;
        }
        total_bytes += recent_payload_size;
        ctx->next_part_number++;
        if (!to_continue) {
            break;
        }
    }
    const size_t num_parts = ctx->next_part_number;
    tree_hash(th, num_parts);
    glacier_complete(ctx, handle, payload_buffer, total_bytes, th[0]);

    free(th_buffer);
    free(ctx->upload_id);
}

static request_ctx_t *glacier_ctx_new(const master_ctx_t *const master_ctx,
                                      uint8_t *const payload_buffer) {
    static const char *const host_prefix = "glacier.";
    static const char *const host_suffix = ".amazonaws.com";

    request_ctx_t *const ctx = calloc(1, sizeof(request_ctx_t));
    if (ctx == NULL) {
        exit_errno();
    }
    ctx->master = master_ctx;

    const size_t host_prefix_len = strlen(host_prefix);
    const size_t region_len = strlen(master_ctx->region);
    ctx->host = calloc(host_prefix_len + region_len + strlen(host_suffix) + 1,
                       sizeof(uint8_t));
    if (ctx->host == NULL) {
        exit_errno();
    }
    copy((uint8_t *)host_prefix, ctx->host);
    copy((uint8_t *)master_ctx->region, ctx->host + host_prefix_len);
    copy((uint8_t *)host_suffix, ctx->host + host_prefix_len + region_len);

    ctx->payload = payload_buffer;
    return ctx;
}

static void glacier_request_ctx_free(request_ctx_t *const ctx) {
    free(ctx->host);
    if (ctx->parameters != NULL) {
        free(ctx->parameters);
    }
    if (ctx->headers != NULL) {
        free(ctx->headers);
    }
    free(ctx);
}

static uint8_t *glacier_endpoint_multipart(const master_ctx_t *const ctx) {
    static const char *const f1 = "/-/vaults/";
    static const char *const f2 = "/multipart-uploads";
    const size_t f1_len = strlen(f1);
    const size_t f2_len = strlen(f2);
    const size_t vault_len = strlen(ctx->bucket_name);

    char *const str = calloc(f1_len + vault_len + f2_len + 1, sizeof(char));
    if (str == NULL) {
        exit_errno();
    }
    copy((uint8_t *)f1, (uint8_t *)str);
    copy((uint8_t *)ctx->bucket_name, (uint8_t *)str + f1_len);
    copy((uint8_t *)f2, (uint8_t *)str + f1_len + vault_len);
    return (uint8_t *)str;
}

static uint8_t *glacier_endpoint_uploadid(const master_ctx_t *const ctx) {
    uint8_t *uploads = glacier_endpoint_multipart(ctx);
    const size_t uploads_len = len(uploads);
    const size_t uploadid_len = len(ctx->upload_id);
    char *const str = calloc(uploads_len + 1 + uploadid_len + 1, sizeof(char));
    if (str == NULL) {
        exit_errno();
    }
    copy(uploads, (uint8_t *)str);
    copy((uint8_t *)"/", (uint8_t *)str + uploads_len);
    copy(ctx->upload_id, (uint8_t *)str + uploads_len + 1);
    free(uploads);
    return (uint8_t *)str;
}

static void glacier_init(const master_ctx_t *const master_ctx,
                         CURL *const handle, uint8_t *const payload_buffer,
                         uint8_t **addr_to_uploadid) {
    static const size_t num_headers = 12;
    static const size_t part_size_str_maxlen = 100;

    request_ctx_t *const ctx = glacier_ctx_new(master_ctx, payload_buffer);
    ctx->http_method = post;
    ctx->resource = glacier_endpoint_multipart(master_ctx);
    ctx->num_parameters = 0;

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
    uint8_t *const part_size_str =
        calloc(part_size_str_maxlen, sizeof(uint8_t));
    if (part_size_str == NULL) {
        exit_errno();
    }
    snprintf((char *)part_size_str, part_size_str_maxlen, "%zu",
             ctx->master->chunk_size);
    ctx->headers[0].key = header_accept;
    ctx->headers[1].key = header_user_agent;
    ctx->headers[2].key = header_expect;
    ctx->headers[3].key = header_transfer_encoding;
    ctx->headers[4].key = header_content_length;
    ctx->headers[5].key = header_content_type;
    ctx->headers[6].key = header_host;
    ctx->headers[6].value = ctx->host;
    ctx->headers[7].key = header_x_archive_desc;
    ctx->headers[7].value = (uint8_t *)ctx->master->object_name;
    ctx->headers[8].key = header_x_sha256;
    ctx->headers[8].value = sha256_hex;
    ctx->headers[9].key = header_x_date;
    ctx->headers[9].value = x_date_value;
    ctx->headers[10].key = header_glacier_version;
    ctx->headers[10].value = header_glacier_version_value;
    ctx->headers[11].key = header_x_part_size;
    ctx->headers[11].value = part_size_str;

    write_ctx_t *const result = request(ctx, handle, (char **)addr_to_uploadid,
                                        header_callback_uploadid);
    if (result->response != 201) {
        error(1, 0, "Cannot initiate multipart upload: %ld", result->response);
    }
    print_debugv("Using UploadId %s", (char *)*addr_to_uploadid);

    if (result->buffer != NULL) {
        free(result->buffer);
    }
    free(result);
    free(part_size_str);
    free(sha256_hex);
    free(x_date_value);
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
    free(ctx->resource);
    glacier_request_ctx_free(ctx);
}

static bool glacier_upload(const master_ctx_t *const master_ctx,
                           CURL *const handle, uint8_t *const payload_buffer,
                           size_t *payload_size, uint8_t *th_buffer,
                           uint8_t *addr_to_th) {
    static const size_t num_headers = 12;
    static const size_t header_length = 100;

    request_ctx_t *const ctx = glacier_ctx_new(master_ctx, payload_buffer);
    print_debugv("Trying to fill for #%zu...",
                 ctx->master->next_part_number + 1);
    const bool to_continue = fill(ctx);
    *payload_size = ctx->payload_size;
    if (ctx->payload_size == 0) {
        glacier_request_ctx_free(ctx);
        return to_continue;
    }

    // tree-hash calculation
    EVP_MD_CTX *const evp = EVP_MD_CTX_new();
    if (evp == NULL) {
        exit_openssl();
    }
    size_t onemega_chunk_idx = 0;
    for (;; onemega_chunk_idx++) {
        const size_t start = onemega_chunk_idx * ONE_MEGA;
        const size_t next_start = (onemega_chunk_idx + 1) * ONE_MEGA;
        const size_t size = ctx->payload_size - start < ONE_MEGA
                                ? ctx->payload_size - start
                                : ONE_MEGA;
        if (EVP_DigestInit_ex(evp, EVP_sha256(), NULL) == 0) {
            exit_openssl();
        }
        if (EVP_DigestUpdate(evp, ctx->payload + start, size) == 0) {
            exit_openssl();
        }
        if (EVP_DigestFinal_ex(
                evp, th_buffer + onemega_chunk_idx * SHA256_BYTES, NULL) == 0) {
            exit_openssl();
        }

        if (next_start >= ctx->payload_size) {
            break;
        }
        EVP_MD_CTX_reset(evp);
    }
    EVP_MD_CTX_free(evp);
    const size_t num_onemega_chunks = onemega_chunk_idx + 1;
    tree_hash((uint8_t(*)[SHA256_BYTES])th_buffer, num_onemega_chunks);
    memcpy(addr_to_th, th_buffer, SHA256_BYTES);

    ctx->http_method = put;
    ctx->resource = glacier_endpoint_uploadid(master_ctx);
    ctx->num_parameters = 0;

    ctx->num_headers = num_headers;
    ctx->headers = calloc(num_headers, sizeof(tuple_t));
    if (ctx->headers == NULL) {
        exit_errno();
    }
    const uint64_t range_start =
        master_ctx->chunk_size * master_ctx->next_part_number;
    const uint64_t range_end = range_start + ctx->payload_size - 1;
    uint8_t *const content_range_str = calloc(header_length, sizeof(uint8_t));
    if (content_range_str == NULL) {
        exit_errno();
    }
    snprintf((char *)content_range_str, header_length,
             "bytes %" PRIu64 "-%" PRIu64 "/*", range_start, range_end);
    ctx->payload_sha256 = sha256(ctx->payload, ctx->payload_size);
    uint8_t *const sha256_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (sha256_hex == NULL) {
        exit_errno();
    }
    hex(ctx->payload_sha256, SHA256_BYTES, sha256_hex);
    uint8_t *const x_date_value = set_time(ctx);
    uint8_t *const th_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (th_hex == NULL) {
        exit_errno();
    }
    hex(addr_to_th, SHA256_BYTES, th_hex);
    uint8_t *const content_size_str = calloc(header_length, sizeof(uint8_t));
    if (content_size_str == NULL) {
        exit_errno();
    }
    snprintf((char *)content_size_str, header_length, "%zu", ctx->payload_size);
    ctx->headers[0].key = header_accept;
    ctx->headers[1].key = header_user_agent;
    ctx->headers[2].key = header_expect;
    ctx->headers[3].key = header_transfer_encoding;
    ctx->headers[4].key = header_content_length;
    ctx->headers[4].value = content_size_str;
    ctx->headers[5].key = header_content_range;
    ctx->headers[5].value = content_range_str;
    ctx->headers[6].key = header_content_type;
    ctx->headers[6].value = header_bin;
    ctx->headers[7].key = header_host;
    ctx->headers[7].value = ctx->host;
    ctx->headers[8].key = header_x_sha256;
    ctx->headers[8].value = sha256_hex;
    ctx->headers[9].key = header_x_date;
    ctx->headers[9].value = x_date_value;
    ctx->headers[10].key = header_glacier_version;
    ctx->headers[10].value = header_glacier_version_value;
    ctx->headers[11].key = header_x_tree_hash;
    ctx->headers[11].value = th_hex;

    write_ctx_t *const result = request(ctx, handle, NULL, NULL);
    if (result->response != 204) {
        error(1, 0, "Failed to upload: %ld", result->response);
    }
    fprintf(stderr, "#%zu\tsha256=%s\ttree_sha256=%s\n",
            master_ctx->next_part_number + 1, sha256_hex, th_hex);

    if (result->buffer != NULL) {
        free(result->buffer);
    }
    free(result);
    free(content_size_str);
    free(content_range_str);
    free(sha256_hex);
    free(th_hex);
    free(x_date_value);
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
    free(ctx->resource);
    glacier_request_ctx_free(ctx);
    return to_continue;
}

static void glacier_complete(const master_ctx_t *const master_ctx,
                             CURL *const handle, uint8_t *const payload_buffer,
                             const uint64_t total_bytes,
                             const uint8_t *const th) {
    static const size_t num_headers = 13;
    static const size_t str_maxlen = 100;

    request_ctx_t *const ctx = glacier_ctx_new(master_ctx, payload_buffer);
    ctx->http_method = post;
    ctx->resource = glacier_endpoint_uploadid(master_ctx);
    ctx->num_parameters = 0;

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
    uint8_t *const archive_size_str = calloc(str_maxlen, sizeof(uint8_t));
    if (archive_size_str == NULL) {
        exit_errno();
    }
    snprintf((char *)archive_size_str, str_maxlen, "%" PRIu64, total_bytes);
    uint8_t *const th_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (th_hex == NULL) {
        exit_errno();
    }
    hex(th, SHA256_BYTES, th_hex);
    uint8_t *const part_size_str = calloc(str_maxlen, sizeof(uint8_t));
    if (part_size_str == NULL) {
        exit_errno();
    }
    snprintf((char *)part_size_str, str_maxlen, "%zu", ctx->master->chunk_size);
    ctx->headers[0].key = header_accept;
    ctx->headers[1].key = header_user_agent;
    ctx->headers[2].key = header_expect;
    ctx->headers[3].key = header_transfer_encoding;
    ctx->headers[4].key = header_content_length;
    ctx->headers[5].key = header_content_type;
    ctx->headers[6].key = header_host;
    ctx->headers[6].value = ctx->host;
    ctx->headers[7].key = header_x_archive_size;
    ctx->headers[7].value = archive_size_str;
    ctx->headers[8].key = header_x_sha256;
    ctx->headers[8].value = sha256_hex;
    ctx->headers[9].key = header_x_date;
    ctx->headers[9].value = x_date_value;
    ctx->headers[10].key = header_glacier_version;
    ctx->headers[10].value = header_glacier_version_value;
    ctx->headers[11].key = header_x_part_size;
    ctx->headers[11].value = part_size_str;
    ctx->headers[12].key = header_x_tree_hash;
    ctx->headers[12].value = th_hex;

    char *addr_to_location = NULL;
    write_ctx_t *const result =
        request(ctx, handle, &addr_to_location, header_callback_location);
    if (result->response != 201) {
        error(1, 0, "Failed to complete: %ld", result->response);
    }
    if (result->buffer != NULL) {
        free(result->buffer);
    }

    fprintf(stderr, "location=%s\n", addr_to_location);
    fprintf(stderr, "archive_tree_hash_sha256=%s\n", th_hex);
    fprintf(stderr, "archive_size=%s\n", archive_size_str);
    fprintf(stdout, "%s\n", addr_to_location);
    free(addr_to_location);
    free(result);
    free(part_size_str);
    free(archive_size_str);
    free(th_hex);
    free(sha256_hex);
    free(x_date_value);
    free(ctx->payload_sha256);
    free(ctx->date);
    free(ctx->time);
    free(ctx->resource);
    glacier_request_ctx_free(ctx);
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

static void tree_hash(uint8_t buffer[][SHA256_BYTES], const size_t in_size) {
    if (in_size < 1) {
        exit_error("tree_hash: empty input");
        return;
    }

    size_t size = in_size;
    while (size != 1) {
        tree_hash_(buffer, size);
        size = size / 2 + size % 2;
    }
}

static void tree_hash_(uint8_t buffer[][SHA256_BYTES], const size_t in_size) {
    const size_t out_size = in_size / 2 + in_size % 2;
    for (size_t i = 0; i < out_size; i++) {
        const size_t in0_idx = i * 2;
        const size_t in1_idx = in0_idx + 1;
        if (in1_idx < in_size) {
            tree_hash_sha256(buffer[in0_idx], buffer[in1_idx], buffer[i]);
        } else {
            memcpy(buffer[i], buffer[in0_idx], SHA256_BYTES);
        }
    }
}

void tree_hash_sha256(const uint8_t in0[SHA256_BYTES],
                      const uint8_t in1[SHA256_BYTES], uint8_t *const out) {
    uint8_t *tree_hash =
        in0 != out ? out : calloc(SHA256_BYTES, sizeof(uint8_t));
    if (tree_hash == NULL) {
        exit_errno();
    }
    EVP_MD_CTX *const ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        exit_openssl();
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 0) {
        exit_openssl();
    }
    if (EVP_DigestUpdate(ctx, in0, SHA256_BYTES) == 0) {
        exit_openssl();
    }
    if (EVP_DigestUpdate(ctx, in1, SHA256_BYTES) == 0) {
        exit_openssl();
    }
    if (EVP_DigestFinal_ex(ctx, tree_hash, NULL) == 0) {
        exit_openssl();
    }
    EVP_MD_CTX_free(ctx);
    if (in0 == out) {
        // tree_hash != out
        memcpy(out, tree_hash, SHA256_BYTES);
        free(tree_hash);
    }
}

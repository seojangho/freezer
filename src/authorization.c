#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "freezer.h"

static size_t authorization_header_(const request_ctx_t *const ctx,
                                    uint8_t *const out);
static uint8_t *signature(const request_ctx_t *const ctx);
static uint8_t *signing_key(const request_ctx_t *const ctx);
static size_t string_to_sign(const request_ctx_t *const ctx,
                             uint8_t *const out);
static size_t canonical_request(const request_ctx_t *const ctx,
                                uint8_t *const out);

static uint8_t *hmac_sha256(const uint8_t *const key, const size_t key_size,
                            const uint8_t *const in, const size_t in_size);

static const uint8_t *const slash = (const uint8_t *const) "/";
static const uint8_t *const newline = (const uint8_t *const) "\n";

/**
 * Get null-terminated authorization header string
 */
char *authorization_header(const request_ctx_t *const ctx) {
    const size_t size = authorization_header_(ctx, NULL);
    uint8_t *const header = calloc(size + 1, sizeof(uint8_t));
    if (header == NULL) {
        exit_errno();
    }
    authorization_header_(ctx, header);
    return (char *const)header;
}

static size_t authorization_header_(const request_ctx_t *const ctx,
                                    uint8_t *const out) {
    static const uint8_t *const authorization =
        (const uint8_t *const) "Authorization: AWS4-HMAC-SHA256 Credential=";
    static const uint8_t *const signed_headers =
        (const uint8_t *const) "/aws4_request, SignedHeaders=";
    static const uint8_t *const signature_is =
        (const uint8_t *const) ", Signature=";

    size_t out_idx = 0;
    out_idx += copy(authorization, out != NULL ? out + out_idx : NULL);
    out_idx += copy((const uint8_t *const)ctx->master->id,
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(slash, out != NULL ? out + out_idx : NULL);
    out_idx += copy((const uint8_t *const)ctx->date,
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(slash, out != NULL ? out + out_idx : NULL);
    out_idx += copy((const uint8_t *const)ctx->master->region,
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(slash, out != NULL ? out + out_idx : NULL);
    out_idx += copy(service_str(ctx->master->service),
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(signed_headers, out != NULL ? out + out_idx : NULL);

    bool first_signed_header = true;
    for (size_t i = 0; i < ctx->num_headers; i++) {
        const tuple_t *const header = &ctx->headers[i];
        if (header->value == NULL) {
            continue;
        }
        if (!first_signed_header) {
            if (out != NULL) {
                out[out_idx] = ';';
            }
            out_idx++;
        }
        first_signed_header = false;
        out_idx += copy(header->key, out != NULL ? out + out_idx : NULL);
    }

    out_idx += copy(signature_is, out != NULL ? out + out_idx : NULL);
    if (out != NULL) {
        uint8_t *const sign = signature(ctx);
        out_idx += copy(sign, out + out_idx);
        free(sign);
    } else {
        out_idx += SHA256_BYTES * 2;
    }

    return out_idx;
}

/**
 * Returns null-terminated signature string.
 */
static uint8_t *signature(const request_ctx_t *const ctx) {
    size_t str_size = string_to_sign(ctx, NULL);
    uint8_t *const str = calloc(str_size, sizeof(uint8_t));
    if (str == NULL) {
        exit_errno();
    }
    string_to_sign(ctx, str);
    uint8_t *const key = signing_key(ctx);
    uint8_t *const sign = hmac_sha256(key, SHA256_BYTES, str, str_size);
    free(key);
    free(str);
    uint8_t *const sign_hex = calloc(SHA256_BYTES * 2 + 1, sizeof(uint8_t));
    if (sign_hex == NULL) {
        exit_errno();
    }
    hex(sign, SHA256_BYTES, sign_hex);
    free(sign);
    return sign_hex;
}

static uint8_t *signing_key(const request_ctx_t *const ctx) {
    static const uint8_t *const aws4 = (const uint8_t *const) "AWS4";
    static const uint8_t *const aws4_request =
        (const uint8_t *const) "aws4_request";

    const int aws4_size = len(aws4);
    const int key_size =
        aws4_size + len((const uint8_t *const)ctx->master->key);
    uint8_t *const key = calloc(key_size, sizeof(uint8_t));
    if (key == NULL) {
        exit_errno();
    }
    copy(aws4, key);
    copy((const uint8_t *const)ctx->master->key, key + aws4_size);

    uint8_t *const date_key =
        hmac_sha256(key, key_size, ctx->date, len(ctx->date));
    free(key);
    uint8_t *const date_region_key = hmac_sha256(
        date_key, SHA256_BYTES, (const uint8_t *const)ctx->master->region,
        strlen(ctx->master->region));
    free(date_key);
    uint8_t *const date_region_service_key = hmac_sha256(
        date_region_key, SHA256_BYTES, service_str(ctx->master->service),
        len(service_str(ctx->master->service)));
    free(date_region_key);
    uint8_t *const signing_key = hmac_sha256(
        date_region_service_key, SHA256_BYTES, aws4_request, len(aws4_request));
    free(date_region_service_key);
    return signing_key;
}

static size_t string_to_sign(const request_ctx_t *const ctx,
                             uint8_t *const out) {
    static const uint8_t *const algorithm =
        (const uint8_t *const) "AWS4-HMAC-SHA256\n";
    static const uint8_t *const scope_tail =
        (const uint8_t *const) "/aws4_request\n";

    size_t out_idx = 0;

    out_idx += copy(algorithm, out != NULL ? out + out_idx : NULL);
    out_idx += copy(ctx->date, out != NULL ? out + out_idx : NULL);
    out_idx += copy(ctx->time, out != NULL ? out + out_idx : NULL);
    out_idx += copy(newline, out != NULL ? out + out_idx : NULL);

    // scope
    out_idx += copy(ctx->date, out != NULL ? out + out_idx : NULL);
    out_idx += copy(slash, out != NULL ? out + out_idx : NULL);
    out_idx += copy((const uint8_t *const)ctx->master->region,
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(slash, out != NULL ? out + out_idx : NULL);
    out_idx += copy(service_str(ctx->master->service),
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(scope_tail, out != NULL ? out + out_idx : NULL);

    // canonical request
    if (out != NULL) {
        const size_t cr_size = canonical_request(ctx, NULL);
        uint8_t *const cr = calloc(cr_size, sizeof(uint8_t));
        if (cr == NULL) {
            exit_errno();
        }
        canonical_request(ctx, cr);
        print_debug("===== BEGIN canonical_request =====");
        if (level_debug) {
            for (size_t i = 0; i < cr_size; i++) {
                fputc(cr[i], stderr);
            }
            fputc('\n', stderr);
        }
        print_debug("===== END canonical_request =====");
        uint8_t *const cr_md = sha256(cr, cr_size);
        out_idx += hex(cr_md, SHA256_BYTES, out + out_idx);
        free(cr);
        free(cr_md);
    } else {
        out_idx += SHA256_BYTES * 2;
    }

    return out_idx;
}

static size_t canonical_request(const request_ctx_t *const ctx,
                                uint8_t *const out) {
    size_t out_idx = 0;

    // http method
    out_idx += copy(http_method_str(ctx->http_method),
                    out != NULL ? out + out_idx : NULL);
    out_idx += copy(newline, out != NULL ? out + out_idx : NULL);

    // resource
    out_idx +=
        uri_encode(ctx->resource, out != NULL ? out + out_idx : NULL, false);
    out_idx += copy(newline, out != NULL ? out + out_idx : NULL);

    // query string
    for (size_t i = 0; i < ctx->num_parameters; i++) {
        const tuple_t *const param = &ctx->parameters[i];
        if (i != 0) {
            if (out != NULL) {
                out[out_idx] = '&';
            }
            out_idx++;
        }
        out_idx +=
            uri_encode(param->key, out != NULL ? out + out_idx : NULL, true);
        if (out != NULL) {
            out[out_idx] = '=';
        }
        out_idx++;
        if (param->value == NULL) {
            continue;
        }
        out_idx +=
            uri_encode(param->value, out != NULL ? out + out_idx : NULL, true);
    }
    out_idx += copy(newline, out != NULL ? out + out_idx : NULL);

    // headers
    for (size_t i = 0; i < ctx->num_headers; i++) {
        const tuple_t *const header = &ctx->headers[i];
        if (header->value == NULL) {
            continue;
        }
        out_idx += copy(header->key, out != NULL ? out + out_idx : NULL);
        if (out != NULL) {
            out[out_idx] = ':';
        }
        out_idx++;
        out_idx += copy(header->value, out != NULL ? out + out_idx : NULL);
        out_idx += copy(newline, out != NULL ? out + out_idx : NULL);
    }
    out_idx += copy(newline, out != NULL ? out + out_idx : NULL);

    // signed headers
    bool first_signed_header = true;
    for (size_t i = 0; i < ctx->num_headers; i++) {
        const tuple_t *const header = &ctx->headers[i];
        if (header->value == NULL) {
            continue;
        }
        if (!first_signed_header) {
            if (out != NULL) {
                out[out_idx] = ';';
            }
            out_idx++;
        }
        first_signed_header = false;
        out_idx += copy(header->key, out != NULL ? out + out_idx : NULL);
    }
    out_idx += copy(newline, out != NULL ? out + out_idx : NULL);

    // hashed payload
    if (out != NULL) {
        out_idx += hex(ctx->payload_sha256, SHA256_BYTES, out + out_idx);
    } else {
        // hex(sha256(something))
        out_idx += SHA256_BYTES * 2;
    }

    return out_idx;
}

/**
 * Get HMAC using sha256
 * key: Pointer byte string to be used as key.
 * in: Pointer byte string to be used as content.
 */
static uint8_t *hmac_sha256(const uint8_t *const key, const size_t key_size,
                            const uint8_t *const in, const size_t in_size) {
    // extra one byte is for null-termination
    static unsigned int md_size = SHA256_BYTES;
    uint8_t *md = calloc(md_size, sizeof(uint8_t));
    if (md == NULL) {
        exit_errno();
    }
    if (HMAC(EVP_sha256(), key, key_size, in, in_size, md, &md_size) == NULL) {
        exit_openssl();
    }
    return md;
}

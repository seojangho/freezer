#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <utf8proc.h>

#include "freezer.h"

/**
 * Returns the corresponding string for the given service
 */
uint8_t *service_str(const enum service service) {
    return (uint8_t *)(service == s3 ? AWS_S3 : AWS_GLACIER);
}

uint8_t *http_method_str(const enum http_method method) {
    switch (method) {
    case get:
        return (uint8_t *)"GET";
    case put:
        return (uint8_t *)"PUT";
    case post:
        return (uint8_t *)"POST";
    default:
        exit_error("unknown http_method");
        return NULL;
    }
}

/**
 * Returns the length of the given null-terminated string
 */
int len(const uint8_t *const in) {
    int i = 0;
    for (;; i++) {
        if (in[i] == 0) {
            break;
        }
    }
    return i;
}

/**
 * Copies the given null-terminated string 'in'
 * to the given buffer 'out' (nullable)
 * This function do not make 'out' null-terminated.
 * Returns the number of the bytes copied.
 */
size_t copy(const uint8_t *const in, uint8_t *const out) {
    if (out == NULL) {
        size_t i = 0;
        for (;; i++) {
            if (in[i] == 0) {
                return i;
            }
        }
    }
    size_t i = 0;
    for (;; i++) {
        if (in[i] == 0) {
            return i;
        }
        out[i] = in[i];
    }
}

/**
 * Encode uri.
 * Returns the length of the encoded string.
 * in: Pointer to the string to encode. The string must be null-terminated and
 *     utf8-encoded.
 * out: If not null, buffer to store encoded string. The string is NOT
 *      null-terminated.
 * encode_slash: Whether or not to encode slash.
 */
size_t uri_encode(const uint8_t *const in, uint8_t *const out,
                  bool encode_slash) {
    static const utf8proc_int32_t codepoint_A = 0x41;
    static const utf8proc_int32_t codepoint_Z = 0x5a;
    static const utf8proc_int32_t codepoint_a = 0x61;
    static const utf8proc_int32_t codepoint_z = 0x7a;
    static const utf8proc_int32_t codepoint_0 = 0x30;
    static const utf8proc_int32_t codepoint_9 = 0x39;
    static const utf8proc_int32_t codepoint_hyphen = 0x2d;
    static const utf8proc_int32_t codepoint_dot = 0x2e;
    static const utf8proc_int32_t codepoint_underscore = 0x5f;
    static const utf8proc_int32_t codepoint_tilde = 0x7e;
    static const utf8proc_int32_t codepoint_slash = 0x2f;
    static const char *const hex_letters = "0123456789ABCDEF";

    utf8proc_ssize_t in_idx = 0;
    size_t out_idx = 0;

    while (true) {
        utf8proc_ssize_t strlen = 0;
        for (; strlen < 4; strlen++) {
            if (in[in_idx + strlen] == 0) {
                break;
            }
        }
        if (strlen == 0) {
            break;
        }

        utf8proc_int32_t codepoint = -1;
        utf8proc_ssize_t bytes =
            utf8proc_iterate(in + in_idx, strlen, &codepoint);
        if (bytes < 0) {
            exit_utf8proc(bytes);
        }

        if ((codepoint >= codepoint_A && codepoint <= codepoint_Z) ||
            (codepoint >= codepoint_a && codepoint <= codepoint_z) ||
            (codepoint >= codepoint_0 && codepoint <= codepoint_9) ||
            codepoint == codepoint_hyphen || codepoint == codepoint_dot ||
            codepoint == codepoint_underscore || codepoint == codepoint_tilde ||
            (codepoint == codepoint_slash && !encode_slash)) {
            // copy the character as-is
            if (out != NULL) {
                out[out_idx] = codepoint;
            }
            out_idx++;
        } else if (codepoint == codepoint_slash) {
            // encode_slash is true here
            if (out != NULL) {
                out[out_idx++] = '%';
                out[out_idx++] = '2';
                out[out_idx++] = 'F';
            } else {
                out_idx += 3;
            }
        } else if (out != NULL) {
            for (int i = 0; i < bytes; i++) {
                out[out_idx++] = '%';
                out[out_idx++] = hex_letters[(in[in_idx + i] >> 4) & 0xF];
                out[out_idx++] = hex_letters[in[in_idx + i] & 0xF];
            }
        } else {
            out_idx += bytes * 3;
        }

        in_idx += bytes;
    }

    return out_idx;
}

/**
 * Writes hexadecimal representation of the given byte sequence
 */
size_t hex(const uint8_t *const in, const size_t in_size, uint8_t *const out) {
    static const char *const letters = "0123456789abcdef";
    for (size_t i = 0; i < in_size; i++) {
        out[i * 2] = letters[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = letters[in[i] & 0xF];
    }
    return in_size * 2;
}

uint8_t *sha256(const uint8_t *const in, const size_t in_size) {
    uint8_t *md = calloc(SHA256_BYTES, sizeof(uint8_t));
    if (md == NULL) {
        exit_errno();
    }
    EVP_MD_CTX *const ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        exit_openssl();
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 0) {
        exit_openssl();
    }
    if (EVP_DigestUpdate(ctx, in, in_size) == 0) {
        exit_openssl();
    }
    if (EVP_DigestFinal_ex(ctx, md, NULL) == 0) {
        exit_openssl();
    }
    EVP_MD_CTX_free(ctx);
    return md;
}

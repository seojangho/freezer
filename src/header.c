#include <unistd.h>

#include "freezer.h"

static size_t header_callback(const char *const buffer, const size_t size,
                              const size_t nitems, char **addr_to_headervalue,
                              const char *const key_l, const char *const key_h);

size_t header_callback_etag(const char *const buffer, const size_t size,
                            const size_t nitems, char **addr_to_headervalue) {
    return header_callback(buffer, size, nitems, addr_to_headervalue, "etag",
                           "ETAG");
}

size_t header_callback_uploadid(const char *const buffer, const size_t size,
                                const size_t nitems,
                                char **addr_to_headervalue) {
    return header_callback(buffer, size, nitems, addr_to_headervalue,
                           "x-amz-multipart-upload-id",
                           "X-AMZ-MULTIPART-UPLOAD-ID");
}

size_t header_callback_location(const char *const buffer, const size_t size,
                                const size_t nitems,
                                char **addr_to_headervalue) {
    return header_callback(buffer, size, nitems, addr_to_headervalue,
                           "location", "LOCATION");
}

static size_t header_callback(const char *const buffer, const size_t size,
                              const size_t nitems, char **addr_to_headervalue,
                              const char *const key_l,
                              const char *const key_h) {
    const size_t key_len = strlen(key_l);
    const size_t len = size * nitems;

    size_t i = 0;
    for (; i < len && buffer[i] == ' '; i++)
        ;
    if (i == len) {
        return len;
    }
    for (size_t key_idx = 0; key_idx < key_len; key_idx++) {
        if (buffer[i] != key_l[key_idx] && buffer[i] != key_h[key_idx]) {
            return len;
        }
        i++;
        if (i == len) {
            return len;
        }
    }
    if (buffer[i] != ' ' && buffer[i] != ':') {
        return len;
    }
    for (; i < len && buffer[i] == ' '; i++)
        ;
    if (i == len) {
        return len;
    }
    if (buffer[i] != ':') {
        return len;
    }
    i++;
    for (; i < len && buffer[i] == ' '; i++)
        ;
    if (i == len) {
        return len;
    }

    // Adding null byte is handled by calloc
    // (len is always bigger than the length of value)
    char *value = calloc(len, sizeof(char));
    if (value == NULL) {
        exit_errno();
    }
    size_t value_idx = 0;
    for (; i < len; i++) {
        if (buffer[i] < '!' || buffer[i] > '~') {
            break;
        }
        value[value_idx++] = buffer[i];
    }
    *addr_to_headervalue = value;
    return len;
}

#define _POSIX_C_SOURCE 200809L

#include <config.h>
#include <curl/curl.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <libxml/parser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "freezer.h"

static void help(const char *const argv0);

/**
 * Responsible for argument parsing.
 */
int main(int argc, char *const argv[]) {
    static const char *const dup_msg =
        "%s: Repeating %s switch does not make sense\n";
    master_ctx_t master_ctx;
    master_ctx.id = NULL;
    master_ctx.region = NULL;
    master_ctx.key = NULL;
    master_ctx.chunk_size = DEFAULT_CHUNK_SIZE;
    master_ctx.bucket_name = NULL;
    master_ctx.object_name = NULL;
    master_ctx.upload_id = NULL;
    master_ctx.next_part_number = 0;

    bool args_invalid = false;
    int opt;
    char *aws_key_path = NULL;
    char *aws_service_str = NULL;
    char *chunk_size_str = NULL;
    while ((opt = getopt(argc, argv, "vi:k:r:s:c:")) != -1) {
        switch (opt) {
        case 'i':
            if (master_ctx.id != NULL) {
                fprintf(stderr, dup_msg, argv[0], "-i");
                args_invalid = true;
            }
            master_ctx.id = optarg;
            break;
        case 'k':
            if (aws_key_path != NULL) {
                fprintf(stderr, dup_msg, argv[0], "-k");
                args_invalid = true;
            }
            aws_key_path = optarg;
            break;
        case 'r':
            if (master_ctx.region != NULL) {
                fprintf(stderr, dup_msg, argv[0], "-r");
                args_invalid = true;
            }
            master_ctx.region = optarg;
            break;
        case 's':
            if (aws_service_str != NULL) {
                fprintf(stderr, dup_msg, argv[0], "-s");
                args_invalid = true;
            }
            aws_service_str = optarg;
            break;
        case 'v':
            level_debug = true;
            break;
        case 'c':
            if (chunk_size_str != NULL) {
                fprintf(stderr, dup_msg, argv[0], "-c");
                args_invalid = true;
            }
            chunk_size_str = optarg;
            break;
        default:
            help(argv[0]);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: bucket/valut name is required\n", argv[0]);
        args_invalid = true;
    } else {
        master_ctx.bucket_name = argv[optind];
        for (size_t i = 0;; i++) {
            if (master_ctx.bucket_name[i] == 0) {
                break;
            }
            if (master_ctx.bucket_name[i] == '/') {
                fprintf(stderr, "%s: bucket/valut name cannot contain slash\n",
                        argv[0]);
                args_invalid = true;
                break;
            }
        }
    }
    optind++;
    if (optind >= argc) {
        fprintf(stderr, "%s: object name is required\n", argv[0]);
        args_invalid = true;
    } else {
        master_ctx.object_name = argv[optind];
    }
    if (argc > optind + 1) {
        fprintf(stderr, "%s: superfluous argument(s)\n", argv[0]);
        args_invalid = true;
    }
    if (master_ctx.id == NULL) {
        fprintf(stderr, "%s: aws_access_key_id is not specified\n", argv[0]);
        args_invalid = true;
    }
    if (aws_key_path == NULL) {
        fprintf(stderr, "%s: path_to_aws_secret_access_key is not specified\n",
                argv[0]);
        args_invalid = true;
    }
    if (master_ctx.region == NULL) {
        fprintf(stderr, "%s: aws_region is not specified\n", argv[0]);
        args_invalid = true;
    }
    if (aws_service_str == NULL) {
        fprintf(stderr, "%s: aws_service is not specified\n", argv[0]);
        args_invalid = true;
    } else if (strcmp(aws_service_str, AWS_S3) == 0) {
        master_ctx.service = s3;
    } else if (strcmp(aws_service_str, AWS_GLACIER) == 0) {
        master_ctx.service = glacier;
    } else {
        fprintf(stderr, "%s: invalid aws_service: %s\n", argv[0],
                aws_service_str);
        args_invalid = true;
    }
    if (chunk_size_str != NULL) {
        const long chunk_size_l = atol(chunk_size_str);
        if (chunk_size_l <= 0) {
            fprintf(stderr, "%s: illegal chunk size\n", argv[0]);
            args_invalid = true;
        } else {
            // To calculate tree-hash checksum for glacier easily, chunk size
            // should be aligned to 1MiB
            master_ctx.chunk_size = (size_t)chunk_size_l * ONE_MEGA;
        }
    }
    if (args_invalid) {
        help(argv[0]);
    }

    const int aws_key_file = open(aws_key_path, O_RDONLY);
    if (aws_key_file == -1) {
        error(1, errno, "Cannot open file for AWS secret access key");
    }
    struct stat aws_key_file_stat;
    if (fstat(aws_key_file, &aws_key_file_stat) == -1) {
        exit_errno();
    }
    // Extra one byte for null-termination
    master_ctx.key = calloc(aws_key_file_stat.st_size + 1, sizeof(uint8_t));
    if (master_ctx.key == NULL) {
        exit_errno();
    }
    for (ssize_t bytes_read = 0; bytes_read < aws_key_file_stat.st_size;) {
        ssize_t b = read(aws_key_file, master_ctx.key + bytes_read,
                         aws_key_file_stat.st_size - bytes_read);
        if (b == -1) {
            exit_errno();
        }
        if (b == 0) {
            exit_error("unexpected EOF");
        }
        bytes_read += b;
    }
    // We don't need this (since calloc zerofills the memory)
    // master_ctx.key[aws_key_file_stat.st_size] = 0;
    for (off_t aws_key_idx = aws_key_file_stat.st_size - 1; aws_key_idx >= 0;
         aws_key_idx--) {
        if (master_ctx.key[aws_key_idx] == '\n') {
            master_ctx.key[aws_key_idx] = 0;
        } else {
            break;
        }
    }

    LIBXML_TEST_VERSION
    const CURLcode init_result = curl_global_init(CURL_GLOBAL_ALL);
    if (init_result) {
        exit_curl(init_result);
    }
    CURL *const handle = curl_easy_init();
    if (handle == NULL) {
        exit_error("curl_easy_init");
    }
    uint8_t *const payload_buffer =
        calloc(master_ctx.chunk_size, sizeof(uint8_t));
    if (payload_buffer == NULL) {
        exit_errno();
    }

    switch (master_ctx.service) {
    case s3:
        upload_s3(&master_ctx, handle, payload_buffer);
        break;
    case glacier:
        upload_glacier(&master_ctx, handle, payload_buffer);
        break;
    default:
        exit_error("unknown servicee");
        break;
    }

    free(payload_buffer);
    curl_easy_cleanup(handle);
    curl_global_cleanup();
    xmlCleanupParser();
    free(master_ctx.key);
    return 0;
}

static void help(const char *const argv0) {
    fprintf(stderr, "Usage: %s [OPTION] BUCKET_NAME OBJECT_NAME\n\
  -i id\t\tAWS access key id\n\
  -k secret\tPath to the file which stores AWS secret access key\n\
  -r region\tAWS region\n\
  -s service\tAWS service to use: s3 or glacier\n\
  -c chunk_size\tThe size of payload to upload at once (in MiB)\n\
  -v \t\tBe verbose\n",
            argv0);
    exit(EXIT_FAILURE);
}

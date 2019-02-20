#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>

#include "freezer.h"

bool level_debug = false;

void print_message_(const bool debug, const bool fatal, const char *const file,
                    const int line, const char *const message) {
    if (!level_debug && debug) {
        return;
    }
    fprintf(stderr, "%s: %d: %s\n", file, line, message);
    if (fatal) {
        exit(EX_SOFTWARE);
    }
}

void print_debug_v_(const char *const file, const int line,
                    const char *const format, ...) {
    if (!level_debug) {
        return;
    }
    va_list arg;
    va_start(arg, format);
    fprintf(stderr, "%s: %d: ", file, line);
    vfprintf(stderr, format, arg);
    fprintf(stderr, "\n");
    va_end(arg);
}

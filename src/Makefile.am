AM_CFLAGS=-std=c11 -Wall -Wextra -pedantic -Werror -Wshadow \
	  -Wstrict-overflow -fno-strict-aliasing \
	  $(CURL_CFLAGS) $(UTF8PROC_CFLAGS) $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS)
AM_LDFLAGS=$(CURL_LIBS) $(UTF8PROC_LIBS) $(OPENSSL_LIBS) $(LIBXML2_LIBS)
CFORMAT_FLAGS=-i -style="{BasedOnStyle: llvm, IndentWidth: 4, \
  AllowShortFunctionsOnASingleLine: None, \
  KeepEmptyLinesAtTheStartOfBlocks: false}"

bin_PROGRAMS = freezer
freezer_SOURCES = freezer.h main.c authorization.c utils.c debug.c request.c upload.c header.c

format: $(freezer_SOURCES)
	$(CFORMAT) $(CFORMAT_FLAGS) $^

.PHONEY: format

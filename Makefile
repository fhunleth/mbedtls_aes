# SPDX-FileCopyrightText: None
# SPDX-License-Identifier: CC0-1.0

CFLAGS  := -O3 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
           -std=c11 -D_GNU_SOURCE -I.
LDFLAGS :=

CC      := cc
BIN     := aes_bench
OBJDIR  := build
SRCS    := bench/benchmark.c bench/tiny-AES-c/aes.c mbedtls_aes.c
OBJS    := $(SRCS:%.c=$(OBJDIR)/%.o)
GEN     := mbedtls_aes.c mbedtls_aes.h

.PHONY: all run check amalgamate clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: %.c $(GEN)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

amalgamate $(GEN): generator/amalgamate.sh \
                   generator/mbedtls_aes.h.in \
                   generator/platform_util_min.c \
                   $(wildcard generator/patches/*.patch)
	./generator/amalgamate.sh

run: $(BIN)
	./$(BIN)

check: $(BIN)
	AES_BENCH_MIN_SECONDS=0.2 ./$(BIN)

clean:
	rm -rf $(OBJDIR) $(BIN)

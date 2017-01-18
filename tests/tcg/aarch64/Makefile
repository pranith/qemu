# -*- Mode: makefile -*-
#
# Aarch64 linux-user TCG tests
#
# The Make is expected to be called in the
# ${BUILD_DIR}/aarch64-linux-user/tests directory
#

BUILD_DIR=../..
include $(BUILD_DIR)/config-host.mak	# brings in SRC_PATH
include ../config-target.mak		# TARGET_NAME
include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/tests/tcg/aarch64)

QEMU=$(BUILD_DIR)/aarch64-linux-user/qemu-aarch64

# Compiler set-up, default to system compiler if not set
CROSS_CC?=$(CC)

QEMU_INCLUDES += -I$(BUILD_DIR)
CFLAGS=-static -Wall -O2 -g -fno-strict-aliasing -nostdlib
LDFLAGS=-nostdlib

TESTS=hello-aarch64

run: $(patsubst %,run-%,$(I386_TESTS))
all: $(TESTS)
test: all

# rules to run tests

run-%: %
	$(QEMU) ./$*

#.PHONY: $(patsubst %,run-%,$(TESTS))

run-hello-aarch64: hello-aarch64

# aarch64 test
hello-aarch64: hello-aarch64.o
	$(CROSS_CC) $(LDFLAGS) -o $@ $<

hello-aarch64.o: hello-aarch64.c
	$(CROSS_CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *~ *.o $(TESTS)

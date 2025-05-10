# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024, MediaTek

CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

CFLAGS += -Wall -I../../ta/hdcp/include
CFLAGS += -I$(TEEC_EXPORT)/include

LDADD += -lteec -L$(TEEC_EXPORT)/lib

BINARY = hdcp_ca_test

.PHONY: all
all: $(BINARY)

$(BINARY): hdcp_ca_test.o hdcp_ca.o
	$(CC) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f $(BINARY) *.o

# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024, MediaTek

# 全局变量
OPTEE_OS_DIR ?= $(shell cd .. && pwd)

# 编译TA和CA
.PHONY: all ta ca clean

all: ta ca

ta:
	$(MAKE) -C ta OPTEE_OS_DIR=$(OPTEE_OS_DIR)

ca:
	$(MAKE) -C ca

clean:
	$(MAKE) -C ta clean
	$(MAKE) -C ca clean

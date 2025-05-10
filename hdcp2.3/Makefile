# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024, MediaTek

# 全局变量
OPTEE_OS_DIR ?= $(shell cd .. && pwd)

# 编译TA、CA和测试
.PHONY: all ta ca tests clean

all: ta ca tests

ta:
	$(MAKE) -C ta/hdcp OPTEE_OS_DIR=$(OPTEE_OS_DIR)

ca:
	$(MAKE) -C ca/hdcp

tests:
	$(MAKE) -C tests

clean:
	$(MAKE) -C ta/hdcp clean
	$(MAKE) -C ca/hdcp clean
	$(MAKE) -C tests clean

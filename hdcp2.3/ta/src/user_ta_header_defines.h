/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <hdcp_ta.h>

#define TA_UUID				HDCP_TA_UUID

#define TA_FLAGS				(TA_FLAG_MULTI_SESSION | \
					 TA_FLAG_SECURE_DATA_PATH)

#define TA_STACK_SIZE			(4 * 1024)

#define TA_DATA_SIZE			(32 * 1024)

#define TA_DESCRIPTION			"HDCP 2.3 Sink Trusted Application"
#define TA_VERSION				"1.0"

#endif /* USER_TA_HEADER_DEFINES_H */

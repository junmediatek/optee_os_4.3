/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <hdcp2_3_ta.h>

#define TA_UUID                 TA_HDCP2_3_UUID

/* 多会话支持，启用安全数据路径 */
#define TA_FLAGS                (TA_FLAG_MULTI_SESSION | \
                               TA_FLAG_SECURE_DATA_PATH)

/* 为TA分配合适的栈和堆大小 */
#define TA_STACK_SIZE           (32 * 1024)
#define TA_DATA_SIZE            (128 * 1024)

#define TA_DESCRIPTION          "HDCP 2.3 Trusted Application"
#define TA_VERSION              "1.0"

#endif /* USER_TA_HEADER_DEFINES_H */

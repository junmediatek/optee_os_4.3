/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef __HDCP2_3_CLIENT_H
#define __HDCP2_3_CLIENT_H

#include <tee_client_api.h>

/* 导入TA头文件中的定义 */
#include <hdcp2_3_ta.h>

/* HDCP客户端上下文 */
typedef struct {
    TEEC_Context ctx;          /* TEEC上下文 */
    TEEC_Session session;      /* 与TA的会话 */
    bool is_initialized;       /* 是否已初始化 */
    uint32_t hdcp_status;      /* HDCP状态 */
} HDCP2_3_CLIENT_CTX;

/* HDCP客户端API */

/* 初始化HDCP客户端 */
TEEC_Result hdcp_ca_init(HDCP2_3_CLIENT_CTX *context);

/* 释放HDCP客户端资源 */
void hdcp_ca_close(HDCP2_3_CLIENT_CTX *context);

/* 验证接收方身份和交换密钥 */
TEEC_Result hdcp_ca_ake_init(TEEC_Session *session, uint8_t *rtx, uint8_t *tx_caps);

/* 测试函数 */
TEEC_Result hdcp_ca_test(TEEC_Session *session);

/* 解密视频数据 */
TEEC_Result hdcp_ca_decrypt_video(TEEC_Session *session,
                                 TEEC_SharedMemory *input_buffer,
                                 TEEC_SharedMemory *output_buffer);

#endif /* __HDCP2_3_CLIENT_H */

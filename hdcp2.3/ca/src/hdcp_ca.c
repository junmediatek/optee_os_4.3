/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "../include/hdcp2_3_client.h"

TEEC_Result hdcp_ca_init(HDCP2_3_CLIENT_CTX *context)
{
    TEEC_UUID uuid = TA_HDCP2_3_UUID;
    TEEC_Result res;
    uint32_t err_origin;
    
    if (!context)
        return TEEC_ERROR_BAD_PARAMETERS;
        
    /* 初始化上下文 */
    res = TEEC_InitializeContext(NULL, &context->ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return res;
    }
    
    /* 打开会话 */
    res = TEEC_OpenSession(&context->ctx, &context->session, &uuid, TEEC_LOGIN_PUBLIC,
                          NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x, origin: 0x%x\n", res, err_origin);
        TEEC_FinalizeContext(&context->ctx);
        return res;
    }
    
    context->is_initialized = true;
    context->hdcp_status = 0; // HDCP_STATE_UNAUTHENTICATED
    
    return res;
}

void hdcp_ca_close(HDCP2_3_CLIENT_CTX *context)
{
    if (!context || !context->is_initialized)
        return;
        
    /* 关闭会话 */
    TEEC_CloseSession(&context->session);
    
    /* 清理上下文 */
    TEEC_FinalizeContext(&context->ctx);
    
    context->is_initialized = false;
}

TEEC_Result hdcp_ca_ake_init(TEEC_Session *session, uint8_t *rtx, uint8_t *tx_caps)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ake_init param;
    
    /* 准备参数 */
    memcpy(param.r_tx, rtx, 8);
    memcpy(param.tx_caps, tx_caps, 3);
    
    /* 准备操作 */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE);
    op.params[0].tmpref.buffer = &param;
    op.params[0].tmpref.size = sizeof(param);
    
    /* 调用TA */
    res = TEEC_InvokeCommand(session, TA_HDCP2_3_CMD_AKE_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_AKE_INIT failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_ake_send_cert(TEEC_Session *session, uint8_t *cert_rx, uint8_t *rrx, uint8_t *rx_caps)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ake_send_cert param;
    
    /* 准备参数 */
    memcpy(param.cert_rx, cert_rx, 522);
    memcpy(param.r_rx, rrx, 8);
    memcpy(param.rx_caps, rx_caps, 3);
    
    /* 准备操作 */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE);
    op.params[0].tmpref.buffer = &param;
    op.params[0].tmpref.size = sizeof(param);
    
    /* 调用TA */
    res = TEEC_InvokeCommand(session, TA_HDCP2_3_CMD_AKE_SEND_CERT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_AKE_SEND_CERT failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_decrypt_video(TEEC_Session *session, 
                                 TEEC_SharedMemory *input_buffer,
                                 TEEC_SharedMemory *output_buffer)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    
    /* 准备操作 */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_MEMREF_WHOLE,
                    TEEC_MEMREF_WHOLE,
                    TEEC_NONE,
                    TEEC_NONE);
    op.params[0].memref.parent = input_buffer;
    op.params[1].memref.parent = output_buffer;
    
    /* 调用TA */
    res = TEEC_InvokeCommand(session, TA_HDCP2_3_CMD_DECRYPT_VIDEO, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_DECRYPT_VIDEO failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_test(TEEC_Session *session)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    
    /* 准备操作 */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE);
    
    /* 调用TA */
    res = TEEC_InvokeCommand(session, TA_HDCP2_3_CMD_GET_STATUS, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_TEST failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

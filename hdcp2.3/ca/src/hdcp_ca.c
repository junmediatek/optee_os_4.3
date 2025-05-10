/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "hdcp_ca.h"
#include "../../ta/hdcp/include/hdcp_ta.h"

TEEC_Result hdcp_ca_init(TEEC_Context *context, TEEC_Session *session)
{
    TEEC_UUID uuid = HDCP_TA_UUID;
    TEEC_Result res;
    uint32_t err_origin;
    
    /* 初始化上下文 */
    res = TEEC_InitializeContext(NULL, context);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return res;
    }
    
    /* 打开会话 */
    res = TEEC_OpenSession(context, session, &uuid, TEEC_LOGIN_PUBLIC,
                          NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x, origin: 0x%x\n", res, err_origin);
        TEEC_FinalizeContext(context);
    }
    
    return res;
}

void hdcp_ca_close(TEEC_Context *context, TEEC_Session *session)
{
    /* 关闭会话 */
    TEEC_CloseSession(session);
    
    /* 清理上下文 */
    TEEC_FinalizeContext(context);
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_AKE_INIT, &op, &err_origin);
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_AKE_SEND_CERT, &op, &err_origin);
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_DECRYPT_VIDEO, &op, &err_origin);
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_TEST, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_TEST failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

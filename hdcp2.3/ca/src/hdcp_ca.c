/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "hdcp_ca.h"
#include "../../ta/hdcp/include/hdcp_ta.h"

/* 结构体定义 - 与TA端保持一致 */
struct hdcp_param_ake_no_stored_km {
    uint8_t e_kpub_km[128];
};

struct hdcp_param_ake_stored_km {
    uint8_t e_kh_km[16];
    uint8_t m[16];
};

struct hdcp_param_ake_send_h_prime {
    uint8_t h_prime[32];
};

struct hdcp_param_ake_send_pairing_info {
    uint8_t e_kh_km[16];
};

struct hdcp_param_lc_init {
    uint8_t rn[8];
};

struct hdcp_param_lc_send_l_prime {
    uint8_t l_prime[32];
};

struct hdcp_param_ske_send_eks {
    uint8_t e_dkey_ks[16];
    uint8_t riv[8];
};

struct hdcp_param_decrypt_init {
    uint8_t stream_ctr[8];
};

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

TEEC_Result hdcp_ca_ake_no_stored_km(TEEC_Session *session, uint8_t *e_kpub_km)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ake_no_stored_km param;
    
    /* 准备参数 */
    memcpy(param.e_kpub_km, e_kpub_km, 128);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_AKE_NO_STORED_KM, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_AKE_NO_STORED_KM failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_ake_stored_km(TEEC_Session *session, uint8_t *e_kh_km, uint8_t *m)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ake_stored_km param;
    
    /* 准备参数 */
    memcpy(param.e_kh_km, e_kh_km, 16);
    memcpy(param.m, m, 16);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_AKE_STORED_KM, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_AKE_STORED_KM failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_ake_send_h_prime(TEEC_Session *session, uint8_t *h_prime)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ake_send_h_prime param;
    
    /* 准备参数 */
    memcpy(param.h_prime, h_prime, 32);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_AKE_SEND_H_PRIME, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_AKE_SEND_H_PRIME failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_ake_send_pairing_info(TEEC_Session *session, uint8_t *e_kh_km)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ake_send_pairing_info param;
    
    /* 准备参数 */
    memcpy(param.e_kh_km, e_kh_km, 16);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_AKE_SEND_PAIRING_INFO, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_AKE_SEND_PAIRING_INFO failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_lc_init(TEEC_Session *session, uint8_t *rn)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_lc_init param;
    
    /* 准备参数 */
    memcpy(param.rn, rn, 8);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_LC_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_LC_INIT failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_lc_send_l_prime(TEEC_Session *session, uint8_t *l_prime)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_lc_send_l_prime param;
    
    /* 准备参数 */
    memcpy(param.l_prime, l_prime, 32);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_LC_SEND_L_PRIME, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_LC_SEND_L_PRIME failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_ske_send_eks(TEEC_Session *session, uint8_t *e_dkey_ks, uint8_t *riv)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_ske_send_eks param;
    
    /* 准备参数 */
    memcpy(param.e_dkey_ks, e_dkey_ks, 16);
    memcpy(param.riv, riv, 8);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_SKE_SEND_EKS, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_SKE_SEND_EKS failed: 0x%x, origin: 0x%x\n", res, err_origin);
    }
    
    return res;
}

TEEC_Result hdcp_ca_decrypt_init(TEEC_Session *session, uint8_t *stream_ctr)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    struct hdcp_param_decrypt_init param;
    
    /* 准备参数 */
    memcpy(param.stream_ctr, stream_ctr, 8);
    
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
    res = TEEC_InvokeCommand(session, HDCP_CMD_DECRYPT_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("HDCP_CMD_DECRYPT_INIT failed: 0x%x, origin: 0x%x\n", res, err_origin);
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

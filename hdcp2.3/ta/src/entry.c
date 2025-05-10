/*
 * Copyright (c) 2024, MediaTek
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <hdcp_ta.h>
#include "hdcp_internal.h"

/*
 * TA生命周期入口点
 */
TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("HDCP TA: CreateEntryPoint");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("HDCP TA: DestroyEntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                  TEE_Param params[4],
                                  void **sess_ctx)
{
    struct hdcp_session *session;
    
    DMSG("HDCP TA: OpenSessionEntryPoint");
    
    /* 检查参数类型 */
    uint32_t exp_param_types = TEE_PARAM_TYPES(
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 分配会话上下文 */
    session = TEE_Malloc(sizeof(*session), 0);
    if (!session)
        return TEE_ERROR_OUT_OF_MEMORY;
        
    /* 初始化会话状态 */
    session->session_state = HDCP_STATE_UNINITIALIZED;
    session->input_ctr = 0;
    
    /* 分配安全路径缓冲区 - 这里仅为演示，实际实现中可能会在需要时分配 */
    /* 注: 真正的视频缓冲区将通过共享内存处理 */
    
    *sess_ctx = session;
    
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct hdcp_session *session = sess_ctx;
    
    DMSG("HDCP TA: CloseSessionEntryPoint");
    
    /* 释放会话资源 */
    if (session) {
        /* 清除敏感信息 */
        TEE_MemFill(session->km, 0, sizeof(session->km));
        TEE_MemFill(session->kh, 0, sizeof(session->kh));
        TEE_MemFill(session->ks, 0, sizeof(session->ks));
        
        /* 释放安全缓冲区（如果已分配） */
        if (session->secure_buf) {
            TEE_CloseObject(session->secure_buf);
            session->secure_buf = NULL;
        }
        
        TEE_Free(session);
    }
}

static TEE_Result hdcp_ake_init(struct hdcp_session *session, 
                              uint32_t param_types,
                              TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
                                   TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ake_init))
        return TEE_ERROR_BAD_PARAMETERS;
        
    struct hdcp_param_ake_init *ake_init = 
        (struct hdcp_param_ake_init *)params[0].memref.buffer;
        
    /* 保存rtx和tx_caps */
    TEE_MemMove(session->rtx, ake_init->r_tx, sizeof(session->rtx));
    TEE_MemMove(session->tx_caps, ake_init->tx_caps, sizeof(session->tx_caps));
    
    /* 更新状态 */
    session->session_state = HDCP_STATE_AKE_INIT;
    
    return TEE_SUCCESS;
}

static TEE_Result hdcp_ake_send_cert(struct hdcp_session *session,
                                   uint32_t param_types,
                                   TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
                                   TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ake_send_cert))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_INIT)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_ake_send_cert *send_cert = 
        (struct hdcp_param_ake_send_cert *)params[0].memref.buffer;
        
    /* 保存rrx和rx_caps */
    TEE_MemMove(session->rrx, send_cert->r_rx, sizeof(session->rrx));
    TEE_MemMove(session->rx_caps, send_cert->rx_caps, sizeof(session->rx_caps));
    
    /* 验证接收方证书 - 实际实现中需要进行真正的验证 */
    /* 这里简化处理，仅更新状态 */
    
    session->session_state = HDCP_STATE_AKE_CERT_SENT;
    
    return TEE_SUCCESS;
}

static TEE_Result hdcp_decrypt_video(struct hdcp_session *session,
                                   uint32_t param_types,
                                   TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
                                   TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_SKE_COMPLETE)
        return TEE_ERROR_BAD_STATE;
        
    /* 获取输入和输出缓冲区 */
    void *input = params[0].memref.buffer;
    uint32_t input_size = params[0].memref.size;
    void *output = params[1].memref.buffer;
    uint32_t output_size = params[1].memref.size;
    
    /* 检查输出缓冲区大小 */
    if (output_size < input_size)
        return TEE_ERROR_SHORT_BUFFER;
    
    /* 使用HDCP密码器解密视频数据 */
    TEE_Result res = hdcp_decrypt_data(
        session->ks, session->riv, session->stream_ctr,
        session->input_ctr, input, input_size,
        output, &output_size);
    
    /* 更新输入计数器 */
    if (res == TEE_SUCCESS) {
        session->input_ctr += (input_size + 15) / 16; /* 按16字节块计数 */
        params[1].memref.size = output_size;
    }
    
    return res;
}

static TEE_Result hdcp_test(struct hdcp_session *session,
                          uint32_t param_types,
                          TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    
    /* 简单的测试函数，仅返回成功 */
    DMSG("HDCP TA: Test function called");
    
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                     uint32_t cmd_id,
                                     uint32_t param_types,
                                     TEE_Param params[4])
{
    struct hdcp_session *session = sess_ctx;
    
    DMSG("HDCP TA: Invoke command 0x%x", cmd_id);
    
    switch (cmd_id) {
    case HDCP_CMD_AKE_INIT:
        return hdcp_ake_init(session, param_types, params);
    case HDCP_CMD_AKE_SEND_CERT:
        return hdcp_ake_send_cert(session, param_types, params);
    case HDCP_CMD_AKE_NO_STORED_KM:
        return hdcp_ake_no_stored_km(session, param_types, params);
    case HDCP_CMD_AKE_STORED_KM:
        return hdcp_ake_stored_km(session, param_types, params);
    case HDCP_CMD_AKE_SEND_RRX:
        return hdcp_ake_send_rrx(session, param_types, params);
    case HDCP_CMD_AKE_SEND_H_PRIME:
        return hdcp_ake_send_h_prime(session, param_types, params);
    case HDCP_CMD_AKE_SEND_PAIRING_INFO:
        return hdcp_ake_send_pairing_info(session, param_types, params);
    case HDCP_CMD_LC_INIT:
        return hdcp_lc_init(session, param_types, params);
    case HDCP_CMD_LC_SEND_L_PRIME:
        return hdcp_lc_send_l_prime(session, param_types, params);
    case HDCP_CMD_SKE_SEND_EKS:
        return hdcp_ske_send_eks(session, param_types, params);
    case HDCP_CMD_DECRYPT_INIT:
        return hdcp_decrypt_init(session, param_types, params);
    case HDCP_CMD_DECRYPT_VIDEO:
        return hdcp_decrypt_video(session, param_types, params);
    case HDCP_CMD_TEST:
        return hdcp_test(session, param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

/*
 * Copyright (c) 2024, MediaTek
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "hdcp_internal.h"

/* AKE: 无存储的Km处理 */
TEE_Result hdcp_ake_no_stored_km(struct hdcp_session *session, 
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ake_no_stored_km))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_CERT_SENT)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_ake_no_stored_km *no_stored_km = 
        (struct hdcp_param_ake_no_stored_km *)params[0].memref.buffer;
        
    /* 处理e_kpub_km - 实际实现中需要解密并验证 */
    /* 这里简化处理，调用现有函数 */
    TEE_Result res = hdcp_process_no_stored_km(session, no_stored_km->e_kpub_km);
    
    if (res == TEE_SUCCESS) {
        /* 更新会话状态 */
        session->session_state = HDCP_STATE_AKE_KM_SENT;
    }
    
    return res;
}

/* AKE: 存储的Km处理 */
TEE_Result hdcp_ake_stored_km(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ake_stored_km))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_CERT_SENT)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_ake_stored_km *stored_km = 
        (struct hdcp_param_ake_stored_km *)params[0].memref.buffer;
        
    /* 处理e_kh_km和m - 实际实现中需要解密并验证 */
    /* 这里简化处理，调用现有函数 */
    TEE_Result res = hdcp_process_stored_km(session, stored_km->e_kh_km, stored_km->m);
    
    if (res == TEE_SUCCESS) {
        /* 更新会话状态 */
        session->session_state = HDCP_STATE_AKE_KM_SENT;
    }
    
    return res;
}

/* AKE: 发送rrx */
TEE_Result hdcp_ake_send_rrx(struct hdcp_session *session,
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
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_KM_SENT)
        return TEE_ERROR_BAD_STATE;
    
    /* 在实际实现中，这里会处理rrx */
    /* 这里简化处理，仅保持状态不变 */
    
    DMSG("HDCP TA: AKE Send rrx");
    
    return TEE_SUCCESS;
}

/* AKE: 发送H' */
TEE_Result hdcp_ake_send_h_prime(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ake_send_h_prime))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_KM_SENT)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_ake_send_h_prime *send_h_prime = 
        (struct hdcp_param_ake_send_h_prime *)params[0].memref.buffer;
        
    /* 验证H' - 实际实现中需要计算并验证 */
    /* 这里简化处理，调用现有函数 */
    TEE_Result res = hdcp_verify_h_prime(session, send_h_prime->h_prime);
    
    return res;
}

/* AKE: 发送配对信息 */
TEE_Result hdcp_ake_send_pairing_info(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ake_send_pairing_info))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_H_VERIFIED)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_ake_send_pairing_info *pairing_info = 
        (struct hdcp_param_ake_send_pairing_info *)params[0].memref.buffer;
        
    /* 保存配对信息 - 实际实现中需要存储到安全存储中 */
    /* 这里简化处理，仅打印日志 */
    DMSG("HDCP TA: Received pairing info");
    
    return TEE_SUCCESS;
}

/* LC: 初始化 */
TEE_Result hdcp_lc_init(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_lc_init))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_AKE_H_VERIFIED)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_lc_init *lc_init = 
        (struct hdcp_param_lc_init *)params[0].memref.buffer;
        
    /* 处理rn - 实际实现中需要保存并用于后续计算 */
    /* 这里简化处理，仅更新状态 */
    
    session->session_state = HDCP_STATE_LC_INIT;
    
    return TEE_SUCCESS;
}

/* LC: 发送L' */
TEE_Result hdcp_lc_send_l_prime(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_lc_send_l_prime))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_LC_INIT)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_lc_send_l_prime *send_l_prime = 
        (struct hdcp_param_lc_send_l_prime *)params[0].memref.buffer;
        
    /* 验证L' - 实际实现中需要计算并验证 */
    /* 这里简化处理，调用现有函数 */
    TEE_Result res = hdcp_verify_l_prime(session, send_l_prime->l_prime);
    
    return res;
}

/* SKE: 发送加密的会话密钥 */
TEE_Result hdcp_ske_send_eks(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_ske_send_eks))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_LC_VERIFIED)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_ske_send_eks *send_eks = 
        (struct hdcp_param_ske_send_eks *)params[0].memref.buffer;
        
    /* 保存加密的会话密钥和riv */
    /* 实际实现中需要解密会话密钥 */
    TEE_MemMove(session->ks, send_eks->e_dkey_ks, sizeof(session->ks));
    TEE_MemMove(session->riv, send_eks->riv, sizeof(session->riv));
    
    /* 更新状态 */
    session->session_state = HDCP_STATE_SKE_COMPLETE;
    
    return TEE_SUCCESS;
}

/* 初始化解密 */
TEE_Result hdcp_decrypt_init(struct hdcp_session *session,
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
        
    if (params[0].memref.size != sizeof(struct hdcp_param_decrypt_init))
        return TEE_ERROR_BAD_PARAMETERS;
        
    /* 检查会话状态 */
    if (session->session_state != HDCP_STATE_SKE_COMPLETE)
        return TEE_ERROR_BAD_STATE;
        
    struct hdcp_param_decrypt_init *decrypt_init = 
        (struct hdcp_param_decrypt_init *)params[0].memref.buffer;
        
    /* 保存流计数器 */
    TEE_MemMove(session->stream_ctr, decrypt_init->stream_ctr, sizeof(session->stream_ctr));
    
    /* 重置输入计数器 */
    session->input_ctr = 0;
    
    /* 初始化HDCP密码器 */
    TEE_Result res = hdcp_cipher_init(session->ks, session->riv, session->stream_ctr);
    
    return res;
}

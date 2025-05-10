/*
 * Copyright (c) 2024, MediaTek
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "hdcp_internal.h"

/* 验证H' */
TEE_Result hdcp_verify_h_prime(struct hdcp_session *session, uint8_t *h_prime)
{
    /* 
     * 实际实现中，需要根据HDCP 2.3规范计算并验证H'
     * 这里简化处理，仅返回成功
     */
    DMSG("HDCP TA: Verify H'");
    
    /* 更新会话状态 */
    session->session_state = HDCP_STATE_AKE_H_VERIFIED;
    
    return TEE_SUCCESS;
}

/* 验证L' */
TEE_Result hdcp_verify_l_prime(struct hdcp_session *session, uint8_t *l_prime)
{
    /* 
     * 实际实现中，需要根据HDCP 2.3规范计算并验证L'
     * 这里简化处理，仅返回成功
     */
    DMSG("HDCP TA: Verify L'");
    
    /* 更新会话状态 */
    session->session_state = HDCP_STATE_LC_VERIFIED;
    
    return TEE_SUCCESS;
}

/* 处理存储的Km */
TEE_Result hdcp_process_stored_km(struct hdcp_session *session, uint8_t *e_kh_km, uint8_t *m)
{
    /* 
     * 实际实现中，需要根据HDCP 2.3规范处理存储的Km
     * 这里简化处理，仅返回成功
     */
    DMSG("HDCP TA: Process stored Km");
    
    /* 更新会话状态 */
    session->session_state = HDCP_STATE_AKE_KM_SENT;
    
    return TEE_SUCCESS;
}

/* 处理非存储的Km */
TEE_Result hdcp_process_no_stored_km(struct hdcp_session *session, uint8_t *e_kpub_km)
{
    /* 
     * 实际实现中，需要根据HDCP 2.3规范处理非存储的Km
     * 这里简化处理，仅返回成功
     */
    DMSG("HDCP TA: Process no stored Km");
    
    /* 更新会话状态 */
    session->session_state = HDCP_STATE_AKE_KM_SENT;
    
    return TEE_SUCCESS;
}

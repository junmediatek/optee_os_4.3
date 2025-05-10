/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef HDCP_INTERNAL_H
#define HDCP_INTERNAL_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <hdcp_ta.h>

/* HDCP会话上下文 */
struct hdcp_session {
    uint32_t session_state;  /* 会话状态 */
    TEE_TASessionHandle tee_session; /* TEE会话句柄 */
    
    /* AKE状态 */
    uint8_t rtx[8];
    uint8_t rrx[8];
    uint8_t tx_caps[3];
    uint8_t rx_caps[3];
    
    /* 密钥材料 - 核心价值保存在TA端 */
    uint8_t km[16];      /* 主密钥 */
    uint8_t kh[16];      /* 哈希密钥 */
    uint8_t ks[16];      /* 会话密钥 */
    uint8_t riv[8];      /* 随机初始化向量 */
    
    /* 解密状态 */
    uint8_t stream_ctr[4]; /* 流计数器 */
    uint64_t input_ctr;    /* 输入计数器 */
    
    /* 安全路径缓冲区 */
    TEE_ObjectHandle secure_buf;
};

/* HDCP状态定义 */
#define HDCP_STATE_UNINITIALIZED    0
#define HDCP_STATE_AKE_INIT         1
#define HDCP_STATE_AKE_CERT_SENT    2
#define HDCP_STATE_AKE_KM_SENT      3
#define HDCP_STATE_AKE_H_VERIFIED   4
#define HDCP_STATE_LC_INIT          5
#define HDCP_STATE_LC_VERIFIED      6
#define HDCP_STATE_SKE_COMPLETE     7

/* 加密/解密函数 */
TEE_Result hdcp_aes_encrypt(uint8_t *key, uint32_t key_len,
                           uint8_t *iv, uint32_t iv_len,
                           uint8_t *src, uint32_t src_len,
                           uint8_t *dst, uint32_t *dst_len);

TEE_Result hdcp_aes_decrypt(uint8_t *key, uint32_t key_len,
                           uint8_t *iv, uint32_t iv_len,
                           uint8_t *src, uint32_t src_len,
                           uint8_t *dst, uint32_t *dst_len);

/* HDCP密码器函数 */
TEE_Result hdcp_cipher_init(uint8_t *ks, uint8_t *riv, uint8_t *stream_ctr);

TEE_Result hdcp_decrypt_data(uint8_t *ks, uint8_t *riv, uint8_t *stream_ctr,
                            uint64_t input_ctr, uint8_t *input, uint32_t input_len,
                            uint8_t *output, uint32_t *output_len);

/* 认证函数 */
TEE_Result hdcp_verify_h_prime(struct hdcp_session *session, uint8_t *h_prime);
TEE_Result hdcp_verify_l_prime(struct hdcp_session *session, uint8_t *l_prime);
TEE_Result hdcp_process_stored_km(struct hdcp_session *session, uint8_t *e_kh_km, uint8_t *m);
TEE_Result hdcp_process_no_stored_km(struct hdcp_session *session, uint8_t *e_kpub_km);

/* HDCP命令处理函数 */
TEE_Result hdcp_ake_no_stored_km(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_ake_stored_km(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_ake_send_rrx(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_ake_send_h_prime(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_ake_send_pairing_info(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_lc_init(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_lc_send_l_prime(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_ske_send_eks(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);
TEE_Result hdcp_decrypt_init(struct hdcp_session *session, uint32_t param_types, TEE_Param params[4]);

#endif /* HDCP_INTERNAL_H */

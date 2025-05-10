/*
 * Copyright (c) 2024, MediaTek
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "hdcp_internal.h"

/* AES加密实现 */
TEE_Result hdcp_aes_encrypt(uint8_t *key, uint32_t key_len,
                           uint8_t *iv, uint32_t iv_len,
                           uint8_t *src, uint32_t src_len,
                           uint8_t *dst, uint32_t *dst_len)
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    
    /* 检查参数 */
    if (!key || !iv || !src || !dst || !dst_len)
        return TEE_ERROR_BAD_PARAMETERS;
    
    if (key_len != 16 || iv_len != 16)
        return TEE_ERROR_BAD_PARAMETERS;
    
    if (*dst_len < src_len)
        return TEE_ERROR_SHORT_BUFFER;
    
    /* 分配AES CTR操作 */
    res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, 128);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 分配临时密钥对象 */
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key_handle);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 设置密钥值 */
    attr.attributeID = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = key;
    attr.content.ref.length = key_len;
    
    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 设置操作密钥 */
    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 执行加密 */
    res = TEE_CipherInit(op, iv, iv_len);
    if (res != TEE_SUCCESS)
        goto exit;
    
    *dst_len = src_len;
    res = TEE_CipherUpdate(op, src, src_len, dst, dst_len);
    
exit:
    if (op != TEE_HANDLE_NULL)
        TEE_FreeOperation(op);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(key_handle);
    
    return res;
}

/* AES解密实现 */
TEE_Result hdcp_aes_decrypt(uint8_t *key, uint32_t key_len,
                           uint8_t *iv, uint32_t iv_len,
                           uint8_t *src, uint32_t src_len,
                           uint8_t *dst, uint32_t *dst_len)
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    
    /* 检查参数 */
    if (!key || !iv || !src || !dst || !dst_len)
        return TEE_ERROR_BAD_PARAMETERS;
    
    if (key_len != 16 || iv_len != 16)
        return TEE_ERROR_BAD_PARAMETERS;
    
    if (*dst_len < src_len)
        return TEE_ERROR_SHORT_BUFFER;
    
    /* 分配AES CTR操作 */
    res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, 128);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 分配临时密钥对象 */
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key_handle);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 设置密钥值 */
    attr.attributeID = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = key;
    attr.content.ref.length = key_len;
    
    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 设置操作密钥 */
    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS)
        goto exit;
    
    /* 执行解密 */
    res = TEE_CipherInit(op, iv, iv_len);
    if (res != TEE_SUCCESS)
        goto exit;
    
    *dst_len = src_len;
    res = TEE_CipherUpdate(op, src, src_len, dst, dst_len);
    
exit:
    if (op != TEE_HANDLE_NULL)
        TEE_FreeOperation(op);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(key_handle);
    
    return res;
}

/* HDCP密码器初始化 */
TEE_Result hdcp_cipher_init(uint8_t *ks, uint8_t *riv, uint8_t *stream_ctr)
{
    /* 初始化HDCP密码器状态 */
    /* 在实际实现中，可能需要保存状态到全局或会话上下文中 */
    
    return TEE_SUCCESS;
}

/* HDCP视频数据解密实现 */
TEE_Result hdcp_decrypt_data(uint8_t *ks, uint8_t *riv, uint8_t *stream_ctr,
                            uint64_t input_ctr, uint8_t *input, uint32_t input_len,
                            uint8_t *output, uint32_t *output_len)
{
    TEE_Result res;
    uint8_t iv[16] = {0};
    uint8_t cipher_key[16] = {0};
    uint8_t lc128[16] = {0}; /* 实际实现中应从安全存储中加载 */
    int i;
    
    /* 检查参数 */
    if (!ks || !riv || !stream_ctr || !input || !output || !output_len)
        return TEE_ERROR_BAD_PARAMETERS;
    
    if (*output_len < input_len)
        return TEE_ERROR_SHORT_BUFFER;
    
    /* 构造IV: p = (riv XOR streamCtr) || inputCtr */
    for (i = 0; i < 8; i++) {
        iv[i] = riv[i] ^ stream_ctr[i % 4];
    }
    
    /* 设置inputCtr (64位) */
    for (i = 0; i < 8; i++) {
        iv[8 + i] = (input_ctr >> ((7-i)*8)) & 0xFF;
    }
    
    /* 创建会话密钥和全局常量的异或值 */
    for (i = 0; i < 16; i++) {
        cipher_key[i] = ks[i] ^ lc128[i];
    }
    
    /* 执行解密 */
    res = hdcp_aes_decrypt(cipher_key, 16, iv, 16, input, input_len, output, output_len);
    
    return res;
}

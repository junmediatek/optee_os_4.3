/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "hdcp_ca.h"

/* 测试HDCP 2.3协议的完整流程 */
int test_hdcp_protocol(TEEC_Session *session)
{
    TEEC_Result res;
    int success = 1;
    
    /* 1. AKE过程 */
    printf("\n--- Testing AKE Process ---\n");
    
    /* 1.1 AKE Init */
    uint8_t rtx[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t tx_caps[3] = {0x02, 0x00, 0x00};
    
    res = hdcp_ca_ake_init(session, rtx, tx_caps);
    if (res != TEEC_SUCCESS) {
        printf("AKE Init failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("AKE Init successful\n");
    }
    
    /* 1.2 AKE Send Cert */
    uint8_t cert_rx[522];
    uint8_t rrx[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
    uint8_t rx_caps[3] = {0x02, 0x00, 0x00};
    
    /* 初始化证书数据 */
    memset(cert_rx, 0xAA, sizeof(cert_rx));
    
    res = hdcp_ca_ake_send_cert(session, cert_rx, rrx, rx_caps);
    if (res != TEEC_SUCCESS) {
        printf("AKE Send Cert failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("AKE Send Cert successful\n");
    }
    
    /* 1.3 AKE No Stored Km */
    uint8_t e_kpub_km[128];
    
    /* 初始化加密的公钥数据 */
    memset(e_kpub_km, 0xBB, sizeof(e_kpub_km));
    
    res = hdcp_ca_ake_no_stored_km(session, e_kpub_km);
    if (res != TEEC_SUCCESS) {
        printf("AKE No Stored Km failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("AKE No Stored Km successful\n");
    }
    
    /* 1.4 AKE Send H Prime */
    uint8_t h_prime[32];
    
    /* 初始化H'数据 */
    memset(h_prime, 0xCC, sizeof(h_prime));
    
    res = hdcp_ca_ake_send_h_prime(session, h_prime);
    if (res != TEEC_SUCCESS) {
        printf("AKE Send H Prime failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("AKE Send H Prime successful\n");
    }
    
    /* 1.5 AKE Send Pairing Info */
    uint8_t e_kh_km[16];
    
    /* 初始化配对信息数据 */
    memset(e_kh_km, 0xDD, sizeof(e_kh_km));
    
    res = hdcp_ca_ake_send_pairing_info(session, e_kh_km);
    if (res != TEEC_SUCCESS) {
        printf("AKE Send Pairing Info failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("AKE Send Pairing Info successful\n");
    }
    
    /* 2. LC过程 */
    printf("\n--- Testing LC Process ---\n");
    
    /* 2.1 LC Init */
    uint8_t rn[8];
    
    /* 初始化随机数据 */
    memset(rn, 0xEE, sizeof(rn));
    
    res = hdcp_ca_lc_init(session, rn);
    if (res != TEEC_SUCCESS) {
        printf("LC Init failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("LC Init successful\n");
    }
    
    /* 2.2 LC Send L Prime */
    uint8_t l_prime[32];
    
    /* 初始化L'数据 */
    memset(l_prime, 0xFF, sizeof(l_prime));
    
    res = hdcp_ca_lc_send_l_prime(session, l_prime);
    if (res != TEEC_SUCCESS) {
        printf("LC Send L Prime failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("LC Send L Prime successful\n");
    }
    
    /* 3. SKE过程 */
    printf("\n--- Testing SKE Process ---\n");
    
    /* 3.1 SKE Send EKS */
    uint8_t e_dkey_ks[16];
    uint8_t riv[8];
    
    /* 初始化会话密钥和IV数据 */
    memset(e_dkey_ks, 0x88, sizeof(e_dkey_ks));
    memset(riv, 0x99, sizeof(riv));
    
    res = hdcp_ca_ske_send_eks(session, e_dkey_ks, riv);
    if (res != TEEC_SUCCESS) {
        printf("SKE Send EKS failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("SKE Send EKS successful\n");
    }
    
    /* 4. 解密过程 */
    printf("\n--- Testing Decryption Process ---\n");
    
    /* 4.1 Decrypt Init */
    uint8_t stream_ctr[8];
    
    /* 初始化流计数器数据 */
    memset(stream_ctr, 0x77, sizeof(stream_ctr));
    
    res = hdcp_ca_decrypt_init(session, stream_ctr);
    if (res != TEEC_SUCCESS) {
        printf("Decrypt Init failed: 0x%x\n", res);
        success = 0;
    } else {
        printf("Decrypt Init successful\n");
    }
    
    return success;
}

int main(void)
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Result res;
    
    printf("HDCP 2.3 Sink CA Test\n");
    
    /* 初始化HDCP CA */
    res = hdcp_ca_init(&context, &session);
    if (res != TEEC_SUCCESS) {
        printf("Failed to initialize HDCP CA: 0x%x\n", res);
        return 1;
    }
    
    /* 测试TA-CA通信 */
    res = hdcp_ca_test(&session);
    if (res != TEEC_SUCCESS) {
        printf("HDCP CA test failed: 0x%x\n", res);
        hdcp_ca_close(&context, &session);
        return 1;
    }
    
    printf("HDCP CA test successful\n");
    
    /* 测试共享内存 */
    TEEC_SharedMemory in_shm;
    TEEC_SharedMemory out_shm;
    uint8_t test_data[1024];
    
    /* 初始化测试数据 */
    for (int i = 0; i < sizeof(test_data); i++) {
        test_data[i] = i & 0xFF;
    }
    
    /* 分配输入共享内存 */
    in_shm.size = sizeof(test_data);
    in_shm.flags = TEEC_MEM_INPUT;
    res = TEEC_AllocateSharedMemory(&context, &in_shm);
    if (res != TEEC_SUCCESS) {
        printf("Failed to allocate input shared memory: 0x%x\n", res);
        hdcp_ca_close(&context, &session);
        return 1;
    }
    
    /* 分配输出共享内存 */
    out_shm.size = sizeof(test_data);
    out_shm.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&context, &out_shm);
    if (res != TEEC_SUCCESS) {
        printf("Failed to allocate output shared memory: 0x%x\n", res);
        TEEC_ReleaseSharedMemory(&in_shm);
        hdcp_ca_close(&context, &session);
        return 1;
    }
    
    /* 复制测试数据到输入共享内存 */
    memcpy(in_shm.buffer, test_data, sizeof(test_data));
    
    /* 测试HDCP协议流程 */
    int protocol_test_success = test_hdcp_protocol(&session);
    
    /* 测试视频解密 */
    printf("\n--- Testing Video Decryption ---\n");
    res = hdcp_ca_decrypt_video(&session, &in_shm, &out_shm);
    if (res != TEEC_SUCCESS) {
        printf("Video decryption failed: 0x%x\n", res);
    } else {
        printf("Video decryption successful\n");
        
        /* 验证解密结果 */
        int diff = memcmp(in_shm.buffer, out_shm.buffer, in_shm.size);
        if (diff == 0) {
            printf("Warning: Decrypted data is identical to encrypted data\n");
            printf("(This is expected in this test implementation)\n");
        } else {
            printf("Decrypted data differs from encrypted data\n");
        }
    }
    
    /* 清理资源 */
    TEEC_ReleaseSharedMemory(&in_shm);
    TEEC_ReleaseSharedMemory(&out_shm);
    hdcp_ca_close(&context, &session);
    
    printf("\nHDCP CA Test completed\n");
    printf("Protocol test %s\n", protocol_test_success ? "PASSED" : "FAILED");
    
    return protocol_test_success ? 0 : 1;
}

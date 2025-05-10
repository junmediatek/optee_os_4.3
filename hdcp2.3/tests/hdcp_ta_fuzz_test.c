/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tee_client_api.h>
#include "hdcp_ca.h"

/* 随机数据生成函数 */
static void generate_random_data(uint8_t *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

/* 模糊测试AKE初始化 */
static void fuzz_ake_init(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t rtx[8];
    uint8_t tx_caps[3];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing AKE Init (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(rtx, sizeof(rtx));
        generate_random_data(tx_caps, sizeof(tx_caps));
        
        /* 调用接口 */
        res = hdcp_ca_ake_init(session, rtx, tx_caps);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试AKE发送证书 */
static void fuzz_ake_send_cert(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t cert_rx[522];
    uint8_t rrx[8];
    uint8_t rx_caps[3];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing AKE Send Cert (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(cert_rx, sizeof(cert_rx));
        generate_random_data(rrx, sizeof(rrx));
        generate_random_data(rx_caps, sizeof(rx_caps));
        
        /* 调用接口 */
        res = hdcp_ca_ake_send_cert(session, cert_rx, rrx, rx_caps);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试AKE无存储Km */
static void fuzz_ake_no_stored_km(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t e_kpub_km[128];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing AKE No Stored Km (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(e_kpub_km, sizeof(e_kpub_km));
        
        /* 调用接口 */
        res = hdcp_ca_ake_no_stored_km(session, e_kpub_km);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试AKE存储Km */
static void fuzz_ake_stored_km(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t e_kh_km[16];
    uint8_t m[16];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing AKE Stored Km (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(e_kh_km, sizeof(e_kh_km));
        generate_random_data(m, sizeof(m));
        
        /* 调用接口 */
        res = hdcp_ca_ake_stored_km(session, e_kh_km, m);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试AKE发送H' */
static void fuzz_ake_send_h_prime(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t h_prime[32];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing AKE Send H Prime (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(h_prime, sizeof(h_prime));
        
        /* 调用接口 */
        res = hdcp_ca_ake_send_h_prime(session, h_prime);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试AKE发送配对信息 */
static void fuzz_ake_send_pairing_info(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t e_kh_km[16];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing AKE Send Pairing Info (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(e_kh_km, sizeof(e_kh_km));
        
        /* 调用接口 */
        res = hdcp_ca_ake_send_pairing_info(session, e_kh_km);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试LC初始化 */
static void fuzz_lc_init(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t rn[8];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing LC Init (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(rn, sizeof(rn));
        
        /* 调用接口 */
        res = hdcp_ca_lc_init(session, rn);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试LC发送L' */
static void fuzz_lc_send_l_prime(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t l_prime[32];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing LC Send L Prime (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(l_prime, sizeof(l_prime));
        
        /* 调用接口 */
        res = hdcp_ca_lc_send_l_prime(session, l_prime);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试SKE发送EKS */
static void fuzz_ske_send_eks(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t e_dkey_ks[16];
    uint8_t riv[8];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing SKE Send EKS (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(e_dkey_ks, sizeof(e_dkey_ks));
        generate_random_data(riv, sizeof(riv));
        
        /* 调用接口 */
        res = hdcp_ca_ske_send_eks(session, e_dkey_ks, riv);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试解密初始化 */
static void fuzz_decrypt_init(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    uint8_t stream_ctr[8];
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing Decrypt Init (%d iterations) ---\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(stream_ctr, sizeof(stream_ctr));
        
        /* 调用接口 */
        res = hdcp_ca_decrypt_init(session, stream_ctr);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试视频解密 */
static void fuzz_decrypt_video(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    TEEC_SharedMemory in_shm;
    TEEC_SharedMemory out_shm;
    const size_t buffer_size = 4096;
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing Decrypt Video (%d iterations) ---\n", iterations);
    
    /* 分配共享内存 */
    in_shm.size = buffer_size;
    in_shm.flags = TEEC_MEM_INPUT;
    if (TEEC_AllocateSharedMemory(&session->ctx, &in_shm) != TEEC_SUCCESS) {
        printf("Failed to allocate input shared memory\n");
        return;
    }
    
    out_shm.size = buffer_size;
    out_shm.flags = TEEC_MEM_OUTPUT;
    if (TEEC_AllocateSharedMemory(&session->ctx, &out_shm) != TEEC_SUCCESS) {
        printf("Failed to allocate output shared memory\n");
        TEEC_ReleaseSharedMemory(&in_shm);
        return;
    }
    
    for (int i = 0; i < iterations; i++) {
        /* 生成随机数据 */
        generate_random_data(in_shm.buffer, buffer_size);
        
        /* 调用接口 */
        res = hdcp_ca_decrypt_video(session, &in_shm, &out_shm);
        
        if (res == TEEC_SUCCESS) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed: 0x%x\n", i, res);
        }
    }
    
    /* 释放共享内存 */
    TEEC_ReleaseSharedMemory(&in_shm);
    TEEC_ReleaseSharedMemory(&out_shm);
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 模糊测试协议状态转换 */
static void fuzz_protocol_state_transitions(TEEC_Session *session, int iterations) {
    TEEC_Result res;
    int success_count = 0;
    int failure_count = 0;
    
    printf("\n--- Fuzzing Protocol State Transitions (%d iterations) ---\n", iterations);
    
    /* 为各种协议状态分配缓冲区 */
    uint8_t rtx[8], rrx[8], tx_caps[3], rx_caps[3];
    uint8_t cert_rx[522], e_kpub_km[128], h_prime[32];
    uint8_t e_kh_km[16], m[16], rn[8], l_prime[32];
    uint8_t e_dkey_ks[16], riv[8], stream_ctr[8];
    
    for (int i = 0; i < iterations; i++) {
        /* 生成所有随机数据 */
        generate_random_data(rtx, sizeof(rtx));
        generate_random_data(rrx, sizeof(rrx));
        generate_random_data(tx_caps, sizeof(tx_caps));
        generate_random_data(rx_caps, sizeof(rx_caps));
        generate_random_data(cert_rx, sizeof(cert_rx));
        generate_random_data(e_kpub_km, sizeof(e_kpub_km));
        generate_random_data(h_prime, sizeof(h_prime));
        generate_random_data(e_kh_km, sizeof(e_kh_km));
        generate_random_data(m, sizeof(m));
        generate_random_data(rn, sizeof(rn));
        generate_random_data(l_prime, sizeof(l_prime));
        generate_random_data(e_dkey_ks, sizeof(e_dkey_ks));
        generate_random_data(riv, sizeof(riv));
        generate_random_data(stream_ctr, sizeof(stream_ctr));
        
        /* 随机选择一个协议状态序列 */
        int steps = rand() % 5 + 1; /* 1-5步 */
        int success = 1;
        
        for (int step = 0; step < steps; step++) {
            int cmd = rand() % 11; /* 随机选择一个命令 */
            
            switch (cmd) {
                case 0:
                    res = hdcp_ca_ake_init(session, rtx, tx_caps);
                    break;
                case 1:
                    res = hdcp_ca_ake_send_cert(session, cert_rx, rrx, rx_caps);
                    break;
                case 2:
                    res = hdcp_ca_ake_no_stored_km(session, e_kpub_km);
                    break;
                case 3:
                    res = hdcp_ca_ake_stored_km(session, e_kh_km, m);
                    break;
                case 4:
                    res = hdcp_ca_ake_send_h_prime(session, h_prime);
                    break;
                case 5:
                    res = hdcp_ca_ake_send_pairing_info(session, e_kh_km);
                    break;
                case 6:
                    res = hdcp_ca_lc_init(session, rn);
                    break;
                case 7:
                    res = hdcp_ca_lc_send_l_prime(session, l_prime);
                    break;
                case 8:
                    res = hdcp_ca_ske_send_eks(session, e_dkey_ks, riv);
                    break;
                case 9:
                    res = hdcp_ca_decrypt_init(session, stream_ctr);
                    break;
                case 10:
                    /* 视频解密需要共享内存，这里跳过 */
                    res = TEEC_SUCCESS;
                    break;
            }
            
            if (res != TEEC_SUCCESS) {
                success = 0;
                break;
            }
        }
        
        if (success) {
            success_count++;
        } else {
            failure_count++;
            printf("  Iteration %d failed at step %d\n", i, steps);
        }
        
        /* 重置会话状态 */
        hdcp_ca_close(&session->ctx, session);
        
        TEEC_UUID uuid = HDCP_TA_UUID;
        uint32_t err_origin;
        res = TEEC_OpenSession(&session->ctx, session, &uuid,
                              TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
        if (res != TEEC_SUCCESS) {
            printf("Failed to reopen session: 0x%x, origin: %d\n", res, err_origin);
            break;
        }
    }
    
    printf("  Results: %d successes, %d failures\n", success_count, failure_count);
}

/* 主函数 */
int main(void)
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_UUID uuid = HDCP_TA_UUID;
    TEEC_Result res;
    uint32_t err_origin;
    
    /* 初始化随机数生成器 */
    srand(time(NULL));
    
    /* 初始化TEE上下文 */
    res = TEEC_InitializeContext(NULL, &context);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return 1;
    }
    
    /* 打开会话 */
    res = TEEC_OpenSession(&context, &session, &uuid,
                          TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x, origin: %d\n", res, err_origin);
        TEEC_FinalizeContext(&context);
        return 1;
    }
    
    printf("=== HDCP TA Fuzzing Test ===\n");
    
    /* 设置每个测试的迭代次数 */
    int iterations = 50;
    
    /* 执行各种模糊测试 */
    fuzz_ake_init(&session, iterations);
    fuzz_ake_send_cert(&session, iterations);
    fuzz_ake_no_stored_km(&session, iterations);
    fuzz_ake_stored_km(&session, iterations);
    fuzz_ake_send_h_prime(&session, iterations);
    fuzz_ake_send_pairing_info(&session, iterations);
    fuzz_lc_init(&session, iterations);
    fuzz_lc_send_l_prime(&session, iterations);
    fuzz_ske_send_eks(&session, iterations);
    fuzz_decrypt_init(&session, iterations);
    fuzz_decrypt_video(&session, iterations);
    
    /* 测试协议状态转换 */
    fuzz_protocol_state_transitions(&session, iterations);
    
    /* 清理资源 */
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    
    printf("\nHDCP TA Fuzzing Test completed\n");
    
    return 0;
}

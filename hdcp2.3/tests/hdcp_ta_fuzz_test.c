/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tee_client_api.h>
#include "hdcp_ca.h"

/* 测试结果结构 */
typedef struct {
    int success_count;
    int failure_count;
    int total_count;
} test_result_t;

/* 改进的随机数据生成函数 */
static void generate_random_data(uint8_t *buffer, size_t size) {
    static uint32_t seed = 0;
    
    /* 如果是第一次调用，使用时间初始化种子 */
    if (seed == 0) {
        seed = (uint32_t)time(NULL);
        srand(seed);
    }
    
    /* 使用更好的随机数生成算法 */
    for (size_t i = 0; i < size; i++) {
        /* 使用线性同余法生成更好的随机数 */
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        buffer[i] = (uint8_t)(seed % 256);
    }
}

/* 重置会话状态的辅助函数 */
static TEEC_Result reset_session(TEEC_Context *context, TEEC_Session *session) {
    TEEC_UUID uuid = HDCP_TA_UUID;
    uint32_t err_origin;
    
    /* 关闭当前会话 */
    hdcp_ca_close(context, session);
    
    /* 重新打开会话 */
    return TEEC_OpenSession(context, session, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
}

/* 通用测试执行函数 */
static test_result_t run_test(const char *test_name, TEEC_Session *session, 
                             TEEC_Result (*test_func)(TEEC_Session *, void *), 
                             void *params, int iterations) {
    TEEC_Result res;
    test_result_t result = {0, 0, iterations};
    
    printf("\n--- Fuzzing %s (%d iterations) ---\n", test_name, iterations);
    
    for (int i = 0; i < iterations; i++) {
        /* 调用测试函数 */
        res = test_func(session, params);
        
        if (res == TEEC_SUCCESS) {
            result.success_count++;
        } else {
            result.failure_count++;
            printf("  Iteration %d failed: 0x%x (%s)\n", i, res, 
                  (res == TEEC_ERROR_BAD_PARAMETERS) ? "Bad Parameters" : 
                  (res == TEEC_ERROR_GENERIC) ? "Generic Error" : 
                  (res == TEEC_ERROR_ACCESS_DENIED) ? "Access Denied" : "Unknown Error");
        }
    }
    
    printf("  Results: %d successes, %d failures\n", result.success_count, result.failure_count);
    return result;
}

/* AKE初始化测试函数 */
static TEEC_Result test_ake_init(TEEC_Session *session, void *params) {
    uint8_t rtx[8];
    uint8_t tx_caps[3];
    
    /* 生成随机数据 */
    generate_random_data(rtx, sizeof(rtx));
    generate_random_data(tx_caps, sizeof(tx_caps));
    
    /* 调用接口 */
    return hdcp_ca_ake_init(session, rtx, tx_caps);
}

/* 模糊测试AKE初始化 */
static void fuzz_ake_init(TEEC_Session *session, int iterations) {
    run_test("AKE Init", session, test_ake_init, NULL, iterations);
}

/* AKE发送证书测试函数 */
static TEEC_Result test_ake_send_cert(TEEC_Session *session, void *params) {
    uint8_t cert_rx[522];
    uint8_t rrx[8];
    uint8_t rx_caps[3];
    
    /* 生成随机数据 */
    generate_random_data(cert_rx, sizeof(cert_rx));
    generate_random_data(rrx, sizeof(rrx));
    generate_random_data(rx_caps, sizeof(rx_caps));
    
    /* 调用接口 */
    return hdcp_ca_ake_send_cert(session, cert_rx, rrx, rx_caps);
}

/* 模糊测试AKE发送证书 */
static void fuzz_ake_send_cert(TEEC_Session *session, int iterations) {
    run_test("AKE Send Cert", session, test_ake_send_cert, NULL, iterations);
}

/* AKE无存储Km测试函数 */
static TEEC_Result test_ake_no_stored_km(TEEC_Session *session, void *params) {
    uint8_t e_kpub_km[128];
    
    /* 生成随机数据 */
    generate_random_data(e_kpub_km, sizeof(e_kpub_km));
    
    /* 调用接口 */
    return hdcp_ca_ake_no_stored_km(session, e_kpub_km);
}

/* 模糊测试AKE无存储Km */
static void fuzz_ake_no_stored_km(TEEC_Session *session, int iterations) {
    run_test("AKE No Stored Km", session, test_ake_no_stored_km, NULL, iterations);
}

/* AKE存储Km测试函数 */
static TEEC_Result test_ake_stored_km(TEEC_Session *session, void *params) {
    uint8_t e_kh_km[16];
    uint8_t m[16];
    
    /* 生成随机数据 */
    generate_random_data(e_kh_km, sizeof(e_kh_km));
    generate_random_data(m, sizeof(m));
    
    /* 调用接口 */
    return hdcp_ca_ake_stored_km(session, e_kh_km, m);
}

/* 模糊测试AKE存储Km */
static void fuzz_ake_stored_km(TEEC_Session *session, int iterations) {
    run_test("AKE Stored Km", session, test_ake_stored_km, NULL, iterations);
}

/* AKE发送H'测试函数 */
static TEEC_Result test_ake_send_h_prime(TEEC_Session *session, void *params) {
    uint8_t h_prime[32];
    
    /* 生成随机数据 */
    generate_random_data(h_prime, sizeof(h_prime));
    
    /* 调用接口 */
    return hdcp_ca_ake_send_h_prime(session, h_prime);
}

/* 模糊测试AKE发送H' */
static void fuzz_ake_send_h_prime(TEEC_Session *session, int iterations) {
    run_test("AKE Send H Prime", session, test_ake_send_h_prime, NULL, iterations);
}

/* AKE发送配对信息测试函数 */
static TEEC_Result test_ake_send_pairing_info(TEEC_Session *session, void *params) {
    uint8_t e_kh_km[16];
    
    /* 生成随机数据 */
    generate_random_data(e_kh_km, sizeof(e_kh_km));
    
    /* 调用接口 */
    return hdcp_ca_ake_send_pairing_info(session, e_kh_km);
}

/* 模糊测试AKE发送配对信息 */
static void fuzz_ake_send_pairing_info(TEEC_Session *session, int iterations) {
    run_test("AKE Send Pairing Info", session, test_ake_send_pairing_info, NULL, iterations);
}

/* LC初始化测试函数 */
static TEEC_Result test_lc_init(TEEC_Session *session, void *params) {
    uint8_t rn[8];
    
    /* 生成随机数据 */
    generate_random_data(rn, sizeof(rn));
    
    /* 调用接口 */
    return hdcp_ca_lc_init(session, rn);
}

/* 模糊测试LC初始化 */
static void fuzz_lc_init(TEEC_Session *session, int iterations) {
    run_test("LC Init", session, test_lc_init, NULL, iterations);
}

/* LC发送L'测试函数 */
static TEEC_Result test_lc_send_l_prime(TEEC_Session *session, void *params) {
    uint8_t l_prime[32];
    
    /* 生成随机数据 */
    generate_random_data(l_prime, sizeof(l_prime));
    
    /* 调用接口 */
    return hdcp_ca_lc_send_l_prime(session, l_prime);
}

/* 模糊测试LC发送L' */
static void fuzz_lc_send_l_prime(TEEC_Session *session, int iterations) {
    run_test("LC Send L Prime", session, test_lc_send_l_prime, NULL, iterations);
}

/* SKE发送EKS测试函数 */
static TEEC_Result test_ske_send_eks(TEEC_Session *session, void *params) {
    uint8_t e_dkey_ks[16];
    uint8_t riv[8];
    
    /* 生成随机数据 */
    generate_random_data(e_dkey_ks, sizeof(e_dkey_ks));
    generate_random_data(riv, sizeof(riv));
    
    /* 调用接口 */
    return hdcp_ca_ske_send_eks(session, e_dkey_ks, riv);
}

/* 模糊测试SKE发送EKS */
static void fuzz_ske_send_eks(TEEC_Session *session, int iterations) {
    run_test("SKE Send EKS", session, test_ske_send_eks, NULL, iterations);
}

/* 解密初始化测试函数 */
static TEEC_Result test_decrypt_init(TEEC_Session *session, void *params) {
    uint8_t stream_ctr[8];
    
    /* 生成随机数据 */
    generate_random_data(stream_ctr, sizeof(stream_ctr));
    
    /* 调用接口 */
    return hdcp_ca_decrypt_init(session, stream_ctr);
}

/* 模糊测试解密初始化 */
static void fuzz_decrypt_init(TEEC_Session *session, int iterations) {
    run_test("Decrypt Init", session, test_decrypt_init, NULL, iterations);
}

/* 视频解密测试参数结构 */
typedef struct {
    TEEC_SharedMemory in_shm;
    TEEC_SharedMemory out_shm;
    int initialized;
} decrypt_video_params_t;

/* 视频解密测试函数 */
static TEEC_Result test_decrypt_video(TEEC_Session *session, void *params) {
    decrypt_video_params_t *test_params = (decrypt_video_params_t *)params;
    const size_t buffer_size = 4096;
    
    /* 如果共享内存尚未初始化，则初始化 */
    if (!test_params->initialized) {
        /* 初始化共享内存 */
        test_params->in_shm.size = buffer_size;
        test_params->in_shm.flags = TEEC_MEM_INPUT;
        
        if (TEEC_AllocateSharedMemory(&session->ctx, &test_params->in_shm) != TEEC_SUCCESS) {
            printf("Failed to allocate input shared memory\n");
            return TEEC_ERROR_OUT_OF_MEMORY;
        }
        
        test_params->out_shm.size = buffer_size;
        test_params->out_shm.flags = TEEC_MEM_OUTPUT;
        
        if (TEEC_AllocateSharedMemory(&session->ctx, &test_params->out_shm) != TEEC_SUCCESS) {
            printf("Failed to allocate output shared memory\n");
            TEEC_ReleaseSharedMemory(&test_params->in_shm);
            return TEEC_ERROR_OUT_OF_MEMORY;
        }
        
        test_params->initialized = 1;
    }
    
    /* 生成随机数据 */
    generate_random_data(test_params->in_shm.buffer, buffer_size);
    
    /* 调用接口 */
    return hdcp_ca_decrypt_video(session, &test_params->in_shm, &test_params->out_shm);
}

/* 模糊测试视频解密 */
static void fuzz_decrypt_video(TEEC_Session *session, int iterations) {
    decrypt_video_params_t params = {0};
    test_result_t result;
    
    result = run_test("Decrypt Video", session, test_decrypt_video, &params, iterations);
    
    /* 释放共享内存 */
    if (params.initialized) {
        TEEC_ReleaseSharedMemory(&params.in_shm);
        TEEC_ReleaseSharedMemory(&params.out_shm);
    }
}

/* 协议状态转换测试参数结构 */
typedef struct {
    uint8_t rtx[8], rrx[8], tx_caps[3], rx_caps[3];
    uint8_t cert_rx[522], e_kpub_km[128], h_prime[32];
    uint8_t e_kh_km[16], m[16], rn[8], l_prime[32];
    uint8_t e_dkey_ks[16], riv[8], stream_ctr[8];
    TEEC_Context *context;
} protocol_state_params_t;

/* 协议状态转换测试函数 */
static TEEC_Result test_protocol_state_transitions(TEEC_Session *session, void *params) {
    protocol_state_params_t *test_params = (protocol_state_params_t *)params;
    TEEC_Result res = TEEC_SUCCESS;
    
    /* 生成所有随机数据 */
    generate_random_data(test_params->rtx, sizeof(test_params->rtx));
    generate_random_data(test_params->rrx, sizeof(test_params->rrx));
    generate_random_data(test_params->tx_caps, sizeof(test_params->tx_caps));
    generate_random_data(test_params->rx_caps, sizeof(test_params->rx_caps));
    generate_random_data(test_params->cert_rx, sizeof(test_params->cert_rx));
    generate_random_data(test_params->e_kpub_km, sizeof(test_params->e_kpub_km));
    generate_random_data(test_params->h_prime, sizeof(test_params->h_prime));
    generate_random_data(test_params->e_kh_km, sizeof(test_params->e_kh_km));
    generate_random_data(test_params->m, sizeof(test_params->m));
    generate_random_data(test_params->rn, sizeof(test_params->rn));
    generate_random_data(test_params->l_prime, sizeof(test_params->l_prime));
    generate_random_data(test_params->e_dkey_ks, sizeof(test_params->e_dkey_ks));
    generate_random_data(test_params->riv, sizeof(test_params->riv));
    generate_random_data(test_params->stream_ctr, sizeof(test_params->stream_ctr));
    
    /* 随机选择一个协议状态序列 */
    int steps = rand() % 5 + 1; /* 1-5步 */
    
    for (int step = 0; step < steps; step++) {
        int cmd = rand() % 11; /* 随机选择一个命令 */
        
        switch (cmd) {
            case 0:
                res = hdcp_ca_ake_init(session, test_params->rtx, test_params->tx_caps);
                break;
            case 1:
                res = hdcp_ca_ake_send_cert(session, test_params->cert_rx, test_params->rrx, test_params->rx_caps);
                break;
            case 2:
                res = hdcp_ca_ake_no_stored_km(session, test_params->e_kpub_km);
                break;
            case 3:
                res = hdcp_ca_ake_stored_km(session, test_params->e_kh_km, test_params->m);
                break;
            case 4:
                res = hdcp_ca_ake_send_h_prime(session, test_params->h_prime);
                break;
            case 5:
                res = hdcp_ca_ake_send_pairing_info(session, test_params->e_kh_km);
                break;
            case 6:
                res = hdcp_ca_lc_init(session, test_params->rn);
                break;
            case 7:
                res = hdcp_ca_lc_send_l_prime(session, test_params->l_prime);
                break;
            case 8:
                res = hdcp_ca_ske_send_eks(session, test_params->e_dkey_ks, test_params->riv);
                break;
            case 9:
                res = hdcp_ca_decrypt_init(session, test_params->stream_ctr);
                break;
            case 10:
                /* 视频解密需要共享内存，这里跳过 */
                res = TEEC_SUCCESS;
                break;
        }
        
        if (res != TEEC_SUCCESS) {
            break;
        }
    }
    
    /* 重置会话状态 */
    reset_session(test_params->context, session);
    
    return res;
}

/* 模糊测试协议状态转换 */
static void fuzz_protocol_state_transitions(TEEC_Session *session, int iterations) {
    protocol_state_params_t params = {0};
    params.context = &session->ctx;
    
    run_test("Protocol State Transitions", session, test_protocol_state_transitions, &params, iterations);
}

/* 主函数 */
int main(void)
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_UUID uuid = HDCP_TA_UUID;
    TEEC_Result res;
    uint32_t err_origin;
    test_result_t results[12]; /* 存储所有测试结果 */
    int total_tests = 0;
    int total_success = 0;
    int total_failure = 0;
    int test_idx = 0;
    
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
    
    /* 执行各种模糊测试并收集结果 */
    results[test_idx++] = run_test("AKE Init", &session, test_ake_init, NULL, iterations);
    results[test_idx++] = run_test("AKE Send Cert", &session, test_ake_send_cert, NULL, iterations);
    results[test_idx++] = run_test("AKE No Stored Km", &session, test_ake_no_stored_km, NULL, iterations);
    results[test_idx++] = run_test("AKE Stored Km", &session, test_ake_stored_km, NULL, iterations);
    results[test_idx++] = run_test("AKE Send H Prime", &session, test_ake_send_h_prime, NULL, iterations);
    results[test_idx++] = run_test("AKE Send Pairing Info", &session, test_ake_send_pairing_info, NULL, iterations);
    results[test_idx++] = run_test("LC Init", &session, test_lc_init, NULL, iterations);
    results[test_idx++] = run_test("LC Send L Prime", &session, test_lc_send_l_prime, NULL, iterations);
    results[test_idx++] = run_test("SKE Send EKS", &session, test_ske_send_eks, NULL, iterations);
    results[test_idx++] = run_test("Decrypt Init", &session, test_decrypt_init, NULL, iterations);
    
    /* 视频解密测试需要特殊处理 */
    decrypt_video_params_t video_params = {0};
    results[test_idx++] = run_test("Decrypt Video", &session, test_decrypt_video, &video_params, iterations);
    
    /* 释放视频解密测试的共享内存 */
    if (video_params.initialized) {
        TEEC_ReleaseSharedMemory(&video_params.in_shm);
        TEEC_ReleaseSharedMemory(&video_params.out_shm);
    }
    
    /* 协议状态转换测试 */
    protocol_state_params_t protocol_params = {0};
    protocol_params.context = &session.ctx;
    results[test_idx++] = run_test("Protocol State Transitions", &session, test_protocol_state_transitions, &protocol_params, iterations);
    
    /* 计算总体结果 */
    for (int i = 0; i < test_idx; i++) {
        total_tests += results[i].total_count;
        total_success += results[i].success_count;
        total_failure += results[i].failure_count;
    }
    
    /* 清理资源 */
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    
    /* 打印总体结果 */
    printf("\n=== HDCP TA Fuzzing Test Summary ===\n");
    printf("Total tests: %d\n", total_tests);
    printf("Successful tests: %d (%.2f%%)\n", total_success, (float)total_success / total_tests * 100);
    printf("Failed tests: %d (%.2f%%)\n", total_failure, (float)total_failure / total_tests * 100);
    printf("\nHDCP TA Fuzzing Test completed\n");
    
    return (total_failure > 0) ? 1 : 0;
}

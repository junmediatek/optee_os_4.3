/*
 * Copyright (c) 2024, MediaTek
 */

#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "include/hdcp_ca.h"

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
    
    /* 模拟AKE过程 */
    uint8_t rtx[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t tx_caps[3] = {0x02, 0x00, 0x00};
    
    res = hdcp_ca_ake_init(&session, rtx, tx_caps);
    if (res != TEEC_SUCCESS) {
        printf("AKE Init failed: 0x%x\n", res);
    } else {
        printf("AKE Init successful\n");
    }
    
    /* 清理资源 */
    TEEC_ReleaseSharedMemory(&in_shm);
    TEEC_ReleaseSharedMemory(&out_shm);
    hdcp_ca_close(&context, &session);
    
    printf("HDCP CA Test completed\n");
    
    return 0;
}

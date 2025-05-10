/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef HDCP_TA_H
#define HDCP_TA_H

#include <stdint.h>

/* HDCP2.3 TA UUID - Use the generated UUID */
#define HDCP_TA_UUID { 0x692b0623, 0x850a, 0x46ca, { 0xa4, 0x31, 0x76, 0x3f, 0x7d, 0x94, 0x59, 0xb4 } }

/* HDCP 命令ID */
enum hdcp_cmd_id {
    /* AKE 命令 */
    HDCP_CMD_AKE_INIT = 0,          /* 发送AKE_Init */
    HDCP_CMD_AKE_SEND_CERT,         /* 处理AKE_Send_Cert */
    HDCP_CMD_AKE_NO_STORED_KM,      /* 处理AKE_No_Stored_km */
    HDCP_CMD_AKE_STORED_KM,         /* 处理AKE_Stored_km */
    HDCP_CMD_AKE_SEND_RRX,          /* 发送AKE_Send_rrx */
    HDCP_CMD_AKE_SEND_H_PRIME,      /* 发送AKE_Send_H_prime */
    HDCP_CMD_AKE_SEND_PAIRING_INFO, /* 发送AKE_Send_Pairing_Info */

    /* LC 命令 */
    HDCP_CMD_LC_INIT,               /* 处理LC_Init */
    HDCP_CMD_LC_SEND_L_PRIME,       /* 发送LC_Send_L_prime */

    /* SKE 命令 */
    HDCP_CMD_SKE_SEND_EKS,          /* 处理SKE_Send_Eks */

    /* 加密/解密命令 */
    HDCP_CMD_ENCRYPT_INIT,          /* 初始化加密 */
    HDCP_CMD_DECRYPT_INIT,          /* 初始化解密 */
    HDCP_CMD_ENCRYPT_VIDEO,         /* 加密视频数据 */
    HDCP_CMD_DECRYPT_VIDEO,         /* 解密视频数据 */

    /* 测试命令 */
    HDCP_CMD_TEST,                  /* 测试TA-CA通信 */
};

/* HDCP 参数类型 */
struct hdcp_param_ake_init {
    uint8_t r_tx[8];                /* rtx随机数 */
    uint8_t tx_caps[3];             /* transmitter capabilities */
};

struct hdcp_param_ake_send_cert {
    uint8_t cert_rx[522];           /* receiver certificate */
    uint8_t r_rx[8];                /* rrx随机数 */
    uint8_t rx_caps[3];             /* receiver capabilities */
};

struct hdcp_param_ake_no_stored_km {
    uint8_t e_kpub_km[128];         /* encrypted Kpub_km */
};

struct hdcp_param_ake_stored_km {
    uint8_t e_kh_km[16];            /* encrypted Kh_km */
    uint8_t m[16];                  /* m值 */
};

struct hdcp_param_ake_send_h_prime {
    uint8_t h_prime[32];            /* H' */
};

struct hdcp_param_ake_send_pairing_info {
    uint8_t e_kh_km[16];            /* encrypted Kh_km */
};

struct hdcp_param_lc_init {
    uint8_t r_n[8];                 /* rn随机数 */
};

struct hdcp_param_lc_send_l_prime {
    uint8_t l_prime[32];            /* L' */
};

struct hdcp_param_ske_send_eks {
    uint8_t e_dkey_ks[16];          /* encrypted session key */
    uint8_t riv[8];                 /* 随机初始化向量 */
};

struct hdcp_param_decrypt_init {
    uint8_t stream_ctr[4];          /* Stream counter */
};

struct hdcp_video_buffer {
    uint32_t buffer_size;           /* 缓冲区大小 */
    /* CA将使用TEE_RegisterSharedMemory或TEE_AllocateSharedMemory来分配内存 */
};

#endif /* HDCP_TA_H */

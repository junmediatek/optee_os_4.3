/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef __HDCP2_3_TA_H
#define __HDCP2_3_TA_H

/* 为HDCP2.3 TA定义一个唯一的UUID */
#define TA_HDCP2_3_UUID \
   { 0x692b0623, 0x850a, 0x46ca, \
      { 0xa4, 0x31, 0x76, 0x3f, 0x7d, 0x94, 0x59, 0xb4 } }

/* HDCP2.3 TA命令ID定义 */
/* 基本命令 */
#define TA_HDCP2_3_CMD_AKE_INIT            0x001
#define TA_HDCP2_3_CMD_AKE_SEND_CERT       0x002
#define TA_HDCP2_3_CMD_AKE_NO_STORED_KM    0x003
#define TA_HDCP2_3_CMD_AKE_STORED_KM       0x004
#define TA_HDCP2_3_CMD_AKE_SEND_RRX        0x005
#define TA_HDCP2_3_CMD_AKE_SEND_H_PRIME    0x006
#define TA_HDCP2_3_CMD_AKE_SEND_PAIRING    0x007
#define TA_HDCP2_3_CMD_LC_INIT             0x008
#define TA_HDCP2_3_CMD_LC_SEND_L_PRIME     0x009
#define TA_HDCP2_3_CMD_SKE_SEND_EKS        0x00A

/* 视频解密相关命令 */
#define TA_HDCP2_3_CMD_DECRYPT_VIDEO       0x100
#define TA_HDCP2_3_CMD_SET_STREAM_PARAMS   0x101

/* 状态查询命令 */
#define TA_HDCP2_3_CMD_GET_STATUS          0x200

/* 返回码定义 */
#define HDCP2_3_SUCCESS                    0x00000000
#define HDCP2_3_ERROR_AKE_FAILED           0x00000001
#define HDCP2_3_ERROR_LC_FAILED            0x00000002
#define HDCP2_3_ERROR_SKE_FAILED           0x00000003
#define HDCP2_3_ERROR_DECRYPT_FAILED       0x00000004
#define HDCP2_3_ERROR_INVALID_PARAMS       0x00000005
#define HDCP2_3_ERROR_NOT_READY            0x00000006

#endif /* __HDCP2_3_TA_H */

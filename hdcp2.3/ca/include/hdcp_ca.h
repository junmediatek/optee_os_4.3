/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, MediaTek
 */

#ifndef HDCP_CA_H
#define HDCP_CA_H

#include <tee_client_api.h>
#include <stdint.h>

/* HDCP CA API */

/* 初始化HDCP CA */
TEEC_Result hdcp_ca_init(TEEC_Context *context, TEEC_Session *session);

/* 关闭HDCP CA */
void hdcp_ca_close(TEEC_Context *context, TEEC_Session *session);

/* AKE函数 */
TEEC_Result hdcp_ca_ake_init(TEEC_Session *session, uint8_t *rtx, uint8_t *tx_caps);
TEEC_Result hdcp_ca_ake_send_cert(TEEC_Session *session, uint8_t *cert_rx, uint8_t *rrx, uint8_t *rx_caps);
TEEC_Result hdcp_ca_ake_no_stored_km(TEEC_Session *session, uint8_t *e_kpub_km);
TEEC_Result hdcp_ca_ake_stored_km(TEEC_Session *session, uint8_t *e_kh_km, uint8_t *m);
TEEC_Result hdcp_ca_ake_send_h_prime(TEEC_Session *session, uint8_t *h_prime);
TEEC_Result hdcp_ca_ake_send_pairing_info(TEEC_Session *session, uint8_t *e_kh_km);

/* LC函数 */
TEEC_Result hdcp_ca_lc_init(TEEC_Session *session, uint8_t *rn);
TEEC_Result hdcp_ca_lc_send_l_prime(TEEC_Session *session, uint8_t *l_prime);

/* SKE函数 */
TEEC_Result hdcp_ca_ske_send_eks(TEEC_Session *session, uint8_t *e_dkey_ks, uint8_t *riv);

/* 解密函数 */
TEEC_Result hdcp_ca_decrypt_init(TEEC_Session *session, uint8_t *stream_ctr);
TEEC_Result hdcp_ca_decrypt_video(TEEC_Session *session, 
                                 TEEC_SharedMemory *input_buffer,
                                 TEEC_SharedMemory *output_buffer);

/* 测试函数 */
TEEC_Result hdcp_ca_test(TEEC_Session *session);

#endif /* HDCP_CA_H */

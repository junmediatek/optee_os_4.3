#include "hdcp_ca_api.h"
#include "ta_hdcp_uuid.h" // For TA_HDCP_UUID
#include <stdio.h>    // For printf (debugging)
#include <string.h>   // For memcpy, memset

// Helper to print TEEC_Result errors from CA calls
static void ca_log_error(const char* func_name, TEEC_Result res, uint32_t err_origin)
{
    fprintf(stderr, "CA Error in %s: result=0x%x, origin=0x%x\n", func_name, res, err_origin);
}

/**
 * @brief Initializes the TEE context and opens a session with the HDCP TA.
 *
 * @param ca_session Pointer to the CA session structure to be initialized.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_init_session(hdcp_ca_session_t* ca_session)
{
    TEEC_UUID uuid = TA_HDCP_UUID;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session) return TEEC_ERROR_BAD_PARAMETERS;

    // Initialize context
    res = TEEC_InitializeContext(NULL, &ca_session->ctx);
    if (res != TEEC_SUCCESS) {
        ca_log_error("TEEC_InitializeContext", res, 0);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = 0; 
        return res;
    }

    // Open session
    res = TEEC_OpenSession(&ca_session->ctx, &ca_session->session, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("TEEC_OpenSession", res, err_origin);
        TEEC_FinalizeContext(&ca_session->ctx);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    printf("CA: Session with HDCP TA opened.\n");
    return res;
}

/**
 * @brief Closes the session with the HDCP TA and finalizes the TEE context.
 *
 * @param ca_session Pointer to the CA session structure.
 */
void hdcp_ca_close_session(hdcp_ca_session_t* ca_session)
{
    if (!ca_session) return;

    TEEC_CloseSession(&ca_session->session);
    TEEC_FinalizeContext(&ca_session->ctx);
    printf("CA: Session with HDCP TA closed.\n");
}

/**
 * @brief Invokes the TA to perform its internal initialization for an HDCP session.
 * This includes loading cryptographic keys and the device certificate.
 *
 * @param ca_session Pointer to the initialized CA session structure.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_ta_initialize(hdcp_ca_session_t* ca_session)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_INITIALIZE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_ta_initialize (CMD_HDCP_INITIALIZE)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Invokes the TA to finalize the HDCP session and release resources.
 *
 * @param ca_session Pointer to the CA session structure.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_ta_finalize(hdcp_ca_session_t* ca_session)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_FINALIZE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_ta_finalize (CMD_HDCP_FINALIZE)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Sends the AKE_Init message (rtx, TxCaps) from Transmitter to the TA.
 * Part of the HDCP Authentication and Key Exchange (AKE) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param rtx Pointer to the 8-byte rtx value from the Transmitter.
 * @param tx_caps Pointer to the 3-byte TxCaps value from the Transmitter.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_send_ake_init(hdcp_ca_session_t* ca_session, const uint8_t* rtx, const uint8_t* tx_caps)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    hdcp_message_buffer_t msg_buf;

    if (!ca_session || !rtx || !tx_caps) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    memset(&msg_buf, 0, sizeof(msg_buf));

    memcpy(msg_buf.message_buf, rtx, HDCP_RTX_SIZE);
    memcpy(msg_buf.message_buf + HDCP_RTX_SIZE, tx_caps, HDCP_TXCAPS_SIZE);
    msg_buf.message_len = HDCP_RTX_SIZE + HDCP_TXCAPS_SIZE;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &msg_buf;
    op.params[0].tmpref.size = sizeof(msg_buf); 

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_AKE_INIT_RECEIVED, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_send_ake_init (CMD_HDCP_AKE_INIT_RECEIVED)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Retrieves the AKE_Send_Cert message (cert_rx, rrx, RxCaps) from the TA.
 * Part of the HDCP Authentication and Key Exchange (AKE) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param cert_params_out Pointer to a structure to receive the cert_rx and rrx.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_get_ake_send_cert(hdcp_ca_session_t* ca_session, hdcp_ake_send_cert_params_t* cert_params_out)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session || !cert_params_out) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = cert_params_out;
    op.params[0].tmpref.size = sizeof(hdcp_ake_send_cert_params_t);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_AKE_SEND_CERT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_get_ake_send_cert (CMD_HDCP_AKE_SEND_CERT)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Sends the AKE_No_Stored_km message (Ekpub(km)) from Transmitter to the TA.
 * Used when the Transmitter is performing pairing and sending the master key km.
 * Part of the HDCP Authentication and Key Exchange (AKE) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param ekpub_km Pointer to the 128-byte Ekpub(km) value.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_send_ake_no_stored_km(hdcp_ca_session_t* ca_session, const uint8_t* ekpub_km)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    hdcp_message_buffer_t msg_buf;

    if (!ca_session || !ekpub_km) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    memset(&msg_buf, 0, sizeof(msg_buf));

    memcpy(msg_buf.message_buf, ekpub_km, HDCP_EKHPUB_KM_SIZE); 
    msg_buf.message_len = HDCP_EKHPUB_KM_SIZE;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &msg_buf;
    op.params[0].tmpref.size = sizeof(msg_buf);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_AKE_NO_STORED_KM_RECEIVED, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_send_ake_no_stored_km (CMD_HDCP_AKE_NO_STORED_KM_RECEIVED)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Sends the AKE_Stored_km message (Ekh(km), m) from Transmitter to the TA.
 * Used when the Transmitter believes the Receiver has a stored master key km.
 * Part of the HDCP Authentication and Key Exchange (AKE) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param ekh_km Pointer to the 16-byte Ekh(km) value.
 * @param m Pointer to the 16-byte m value.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_send_ake_stored_km(hdcp_ca_session_t* ca_session, const uint8_t* ekh_km, const uint8_t* m)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    hdcp_message_buffer_t msg_buf;

    if (!ca_session || !ekh_km || !m) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    memset(&msg_buf, 0, sizeof(msg_buf));

    memcpy(msg_buf.message_buf, ekh_km, HDCP_EKH_KM_SIZE); 
    memcpy(msg_buf.message_buf + HDCP_EKH_KM_SIZE, m, HDCP_M_SIZE); 
    msg_buf.message_len = HDCP_EKH_KM_SIZE + HDCP_M_SIZE;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &msg_buf;
    op.params[0].tmpref.size = sizeof(msg_buf);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_AKE_STORED_KM_RECEIVED, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_send_ake_stored_km (CMD_HDCP_AKE_STORED_KM_RECEIVED)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Retrieves H_prime and optionally Pairing_Info (Ekh(km)) from the TA.
 * Part of the HDCP Authentication and Key Exchange (AKE) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param h_prime_out Pointer to a structure to receive H_prime.
 * @param pairing_info_out Pointer to a structure to receive Ekh(km) if pairing occurred.
 * @param sent_pairing_info Pointer to a boolean that will be true if pairing info was sent by TA.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_get_ake_h_prime(hdcp_ca_session_t* ca_session, 
                                 hdcp_ake_send_h_prime_params_t* h_prime_out, 
                                 hdcp_ake_send_pairing_info_params_t* pairing_info_out, 
                                 bool* sent_pairing_info)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session || !h_prime_out || !pairing_info_out || !sent_pairing_info) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = h_prime_out;
    op.params[0].tmpref.size = sizeof(hdcp_ake_send_h_prime_params_t);
    op.params[1].tmpref.buffer = pairing_info_out;
    op.params[1].tmpref.size = sizeof(hdcp_ake_send_pairing_info_params_t);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_AKE_GENERATE_H_PRIME, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_get_ake_h_prime (CMD_HDCP_AKE_GENERATE_H_PRIME)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
        *sent_pairing_info = false;
    } else {
        // TA updates params[1].tmpref.size to 0 if no pairing info is sent.
        if (op.params[1].tmpref.size == sizeof(hdcp_ake_send_pairing_info_params_t)) {
            *sent_pairing_info = true;
        } else {
            *sent_pairing_info = false;
        }
    }
    return res;
}

/**
 * @brief Sends the LC_Init message (rn_lc) from Transmitter to the TA and retrieves L_prime.
 * Part of the HDCP Locality Check (LC) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param rn_lc Pointer to the 8-byte rn_lc value from the Transmitter.
 * @param l_prime_out Pointer to a structure to receive L_prime.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_send_lc_init(hdcp_ca_session_t* ca_session, const uint8_t* rn_lc, hdcp_lc_send_l_prime_params_t* l_prime_out)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    hdcp_message_buffer_t msg_buf; 

    if (!ca_session || !rn_lc || !l_prime_out) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    memset(&msg_buf, 0, sizeof(msg_buf));

    memcpy(msg_buf.message_buf, rn_lc, HDCP_RN_SIZE);
    msg_buf.message_len = HDCP_RN_SIZE;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &msg_buf;
    op.params[0].tmpref.size = sizeof(msg_buf);
    op.params[1].tmpref.buffer = l_prime_out;
    op.params[1].tmpref.size = sizeof(hdcp_lc_send_l_prime_params_t);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_LC_INIT_RECEIVED, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_send_lc_init (CMD_HDCP_LC_INIT_RECEIVED)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Sends the SKE_Send_Eks message (Edkey(ks), riv) from Transmitter to the TA.
 * Part of the HDCP Session Key Exchange (SKE) phase.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param edkey_ks Pointer to the 16-byte Edkey(ks) value.
 * @param riv Pointer to the 8-byte riv value.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_send_ske_eks(hdcp_ca_session_t* ca_session, const uint8_t* edkey_ks, const uint8_t* riv)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    hdcp_message_buffer_t msg_buf;

    if (!ca_session || !edkey_ks || !riv) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    memset(&msg_buf, 0, sizeof(msg_buf));

    memcpy(msg_buf.message_buf, edkey_ks, HDCP_EDKEY_KS_SIZE); 
    memcpy(msg_buf.message_buf + HDCP_EDKEY_KS_SIZE, riv, HDCP_RIV_SIZE); 
    msg_buf.message_len = HDCP_EDKEY_KS_SIZE + HDCP_RIV_SIZE;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &msg_buf;
    op.params[0].tmpref.size = sizeof(msg_buf);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_SKE_SEND_EKS_RECEIVED, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_send_ske_eks (CMD_HDCP_SKE_SEND_EKS_RECEIVED)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Sends an encrypted video packet to the TA for decryption.
 * Assumes HDCP authentication is complete and session keys are established.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param video_data_in_out Pointer to the buffer containing the encrypted video data. 
 *                          This buffer will be overwritten with decrypted data.
 * @param data_len Length of the video data in the buffer.
 * @param input_ctr The 64-bit input counter value for AES-CTR mode for this packet.
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_decrypt_video_packet(hdcp_ca_session_t* ca_session, uint8_t* video_data_in_out, uint32_t data_len, uint64_t input_ctr)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session || !video_data_in_out || data_len == 0) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = video_data_in_out;
    op.params[0].tmpref.size = data_len;
    op.params[1].value.a = (uint32_t)(input_ctr & 0xFFFFFFFF);
    op.params[1].value.b = (uint32_t)(input_ctr >> 32);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_DECRYPT_VIDEO_PACKET, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_decrypt_video_packet (CMD_HDCP_DECRYPT_VIDEO_PACKET)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    }
    return res;
}

/**
 * @brief Retrieves the current HDCP authentication status from the TA.
 *
 * @param ca_session Pointer to the CA session structure.
 * @param hdcp_status Pointer to a uint32_t to receive the HDCP status code (hdcp_auth_state_t).
 * @return TEEC_Result TEEC_SUCCESS on success, or an error code otherwise.
 */
TEEC_Result hdcp_ca_get_ta_status(hdcp_ca_session_t* ca_session, uint32_t* hdcp_status)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    if (!ca_session || !hdcp_status) return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&ca_session->session, CMD_HDCP_GET_STATUS, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ca_log_error("hdcp_ca_get_ta_status (CMD_HDCP_GET_STATUS)", res, err_origin);
        ca_session->last_error_code = res;
        ca_session->last_error_origin = err_origin;
    } else {
        *hdcp_status = op.params[0].value.a;
    }
    return res;
}


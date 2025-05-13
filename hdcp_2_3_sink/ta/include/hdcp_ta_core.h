#ifndef HDCP_TA_CORE_H
#define HDCP_TA_CORE_H

#include "hdcp_ta_types.h"
#include "tee_api_types.h"

// --- HDCP Protocol Engine --- (Functions called by TA_InvokeCommandEntryPoint based on cmd_id)

// AKE Handlers
TEE_Result handle_ake_init(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* ake_init_msg);
TEE_Result handle_generate_ake_send_cert(hdcp_session_context_t* ctx, hdcp_ake_send_cert_params_t* cert_params);
TEE_Result handle_ake_no_stored_km(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* no_stored_km_msg);
TEE_Result handle_ake_stored_km(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* stored_km_msg);
TEE_Result handle_generate_ake_h_prime_and_pairing(hdcp_session_context_t* ctx, hdcp_ake_send_h_prime_params_t* h_prime_params, hdcp_ake_send_pairing_info_params_t* pairing_params, bool* send_pairing_info);

// LC Handlers
TEE_Result handle_lc_init(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* lc_init_msg, hdcp_lc_send_l_prime_params_t* l_prime_params);

// SKE Handlers
TEE_Result handle_ske_send_eks(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* ske_msg);

// --- Secure Content Decryption Module --- (Functions called by TA_InvokeCommandEntryPoint)
TEE_Result handle_decrypt_video_packet(
    hdcp_session_context_t* ctx, 
    uint8_t* data_buffer, // In/Out buffer for decryption
    uint32_t data_len, 
    uint64_t input_ctr
);

// --- Utility functions ---
void XOR_128(uint8_t* out, const uint8_t* in1, const uint8_t* in2);
void print_hex(const char* label, const uint8_t* data, uint32_t len);

#endif // HDCP_TA_CORE_H


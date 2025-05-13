#ifndef HDCP_CA_API_H
#define HDCP_CA_API_H

#include "hdcp_common_ta_ca.h" // For shared command IDs and structures
#include <tee_client_api.h>     // For TEEC_Result, TEEC_Session, etc.

// Structure to hold CA session information with the TA
typedef struct {
    TEEC_Context ctx;
    TEEC_Session session;
    uint32_t last_error_origin;
    TEEC_Result last_error_code; // Corrected
} hdcp_ca_session_t;

// --- CA API Functions ---

// Session Management
TEEC_Result hdcp_ca_init_session(hdcp_ca_session_t* ca_session); // Corrected
void hdcp_ca_close_session(hdcp_ca_session_t* ca_session);

// HDCP TA Initialization/Finalization
TEEC_Result hdcp_ca_ta_initialize(hdcp_ca_session_t* ca_session); // Corrected
TEEC_Result hdcp_ca_ta_finalize(hdcp_ca_session_t* ca_session); // Corrected

// AKE (Authentication and Key Exchange)
TEEC_Result hdcp_ca_send_ake_init(hdcp_ca_session_t* ca_session, const uint8_t* rtx, const uint8_t* tx_caps); // Corrected
TEEC_Result hdcp_ca_get_ake_send_cert(hdcp_ca_session_t* ca_session, hdcp_ake_send_cert_params_t* cert_params_out); // Corrected
TEEC_Result hdcp_ca_send_ake_no_stored_km(hdcp_ca_session_t* ca_session, const uint8_t* ekpub_km); // Corrected
TEEC_Result hdcp_ca_send_ake_stored_km(hdcp_ca_session_t* ca_session, const uint8_t* ekh_km, const uint8_t* m); // Corrected
TEEC_Result hdcp_ca_get_ake_h_prime(hdcp_ca_session_t* ca_session, hdcp_ake_send_h_prime_params_t* h_prime_out, hdcp_ake_send_pairing_info_params_t* pairing_info_out, bool* sent_pairing_info); // Corrected

// LC (Locality Check)
TEEC_Result hdcp_ca_send_lc_init(hdcp_ca_session_t* ca_session, const uint8_t* rn_lc, hdcp_lc_send_l_prime_params_t* l_prime_out); // Corrected

// SKE (Session Key Exchange)
TEEC_Result hdcp_ca_send_ske_eks(hdcp_ca_session_t* ca_session, const uint8_t* edkey_ks, const uint8_t* riv); // Corrected

// Content Decryption
TEEC_Result hdcp_ca_decrypt_video_packet(hdcp_ca_session_t* ca_session, uint8_t* video_data_in_out, uint32_t data_len, uint64_t input_ctr); // Corrected

// Status
TEEC_Result hdcp_ca_get_ta_status(hdcp_ca_session_t* ca_session, uint32_t* hdcp_status); // Corrected

#endif // HDCP_CA_API_H


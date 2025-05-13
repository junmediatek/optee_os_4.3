#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../include/hdcp_ca_api.h" // Adjust path as needed
#include "../../include/hdcp_common_ta_ca.h" // For HDCP_STATE_AUTHENTICATED and other constants

// Helper to print hex for debugging CA test
void print_ca_hex(const char* label, const uint8_t* data, uint32_t len)
{
    printf("%s (%u bytes): ", label, len);
    for (uint32_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// Placeholder for actual Transmitter values - replace with real test vectors
static const uint8_t test_rtx_val[HDCP_RTX_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
// TxCaps: HDCP 2.3 Supported (bit 4), Pairing Supported (bit 5)
static const uint8_t test_tx_caps_val[HDCP_TXCAPS_SIZE] = {0x30, 0x00, 0x00}; // 0b00110000

// For AKE_No_Stored_Km: Ekpub(km) - 128 bytes (placeholder)
static uint8_t test_ekpub_km[HDCP_EKHPUB_KM_SIZE]; 

// For AKE_Stored_Km: Ekh(km) - 16 bytes, m - 16 bytes (placeholders)
static uint8_t test_ekh_km[HDCP_EKH_KM_SIZE];
static uint8_t test_m[HDCP_M_SIZE];

// For LC_Init: rn_lc - 8 bytes (placeholder)
static uint8_t test_rn_lc_val[HDCP_RN_SIZE];

// For SKE_Send_Eks: Edkey(ks) - 16 bytes, riv - 8 bytes (placeholders)
static uint8_t test_edkey_ks_val[HDCP_EDKEY_KS_SIZE];
static uint8_t test_riv_val[HDCP_RIV_SIZE];

// For video decryption test
static uint8_t test_encrypted_video_packet[256]; // Placeholder encrypted data
static const uint32_t test_video_packet_len = sizeof(test_encrypted_video_packet);
static const uint64_t test_video_input_ctr = 0x0000000000000001ULL;

void initialize_test_vectors() {
    // Fill placeholder test vectors with some non-zero data for basic testing
    for(int i=0; i<HDCP_EKHPUB_KM_SIZE; ++i) test_ekpub_km[i] = (uint8_t)(i + 0x10);
    for(int i=0; i<HDCP_EKH_KM_SIZE; ++i) test_ekh_km[i] = (uint8_t)(i + 0xA0);
    for(int i=0; i<HDCP_M_SIZE; ++i) test_m[i] = (uint8_t)(i + 0xB0);
    for(int i=0; i<HDCP_RN_SIZE; ++i) test_rn_lc_val[i] = (uint8_t)(i + 0xC0);
    for(int i=0; i<HDCP_EDKEY_KS_SIZE; ++i) test_edkey_ks_val[i] = (uint8_t)(i + 0xD0);
    for(int i=0; i<HDCP_RIV_SIZE; ++i) test_riv_val[i] = (uint8_t)(i + 0xE0);
    for(uint32_t i=0; i<test_video_packet_len; ++i) test_encrypted_video_packet[i] = (uint8_t)(i % 0xFF); // Corrected loop condition
}

int main(int argc, char* argv[]) {
    hdcp_ca_session_t ca_session;
    TEEC_Result res; // Corrected type
    uint32_t ta_status = HDCP_STATE_UNINITIALIZED; // Initialize ta_status
    bool run_pairing_flow = true; // Set to false to test stored_km flow (requires prior pairing)

    // Declarations moved to the top to avoid goto errors
    hdcp_ake_send_cert_params_t cert_params;
    hdcp_ake_send_h_prime_params_t h_prime_params;
    hdcp_ake_send_pairing_info_params_t pairing_info_params; // Ekh(km)
    bool sent_pairing_info = false;
    hdcp_lc_send_l_prime_params_t l_prime_params;
    uint8_t video_packet_copy[test_video_packet_len];

    if (argc > 1 && strcmp(argv[1], "nopairing") == 0) {
        run_pairing_flow = false;
        printf("INFO: Running NO-PAIRING (stored_km) test flow.\n");
    } else {
        printf("INFO: Running PAIRING (no_stored_km) test flow.\n");
    }

    initialize_test_vectors();

    printf("--- Test HDCP CA API ---\n");

    // 1. Initialize session with TA
    printf("1. Initializing session with TA...\n");
    res = hdcp_ca_init_session(&ca_session);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_init_session failed: 0x%x\n", res);
        return -1;
    }
    printf("   Session initialized successfully.\n");

    // 2. Initialize HDCP TA
    printf("2. Initializing HDCP TA...\n");
    res = hdcp_ca_ta_initialize(&ca_session);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_ta_initialize failed: 0x%x\n", res);
        hdcp_ca_close_session(&ca_session);
        return -1;
    }
    printf("   HDCP TA initialized successfully.\n");

    // --- AKE Phase ---
    printf("--- AKE Phase ---\n");
    // 3. Send AKE_Init from Transmitter
    printf("3. Sending AKE_Init (rtx, TxCaps) to TA...\n");
    print_ca_hex("   Test rtx", test_rtx_val, HDCP_RTX_SIZE);
    print_ca_hex("   Test TxCaps", test_tx_caps_val, HDCP_TXCAPS_SIZE);
    res = hdcp_ca_send_ake_init(&ca_session, test_rtx_val, test_tx_caps_val);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_send_ake_init failed: 0x%x\n", res);
        goto cleanup_fail;
    }
    printf("   AKE_Init sent successfully.\n");

    // 4. Get AKE_Send_Cert from TA
    printf("4. Getting AKE_Send_Cert (cert_rx, rrx) from TA...\n");
    res = hdcp_ca_get_ake_send_cert(&ca_session, &cert_params);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_get_ake_send_cert failed: 0x%x\n", res);
        goto cleanup_fail;
    }
    print_ca_hex("   Received cert_rx (first 32 bytes)", cert_params.cert_rx, 32);
    print_ca_hex("   Received rrx", cert_params.rrx, HDCP_RRX_SIZE);
    printf("   AKE_Send_Cert received successfully.\n");

    if (run_pairing_flow) {
        // 5. Send AKE_No_Stored_Km (for pairing)
        printf("5. Sending AKE_No_Stored_Km (Ekpub(km)) to TA...\n");
        print_ca_hex("   Test Ekpub(km) (first 16 bytes)", test_ekpub_km, 16);
        res = hdcp_ca_send_ake_no_stored_km(&ca_session, test_ekpub_km);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "ERROR: hdcp_ca_send_ake_no_stored_km failed: 0x%x\n", res);
            goto cleanup_fail;
        }
        printf("   AKE_No_Stored_Km sent successfully.\n");
    } else {
        // 5. Send AKE_Stored_Km (for existing pairing)
        printf("5. Sending AKE_Stored_Km (Ekh(km), m) to TA...\n");
        print_ca_hex("   Test Ekh(km)", test_ekh_km, HDCP_EKH_KM_SIZE);
        print_ca_hex("   Test m", test_m, HDCP_M_SIZE);
        res = hdcp_ca_send_ake_stored_km(&ca_session, test_ekh_km, test_m);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "ERROR: hdcp_ca_send_ake_stored_km failed: 0x%x\n", res);
            fprintf(stderr, "   This might be expected if no prior pairing with rtx 0102...08 exists.\n");
            goto cleanup_fail;
        }
        printf("   AKE_Stored_Km sent successfully.\n");
    }

    // 6. Get H_prime (and pairing info if applicable) from TA
    printf("6. Getting H_prime and Pairing_Info from TA...\n");
    res = hdcp_ca_get_ake_h_prime(&ca_session, &h_prime_params, &pairing_info_params, &sent_pairing_info);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_get_ake_h_prime failed: 0x%x\n", res);
        goto cleanup_fail;
    }
    print_ca_hex("   Received H_prime", h_prime_params.h_prime, HDCP_H_PRIME_SIZE);
    if (sent_pairing_info) {
        print_ca_hex("   Received Pairing_Info Ekh(km)", pairing_info_params.ekh_km, HDCP_EKH_KM_SIZE);
        printf("   Pairing Info was sent by TA.\n");
    } else {
        printf("   Pairing Info was NOT sent by TA.\n");
    }
    printf("   H_prime (and Pairing_Info if any) received successfully.\n");

    // --- LC Phase ---
    printf("--- LC Phase ---\n");
    // 7. Send LC_Init from Transmitter and get L_prime from TA
    printf("7. Sending LC_Init (rn_lc) and getting L_prime from TA...\n");
    print_ca_hex("   Test rn_lc", test_rn_lc_val, HDCP_RN_SIZE);
    res = hdcp_ca_send_lc_init(&ca_session, test_rn_lc_val, &l_prime_params);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_send_lc_init failed: 0x%x\n", res);
        goto cleanup_fail;
    }
    print_ca_hex("   Received L_prime", l_prime_params.l_prime, HDCP_L_PRIME_SIZE);
    printf("   LC_Init sent and L_prime received successfully.\n");

    // --- SKE Phase ---
    printf("--- SKE Phase ---\n");
    // 8. Send SKE_Send_Eks from Transmitter
    printf("8. Sending SKE_Send_Eks (Edkey(ks), riv) to TA...\n");
    print_ca_hex("   Test Edkey(ks)", test_edkey_ks_val, HDCP_EDKEY_KS_SIZE);
    print_ca_hex("   Test riv", test_riv_val, HDCP_RIV_SIZE);
    res = hdcp_ca_send_ske_eks(&ca_session, test_edkey_ks_val, test_riv_val);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_send_ske_eks failed: 0x%x\n", res);
        goto cleanup_fail;
    }
    printf("   SKE_Send_Eks sent successfully.\n");

    // 9. Verify TA status is AUTHENTICATED
    printf("9. Verifying TA status...\n");
    res = hdcp_ca_get_ta_status(&ca_session, &ta_status);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_get_ta_status failed: 0x%x\n", res);
        goto cleanup_fail;
    }
    printf("   TA Status: 0x%x (Expected AUTHENTICATED: %d)\n", ta_status, HDCP_STATE_AUTHENTICATED);
    if (ta_status != HDCP_STATE_AUTHENTICATED) {
        fprintf(stderr, "ERROR: TA not in AUTHENTICATED state!\n");
        goto cleanup_fail;
    }
    printf("   TA is AUTHENTICATED.\n");

    // 10. Simulate video packet decryption
    printf("10. Simulating video packet decryption...\n");
    memcpy(video_packet_copy, test_encrypted_video_packet, test_video_packet_len);
    print_ca_hex("   Original Encrypted Video Packet (first 16 bytes)", video_packet_copy, 16);
    res = hdcp_ca_decrypt_video_packet(&ca_session, video_packet_copy, test_video_packet_len, test_video_input_ctr);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_decrypt_video_packet failed: 0x%x\n", res);
        // Not necessarily a fatal error for the rest of the cleanup, but test fails.
    } else {
        print_ca_hex("   Decrypted Video Packet (first 16 bytes)", video_packet_copy, 16);
        printf("   Video packet decryption successful (check content manually if actual crypto is implemented).\n");
    }

    printf("--- Test Completed Successfully (or with decrypt error) ---\n");

cleanup_fail:
    // 11. Finalize HDCP TA
    printf("11. Finalizing HDCP TA...\n");
    TEEC_Result finalize_res = hdcp_ca_ta_finalize(&ca_session); // Use a different TEEC_Result variable
    if (finalize_res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR: hdcp_ca_ta_finalize failed: 0x%x\n", finalize_res);
        // Continue cleanup
    }
    printf("   HDCP TA finalized.\n");

    // 12. Close session
    printf("12. Closing session with TA...\n");
    hdcp_ca_close_session(&ca_session);
    printf("   Session closed.\n");

    // Final test result determination based on original `res` and `ta_status` before cleanup
    if (ta_status == HDCP_STATE_AUTHENTICATED && res == TEEC_SUCCESS) {
         printf("\n*** HDCP CA Test: PASSED (Authenticated and basic flow completed) ***\n");
         return 0;
    } else {
         printf("\n*** HDCP CA Test: FAILED (See errors above) ***\n");
         return -1;
    }
}


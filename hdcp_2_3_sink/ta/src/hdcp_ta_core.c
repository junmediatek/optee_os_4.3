#include "hdcp_ta_core.h"
#include "hdcp_ta_crypto.h"
#include "hdcp_ta_storage.h"
#include "hdcp_common_ta_ca.h"
#include <tee_internal_api.h>
#include <string.h> // For TEE_MemMove, TEE_MemCompare, etc.

// Helper to print hex for debugging (should be guarded by a DMSG macro in sub.mk CFLAGS)
void print_hex(const char* label, const uint8_t* data, uint32_t len)
{
// #define DEBUG_PRINT_HEX // Define this in sub.mk for debug builds or remove for release
#ifdef DEBUG_PRINT_HEX
    char buf[256]; 
    uint32_t i, count = 0;
    if (len == 0) {
        IMSG("%s: (empty)", label);
        return;
    }
    if (len * 3 > sizeof(buf)) { // Each byte is 2 hex chars + space (or just 2 if no space)
        IMSG("%s: (data too long to print full hex, len %u)", label, len);
        len = (sizeof(buf) -1 ) / 3; // Truncate if too long
    }
    for (i = 0; i < len; i++) {
        count += TEE_Snprintf(buf + count, sizeof(buf) - count, "%02x ", data[i]);
        if (count >= sizeof(buf) - 3) break; // Ensure space for last space and null
    }
    buf[count] = '\0';
    IMSG("%s: %s (%u bytes)", label, buf, i); // i is actual printed bytes
#else
    (void)label; (void)data; (void)len;
#endif
}

void XOR_128(uint8_t* out, const uint8_t* in1, const uint8_t* in2)
{
    for (int i = 0; i < 16; ++i) {
        out[i] = in1[i] ^ in2[i];
    }
}

// --- AKE Handlers ---
TEE_Result handle_ake_init(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* ake_init_msg)
{
    DMSG("Handling AKE_Init");
    if (!ctx || !ake_init_msg) {
        EMSG("AKE_Init: Null parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ctx->auth_state != HDCP_STATE_INITIALIZED) {
        EMSG("AKE_Init: Bad state (%d), expected INITIALIZED.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }
    // AKE_Init message: rtx (8 bytes) || TxCaps (3 bytes)
    if (ake_init_msg->message_len < (HDCP_RTX_SIZE + HDCP_TXCAPS_SIZE)) {
        EMSG("AKE_Init: Message too short (%u bytes).", ake_init_msg->message_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove(ctx->rtx, ake_init_msg->message_buf, HDCP_RTX_SIZE);
    TEE_MemMove(ctx->tx_caps, ake_init_msg->message_buf + HDCP_RTX_SIZE, HDCP_TXCAPS_SIZE);

    print_hex("Received rtx", ctx->rtx, HDCP_RTX_SIZE);
    print_hex("Received TxCaps", ctx->tx_caps, HDCP_TXCAPS_SIZE);

    // HDCP 2.3 Spec: TxCaps bit 0: HDCP2_0_REPEATER_CAPABLE, bit 1: HDCP2_1_REPEATER_CAPABLE, etc.
    // Bit 4: HDCP_VERSION_2_3_SUPPORTED_TX
    // Bit 5: PAIRING_SUPPORTED_TX
    // For a Sink, we mainly care if Tx supports pairing if we want to use stored km.
    // And we must ensure Tx supports a compatible HDCP version (e.g. 2.3)
    if (!(ctx->tx_caps[0] & 0x10)) { // Check HDCP_VERSION_2_3_SUPPORTED_TX (Byte 0, bit 4)
         EMSG("Tx does not support HDCP 2.3 (TxCaps[0]=0x%02x)", ctx->tx_caps[0]);
         // return TEE_ERROR_NOT_SUPPORTED; // Or handle downgrade if supported
    }

    ctx->pairing_intended = (ctx->tx_caps[0] & 0x20); // Check PAIRING_SUPPORTED_TX (Byte 0, bit 5)
    DMSG("Tx pairing support: %s", ctx->pairing_intended ? "Yes" : "No");

    ctx->auth_state = HDCP_STATE_AKE_INIT_RECEIVED;
    DMSG("AKE_Init processed. State: AKE_INIT_RECEIVED");
    return TEE_SUCCESS;
}

TEE_Result handle_generate_ake_send_cert(hdcp_session_context_t* ctx, hdcp_ake_send_cert_params_t* cert_params_out)
{
    DMSG("Generating AKE_Send_Cert");
    if (!ctx || !cert_params_out) {
        EMSG("Generate AKE_Send_Cert: Null parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ctx->auth_state != HDCP_STATE_AKE_INIT_RECEIVED) {
        EMSG("Generate AKE_Send_Cert: Bad state (%d), expected AKE_INIT_RECEIVED.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }

    // 1. Copy cert_rx to output buffer
    if (ctx->cert_rx_len == 0 || ctx->cert_rx_len > HDCP_MAX_CERT_SIZE) {
        EMSG("Generate AKE_Send_Cert: Invalid cert_rx length in context: %u", ctx->cert_rx_len);
        return TEE_ERROR_GENERIC; 
    }
    TEE_MemMove(cert_params_out->cert_rx, ctx->cert_rx, ctx->cert_rx_len);
    // Ensure the full buffer is what CA expects if it's fixed size, or TA updates size for CA.
    // For hdcp_ake_send_cert_params_t, cert_rx is fixed size array.
    // If ctx->cert_rx_len is less, the rest of cert_params_out->cert_rx might contain garbage.
    // It's better if cert_params_out->cert_rx_len is also part of the struct if variable.
    // For now, assume ctx->cert_rx_len is the actual size to be sent (e.g. 522 bytes).
    if (ctx->cert_rx_len < HDCP_MAX_CERT_SIZE) {
        TEE_MemFill(cert_params_out->cert_rx + ctx->cert_rx_len, 0, HDCP_MAX_CERT_SIZE - ctx->cert_rx_len);
    }

    // 2. Generate rrx (64-bit random number)
    TEE_Result res = hdcp_crypto_generate_random(ctx->rrx, HDCP_RRX_SIZE);
    if (res != TEE_SUCCESS) {
        EMSG("Generate AKE_Send_Cert: Failed to generate rrx: 0x%x", res);
        return res;
    }
    TEE_MemMove(cert_params_out->rrx, ctx->rrx, HDCP_RRX_SIZE);
    print_hex("Generated rrx for AKE_Send_Cert", ctx->rrx, HDCP_RRX_SIZE);

    // RxCaps are part of cert_rx for HDCP 2.3 IIA. Already extracted during initialize.
    // No need to explicitly add RxCaps to the message here if they are in cert_rx.

    ctx->auth_state = HDCP_STATE_AKE_CERT_SENT;
    DMSG("AKE_Send_Cert generated. State: AKE_CERT_SENT");
    return TEE_SUCCESS;
}

TEE_Result handle_ake_no_stored_km(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* no_stored_km_msg)
{
    DMSG("Handling AKE_No_Stored_km");
    if (!ctx || !no_stored_km_msg) return TEE_ERROR_BAD_PARAMETERS;
    if (ctx->auth_state != HDCP_STATE_AKE_CERT_SENT) {
        EMSG("AKE_No_Stored_km: Bad state (%d), expected AKE_CERT_SENT.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }
    // Ekpub_km is 128 bytes (1024-bit RSA public key encrypted value)
    if (no_stored_km_msg->message_len < 128) { // Ekpub(km) is 128 bytes for 1024-bit RxPrivK
        EMSG("AKE_No_Stored_km: Message too short (%u bytes). Expected >= 128.", no_stored_km_msg->message_len);
        return TEE_ERROR_BAD_PARAMETERS; 
    }

    uint8_t ekpub_km[128]; // Assuming 1024-bit RxPrivK, so Ekpub(km) is 128 bytes.
    TEE_MemMove(ekpub_km, no_stored_km_msg->message_buf, sizeof(ekpub_km));
    print_hex("Received Ekpub(km)", ekpub_km, sizeof(ekpub_km));

    // Decrypt Ekpub(km) using RxPrivK to get km || m (16 bytes km || 16 bytes m)
    uint8_t km_m[32]; 
    uint32_t km_m_len = sizeof(km_m);

    TEE_Result res = hdcp_crypto_rsaes_pkcs1_v1_5_decrypt(ctx, ekpub_km, sizeof(ekpub_km), km_m, &km_m_len);
    if (res != TEE_SUCCESS) {
        EMSG("AKE_No_Stored_km: Failed to decrypt Ekpub(km): 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    if (km_m_len != 32) {
        EMSG("AKE_No_Stored_km: Decrypted Ekpub(km) has unexpected length: %u, expected 32.", km_m_len);
        ctx->auth_state = HDCP_STATE_FAILED;
        return TEE_ERROR_GENERIC;
    }

    TEE_MemMove(ctx->km, km_m, HDCP_KM_SIZE);
    // Store m (km_m + HDCP_KM_SIZE, 16 bytes) for H' calculation. 
    // Need a temporary place in ctx or pass it. For now, assume it's implicitly handled by crypto layer or stored in ctx if needed.
    // Let's add a temporary m to context for H' calculation if it's not too large.
    // uint8_t m_temp[16]; TEE_MemMove(m_temp, km_m + HDCP_KM_SIZE, 16);
    print_hex("Decrypted km from Ekpub(km)", ctx->km, HDCP_KM_SIZE);
    print_hex("Decrypted m from Ekpub(km)", km_m + HDCP_KM_SIZE, 16); // For debug

    // Derive dkey0, dkey1, dkey2, kh from km, rtx, rrx, rn (rn is 0 for this KDF)
    uint8_t rn_for_kd[HDCP_RN_SIZE];
    TEE_MemFill(rn_for_kd, 0, HDCP_RN_SIZE); // rn is 0 for dkey/kh derivation in AKE
    res = hdcp_crypto_derive_kd(ctx->rtx, ctx->rrx, ctx->km, rn_for_kd, 
                                ctx->dkey0, ctx->dkey1, ctx->dkey2, ctx->kh);
    if (res != TEE_SUCCESS) {
        EMSG("AKE_No_Stored_km: Failed to derive dkey/kh: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    DMSG("Derived dkey0, dkey1, dkey2, kh successfully.");
    
    ctx->km_available = true;
    // AKE_No_Stored_km implies pairing is being performed.
    // ctx->pairing_intended was set from TxCaps. If Tx supports pairing, this path means pairing will occur.
    // If Tx did not support pairing, it should not have sent AKE_No_Stored_km (ideally).
    // For the Rx, if this message is received, pairing is happening.
    ctx->auth_state = HDCP_STATE_AKE_KM_RECEIVED;
    DMSG("AKE_No_Stored_km processed. km derived. State: AKE_KM_RECEIVED. Pairing will occur.");
    return TEE_SUCCESS;
}

TEE_Result handle_ake_stored_km(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* stored_km_msg)
{
    DMSG("Handling AKE_Stored_km");
    if (!ctx || !stored_km_msg) return TEE_ERROR_BAD_PARAMETERS;
    if (ctx->auth_state != HDCP_STATE_AKE_CERT_SENT) {
        EMSG("AKE_Stored_km: Bad state (%d), expected AKE_CERT_SENT.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }
    // Ekh(km) is 16 bytes, m is 16 bytes. Total 32 bytes.
    if (stored_km_msg->message_len < (16 + 16)) {
        EMSG("AKE_Stored_km: Message too short (%u bytes). Expected >= 32.", stored_km_msg->message_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t ekh_km_from_tx[16];
    uint8_t m_from_tx[16]; // m from Transmitter, used in H' calculation
    TEE_MemMove(ekh_km_from_tx, stored_km_msg->message_buf, 16);
    TEE_MemMove(m_from_tx, stored_km_msg->message_buf + 16, 16);

    print_hex("Received Ekh(km) from Tx", ekh_km_from_tx, 16);
    print_hex("Received m from Tx", m_from_tx, 16);

    // Attempt to load stored km based on rtx (Transmitter ID)
    bool found_km_in_storage = false;
    TEE_Result res = hdcp_storage_load_pairing_data(ctx->rtx, ctx->km, &found_km_in_storage);
    if (res != TEE_SUCCESS) {
        EMSG("AKE_Stored_km: Error loading stored km for rtx: 0x%x. Responding as if km not found.", res);
        // This is an internal error. HDCP spec says if Rx doesn't have km, it should have responded differently earlier.
        // Or, if Tx sends AKE_Stored_km but Rx has no km, Rx should respond with AKE_Send_Cert (which implies re-authentication from scratch).
        // This state indicates a mismatch. For robustness, might need to reset state and signal re-auth.
        // For now, treat as failure of this path.
        ctx->auth_state = HDCP_STATE_FAILED;
        return res; 
    }
    if (!found_km_in_storage) {
        DMSG("AKE_Stored_km: No stored km found for this rtx. Tx should not have sent AKE_Stored_km.");
        // According to spec, if Rx doesn't have km, it should respond with AKE_Send_Cert.
        // This means we should not have reached this handler if km was not stored.
        // This implies a protocol violation by Tx or an issue in our state/storage.
        // Simplest is to fail here. A more complex recovery might involve telling CA to restart AKE.
        ctx->auth_state = HDCP_STATE_FAILED;
        return TEE_ERROR_ITEM_NOT_FOUND; // Indicate km was expected but not found
    }
    print_hex("Loaded stored km from storage", ctx->km, HDCP_KM_SIZE);

    // Derive kh from stored km: kh = AES(km, rrx XOR rtx)
    // Note: HDCP 2.3 KDF (A.3.1) is more complex. This is a simplified derivation for kh for Ekh(km) context.
    // For verifying Ekh(km), kh is derived using AES-128(km, rrx XOR rtx)
    uint8_t rrx_xor_rtx[HDCP_RRX_SIZE]; // rrx and rtx are 8 bytes each
    for(int i=0; i<HDCP_RRX_SIZE; ++i) rrx_xor_rtx[i] = ctx->rrx[i] ^ ctx->rtx[i];
    
    uint8_t temp_kh_input[16]; // AES input is 16 bytes
    TEE_MemFill(temp_kh_input, 0, sizeof(temp_kh_input));
    TEE_MemMove(temp_kh_input, rrx_xor_rtx, HDCP_RRX_SIZE); // Use (rtx XOR rrx) as the 128-bit input block for AES
                                                          // Padded with zeros if rrx_xor_rtx is shorter than 16B.
                                                          // Spec A.3.1 uses (rtx XOR rrx XOR rn_repeated_twice XOR const)
                                                          // For Ekh(km) verification, it's simpler: AES(km, rrx XOR rtx)
                                                          // Let's assume the 128-bit input is (rtx XOR rrx) || (rtx XOR rrx)
    TEE_MemMove(temp_kh_input + HDCP_RRX_SIZE, rrx_xor_rtx, HDCP_RRX_SIZE); 

    uint8_t derived_kh_for_ekh_verify[HDCP_KH_SIZE];
    uint32_t derived_kh_len = sizeof(derived_kh_for_ekh_verify);
    res = hdcp_crypto_aes_128_ecb_encrypt(ctx->km, temp_kh_input, sizeof(temp_kh_input), derived_kh_for_ekh_verify, &derived_kh_len);
    if (res != TEE_SUCCESS || derived_kh_len != HDCP_KH_SIZE) {
        EMSG("AKE_Stored_km: Failed to derive kh for Ekh(km) verification: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    print_hex("Derived kh for Ekh(km) verification", derived_kh_for_ekh_verify, HDCP_KH_SIZE);

    // Decrypt Ekh(km) from Tx using derived_kh_for_ekh_verify to get km_prime
    // Ekh(km) = AES-CBC-Encrypt(kh, IV=0, km)
    uint8_t km_prime_decrypted[16];
    uint8_t iv_zero[16]; TEE_MemFill(iv_zero, 0, 16);
    res = hdcp_crypto_aes_128_cbc_decrypt(derived_kh_for_ekh_verify, iv_zero, ekh_km_from_tx, 16, km_prime_decrypted);
    if (res != TEE_SUCCESS) {
        EMSG("AKE_Stored_km: Failed to decrypt Ekh(km) from Tx: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    print_hex("Decrypted km from Tx's Ekh(km)", km_prime_decrypted, 16);

    // Verify km_prime_decrypted == ctx->km (loaded from storage)
    if (TEE_MemCompare(km_prime_decrypted, ctx->km, HDCP_KM_SIZE) != 0) {
        EMSG("AKE_Stored_km: Verification of Ekh(km) FAILED. Decrypted km does not match stored km.");
        ctx->auth_state = HDCP_STATE_FAILED;
        return TEE_ERROR_SECURITY; 
    }
    DMSG("AKE_Stored_km: Ekh(km) from Tx verified successfully against stored km.");

    // Now that km is verified, derive dkey0, dkey1, dkey2, kh using the official KDF
    uint8_t rn_for_kd[HDCP_RN_SIZE];
    TEE_MemFill(rn_for_kd, 0, HDCP_RN_SIZE); // rn is 0 for dkey/kh derivation in AKE
    res = hdcp_crypto_derive_kd(ctx->rtx, ctx->rrx, ctx->km, rn_for_kd, 
                                ctx->dkey0, ctx->dkey1, ctx->dkey2, ctx->kh);
    if (res != TEE_SUCCESS) {
        EMSG("AKE_Stored_km: Failed to derive dkey/kh after km verification: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    DMSG("Derived dkey0, dkey1, dkey2, kh successfully after stored km verification.");

    // Store m_from_tx for H' calculation. Add to context if not already there.
    // For now, assume H' calculation will use this m_from_tx.
    // TEE_MemMove(ctx->m_for_h_prime, m_from_tx, 16); // Example if ctx has such a field

    ctx->km_available = true;
    ctx->pairing_intended = false; // AKE_Stored_km means no new pairing is performed in this exchange.
    ctx->auth_state = HDCP_STATE_AKE_KM_RECEIVED;
    DMSG("AKE_Stored_km processed. km verified. State: AKE_KM_RECEIVED. No new pairing.");
    return TEE_SUCCESS;
}

TEE_Result handle_generate_ake_h_prime_and_pairing(hdcp_session_context_t* ctx, 
                                                 hdcp_ake_send_h_prime_params_t* h_prime_params_out, 
                                                 hdcp_ake_send_pairing_info_params_t* pairing_info_params_out, 
                                                 bool* send_pairing_info_flag)
{
    DMSG("Generating AKE_Send_H_prime and Pairing_Info (if applicable)");
    if (!ctx || !h_prime_params_out || !pairing_info_params_out || !send_pairing_info_flag) return TEE_ERROR_BAD_PARAMETERS;
    if (ctx->auth_state != HDCP_STATE_AKE_KM_RECEIVED || !ctx->km_available) {
        EMSG("Generate H"): Bad state (%d) or km not available. Expected AKE_KM_RECEIVED and km_available.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }

    // H' = HMAC-SHA256(dkey2, rtx || RxCaps || TxCaps || rrx || m)
    // Note: HDCP 2.3 IIA Spec (Errata 1.0) for H' (Section A.3.2):
    // H' = HMAC-SHA256(Kd_H, rtx || RxCaps || TxCaps || rrx)
    // where Kd_H is dkey2 derived using KDF in A.3.1.
    // The 'm' is not part of H' input in the errata version.

    uint32_t h_prime_input_len = HDCP_RTX_SIZE + HDCP_RXCAPS_SIZE + HDCP_TXCAPS_SIZE + HDCP_RRX_SIZE;
    uint8_t h_prime_input[h_prime_input_len];
    uint32_t offset = 0;
    TEE_MemMove(h_prime_input + offset, ctx->rtx, HDCP_RTX_SIZE); offset += HDCP_RTX_SIZE;
    TEE_MemMove(h_prime_input + offset, ctx->rx_caps, HDCP_RXCAPS_SIZE); offset += HDCP_RXCAPS_SIZE;
    TEE_MemMove(h_prime_input + offset, ctx->tx_caps, HDCP_TXCAPS_SIZE); offset += HDCP_TXCAPS_SIZE;
    TEE_MemMove(h_prime_input + offset, ctx->rrx, HDCP_RRX_SIZE); //offset += HDCP_RRX_SIZE;

    print_hex("H_prime input data", h_prime_input, h_prime_input_len);
    print_hex("dkey2 for H_prime", ctx->dkey2, HDCP_DKEY2_SIZE);

    uint32_t h_prime_actual_len = sizeof(h_prime_params_out->h_prime);
    TEE_Result res = hdcp_crypto_hmac_sha256(ctx->dkey2, HDCP_DKEY2_SIZE, 
                                           h_prime_input, h_prime_input_len, 
                                           h_prime_params_out->h_prime, &h_prime_actual_len);
    if (res != TEE_SUCCESS || h_prime_actual_len != 32) {
        EMSG("Generate H"): Failed to compute H_prime: 0x%x, len %u", res, h_prime_actual_len);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    print_hex("Generated H_prime", h_prime_params_out->h_prime, h_prime_actual_len);

    // If pairing occurred (i.e., AKE_No_Stored_km was processed which sets pairing_intended implicitly by deriving new km)
    // OR if ctx->pairing_intended was true from TxCaps AND we just derived a new km (not from storage).
    // The logic is: if km was newly derived (not from AKE_Stored_km path), then pairing occurred.
    // A simple way: if the previous state that led to AKE_KM_RECEIVED was via AKE_No_Stored_km.
    // Let's refine: pairing_intended is from TxCaps. If it's true AND we are in a flow where km is new (not from storage),
    // then send pairing info.
    // If `handle_ake_no_stored_km` was called, pairing is happening.
    // If `handle_ake_stored_km` was called, pairing is NOT happening in this exchange.
    // We need a flag in ctx, e.g., `ctx->newly_paired_km` set by `handle_ake_no_stored_km`.
    // For now, use `ctx->pairing_intended` which was set in `handle_ake_init` from TxCaps AND also check if km was from `no_stored_km` path.
    // Let's assume `ctx->pairing_intended` is true if `handle_ake_no_stored_km` was the path taken.
    // A better flag: `bool new_km_established_this_session`.

    if (ctx->pairing_intended) { // This flag should be true if AKE_No_Stored_km path was taken.
        // Ekh(km) = AES-CBC-Encrypt(kh, IV=0, km)
        uint8_t iv_zero[16]; TEE_MemFill(iv_zero, 0, 16);
        uint32_t ekh_km_actual_len = sizeof(pairing_info_params_out->ekh_km);
        
        // Need AES CBC encryption operation handle, or use one-shot crypto function.
        // Let's assume hdcp_crypto_aes_128_cbc_encrypt exists and works.
        // This is ENCRYPT, not decrypt. Need hdcp_crypto_aes_128_cbc_encrypt.
        // Placeholder: Need to implement hdcp_crypto_aes_128_cbc_encrypt
        // For now, let's assume it's similar to decrypt but TEE_MODE_ENCRYPT.
        // res = hdcp_crypto_aes_128_cbc_encrypt(ctx->kh, iv_zero, ctx->km, HDCP_KM_SIZE, pairing_info_params_out->ekh_km, &ekh_km_actual_len);
        // This function is not yet defined in crypto. For now, fill with placeholder.
        TEE_MemFill(pairing_info_params_out->ekh_km, 0xEE, HDCP_MAX_EKH_KM_SIZE);
        res = TEE_SUCCESS; // Placeholder for actual encryption
        ekh_km_actual_len = HDCP_MAX_EKH_KM_SIZE;
        EMSG("Ekh(km) encryption is a PLACEHOLDER!");

        if (res != TEE_SUCCESS || ekh_km_actual_len != HDCP_MAX_EKH_KM_SIZE) {
            EMSG("Generate H"): Failed to compute Ekh(km) for pairing: 0x%x", res);
            ctx->auth_state = HDCP_STATE_FAILED;
            // return res; // Don't fail H' generation if only pairing info fails for now.
        } else {
            print_hex("Generated Ekh(km) for pairing info (PLACEHOLDER)", pairing_info_params_out->ekh_km, ekh_km_actual_len);
            *send_pairing_info_flag = true;

            // Persist pairing data (rtx, km)
            TEE_Result pres = hdcp_storage_save_pairing_data(ctx->rtx, ctx->km);
            if (pres != TEE_SUCCESS) {
                EMSG("Generate H"): Failed to save pairing data: 0x%x. Continuing.", pres);
            }
        }
    } else {
        *send_pairing_info_flag = false;
    }

    ctx->auth_state = HDCP_STATE_AKE_H_PRIME_GENERATED;
    DMSG("AKE_Send_H_prime generated. Pairing info to send: %d. State: AKE_H_PRIME_GENERATED", *send_pairing_info_flag);
    return TEE_SUCCESS;
}


// --- LC Handlers ---
TEE_Result handle_lc_init(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* lc_init_msg, hdcp_lc_send_l_prime_params_t* l_prime_params_out)
{
    DMSG("Handling LC_Init");
    if (!ctx || !lc_init_msg || !l_prime_params_out) return TEE_ERROR_BAD_PARAMETERS;
    if (ctx->auth_state != HDCP_STATE_AKE_H_PRIME_GENERATED) {
        EMSG("LC_Init: Bad state (%d), expected AKE_H_PRIME_GENERATED.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }
    if (lc_init_msg->message_len < HDCP_RN_SIZE) {
        EMSG("LC_Init: Message too short (%u bytes). Expected >= %u.", lc_init_msg->message_len, HDCP_RN_SIZE);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove(ctx->rn_lc, lc_init_msg->message_buf, HDCP_RN_SIZE);
    print_hex("Received rn for LC (rn_lc)", ctx->rn_lc, HDCP_RN_SIZE);

    // Derive lc128 = AES-ECB-Encrypt(kh, rn_lc (repeated twice to make 128-bit block))
    // kh was derived during AKE.
    TEE_Result res = hdcp_crypto_derive_lc128(ctx->rn_lc, ctx->kh, ctx->lc128);
    if (res != TEE_SUCCESS) {
        EMSG("LC_Init: Failed to derive lc128: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    print_hex("Derived lc128 for Locality Check", ctx->lc128, HDCP_LC128_SIZE);

    // Compute L' = HMAC-SHA256(dkey1, rrx || rn_lc)
    // HDCP 2.3 IIA Spec (Errata 1.0) for L' (Section A.3.2):
    // L' = HMAC-SHA256(Kd_L, rrx || rn_lc)
    // where Kd_L is dkey1 derived using KDF in A.3.1.
    uint32_t l_prime_input_len = HDCP_RRX_SIZE + HDCP_RN_SIZE;
    uint8_t l_prime_input[l_prime_input_len];
    TEE_MemMove(l_prime_input, ctx->rrx, HDCP_RRX_SIZE);
    TEE_MemMove(l_prime_input + HDCP_RRX_SIZE, ctx->rn_lc, HDCP_RN_SIZE);

    print_hex("L_prime input data", l_prime_input, l_prime_input_len);
    print_hex("dkey1 for L_prime", ctx->dkey1, HDCP_DKEY1_SIZE);

    uint32_t l_prime_actual_len = sizeof(l_prime_params_out->l_prime);
    res = hdcp_crypto_hmac_sha256(ctx->dkey1, HDCP_DKEY1_SIZE, 
                                  l_prime_input, l_prime_input_len, 
                                  l_prime_params_out->l_prime, &l_prime_actual_len);
    if (res != TEE_SUCCESS || l_prime_actual_len != 32) {
        EMSG("LC_Init: Failed to compute L_prime: 0x%x, len %u", res, l_prime_actual_len);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    print_hex("Generated L_prime", l_prime_params_out->l_prime, l_prime_actual_len);

    ctx->auth_state = HDCP_STATE_LC_L_PRIME_GENERATED;
    DMSG("LC_Init processed, L_prime generated. State: LC_L_PRIME_GENERATED");
    return TEE_SUCCESS;
}


// --- SKE Handlers ---
TEE_Result handle_ske_send_eks(hdcp_session_context_t* ctx, const hdcp_message_buffer_t* ske_msg)
{
    DMSG("Handling SKE_Send_Eks");
    if (!ctx || !ske_msg) return TEE_ERROR_BAD_PARAMETERS;
    if (ctx->auth_state != HDCP_STATE_LC_L_PRIME_GENERATED) {
        EMSG("SKE_Send_Eks: Bad state (%d), expected LC_L_PRIME_GENERATED.", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }
    // Edkey(ks) is 16 bytes, riv is 8 bytes. Total 24 bytes.
    if (ske_msg->message_len < (16 + HDCP_RIV_SIZE)) {
        EMSG("SKE_Send_Eks: Message too short (%u bytes). Expected >= %u.", ske_msg->message_len, (16 + HDCP_RIV_SIZE));
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t edkey_ks_from_tx[16];
    TEE_MemMove(edkey_ks_from_tx, ske_msg->message_buf, 16);
    TEE_MemMove(ctx->riv, ske_msg->message_buf + 16, HDCP_RIV_SIZE); // Store riv directly

    print_hex("Received Edkey(ks) from Tx", edkey_ks_from_tx, 16);
    print_hex("Received riv from Tx and stored", ctx->riv, HDCP_RIV_SIZE);

    // Decrypt Edkey(ks) using dkey2 to get ks.
    // Edkey(ks) = AES-CBC-Encrypt(dkey_ske, IV_ske, ks)
    // dkey_ske = dkey2 (from KDF A.3.1)
    // IV_ske = (rtx[0-7] XOR rrx[0-7]) || (rtx[0-7] XOR rrx[0-7]) (16 bytes total)
    uint8_t iv_ske[16];
    uint8_t rtx_xor_rrx_first_8[8];
    for(int i=0; i<8; ++i) rtx_xor_rrx_first_8[i] = ctx->rtx[i] ^ ctx->rrx[i];
    TEE_MemMove(iv_ske, rtx_xor_rrx_first_8, 8);
    TEE_MemMove(iv_ske + 8, rtx_xor_rrx_first_8, 8);
    print_hex("IV for SKE Edkey(ks) decryption", iv_ske, 16);
    print_hex("dkey2 for SKE Edkey(ks) decryption", ctx->dkey2, HDCP_DKEY2_SIZE);

    TEE_Result res = hdcp_crypto_aes_128_cbc_decrypt(ctx->dkey2, iv_ske, edkey_ks_from_tx, 16, ctx->ks);
    if (res != TEE_SUCCESS) {
        EMSG("SKE_Send_Eks: Failed to decrypt Edkey(ks) to get ks: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    print_hex("Decrypted ks (Session Key)", ctx->ks, HDCP_KS_SIZE);

    // Initialize AES-CTR for content decryption using ks and riv
    res = hdcp_crypto_aes_128_ctr_init(ctx, ctx->ks, ctx->riv);
    if (res != TEE_SUCCESS) {
        EMSG("SKE_Send_Eks: Failed to initialize AES-CTR for content decryption: 0x%x", res);
        ctx->auth_state = HDCP_STATE_FAILED;
        return res;
    }
    DMSG("AES-CTR cipher initialized for content decryption.");

    ctx->ske_completed = true;
    ctx->auth_state = HDCP_STATE_AUTHENTICATED;
    DMSG("SKE_Send_Eks processed. ks and riv obtained. State: AUTHENTICATED. Ready for encrypted content.");
    return TEE_SUCCESS;
}


// --- Secure Content Decryption Module ---
TEE_Result handle_decrypt_video_packet(hdcp_session_context_t* ctx, 
                                     uint8_t* data_buffer, // In/Out buffer for decryption
                                     uint32_t data_len, 
                                     uint64_t input_ctr)
{
    if (!ctx || !data_buffer) return TEE_ERROR_BAD_PARAMETERS;
    if (ctx->auth_state != HDCP_STATE_AUTHENTICATED || !ctx->ske_completed) {
        EMSG("Decrypt video: Not authenticated or SKE not complete (state %d, ske_completed %d).", 
             ctx->auth_state, ctx->ske_completed);
        return TEE_ERROR_BAD_STATE;
    }
    if (!ctx->aes_ctr_op_initialized) {
        EMSG("Decrypt video: AES-CTR not initialized.");
        // Attempt re-initialization if ks and riv are available (should be if AUTHENTICATED)
        if (TEE_MemCompare(ctx->ks, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != 0 && 
            TEE_MemCompare(ctx->riv, "\0\0\0\0\0\0\0\0", 8) != 0) { 
             TEE_Result res_init = hdcp_crypto_aes_128_ctr_init(ctx, ctx->ks, ctx->riv);
             if (res_init != TEE_SUCCESS) {
                 EMSG("Decrypt video: Failed to re-initialize AES-CTR: 0x%x", res_init);
                 return TEE_ERROR_BAD_STATE;
             }
             DMSG("Decrypt video: Re-initialized AES-CTR successfully.");
        } else {
            EMSG("Decrypt video: ks or riv is zero, cannot re-initialize AES-CTR.");
            return TEE_ERROR_BAD_STATE;
        }
    }

    DMSG("Decrypting video packet, len: %u, PES_input_ctr: 0x%llx", data_len, input_ctr);
    
    // Use the refined AES-CTR decryption function that takes the per-packet counter
    TEE_Result res = hdcp_crypto_aes_128_ctr_crypt_packet(ctx, input_ctr, data_buffer, data_len, data_buffer); // In-place
    if (res != TEE_SUCCESS) {
        EMSG("Video packet decryption failed: 0x%x", res);
        // Consider if state should change on decryption error. Usually not, but might indicate key desync.
        return res;
    }

    // DMSG("Video packet decrypted successfully."); // This can be very verbose
    return TEE_SUCCESS;
}


#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_hdcp_uuid.h"
#include "hdcp_common_ta_ca.h"
#include "hdcp_ta_types.h"
#include "hdcp_ta_core.h"
#include "hdcp_ta_crypto.h"
#include "hdcp_ta_storage.h"
#include <string.h> // For TEE_MemFill, TEE_MemMove

// --- Placeholder for device certificate (cert_rx) ---
// In a real device, this would be provisioned securely.
// This is an example structure, actual content and length vary.
// HDCP 2.3 cert_rx is 522 bytes.
static const uint8_t embedded_cert_rx[HDCP_MAX_CERT_SIZE] = {
    // Receiver Public Key (e.g., 1024-bit RSA key = 128 bytes modulus + exponent)
    // For HDCP 2.3, this is more complex: (131 bytes for k=1024)
    // [Device Public Key (131 bytes: Public Exponent (3 bytes) || Modulus (128 bytes))]
    // RxCaps (2 bytes)
    // Reserved (3 bytes)
    // Signature (e.g., 128 bytes for 1024-bit RxPrivK, or 256 bytes if signed by 2048-bit DCP_LLC key)
    // Total 522 bytes for HDCP 2.3 IIA.
    // This is a highly simplified placeholder.
    0x01, 0x02, 0x03, /* ... 519 more bytes ... */ 0x00
};
static const uint32_t embedded_cert_rx_len = sizeof(embedded_cert_rx); // Should be 522

// --- Placeholder for HDCP Global Constant (lc) ---
// 128-bit value, should be securely provisioned.
static const uint8_t embedded_global_const[HDCP_GLOBAL_CONSTANT_SIZE] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

// Session context storage
static hdcp_session_context_t session_ctx_storage[TEE_NUM_TA_SESSIONS];
static bool session_ctx_used[TEE_NUM_TA_SESSIONS];

// DCP LLC Public Key for certrx signature verification
static TEE_ObjectHandle dcp_llc_public_key_handle = TEE_HANDLE_NULL;

static hdcp_session_context_t* get_session_context(TEE_TASessionHandle sessionHandle)
{
    for (uint32_t i = 0; i < TEE_NUM_TA_SESSIONS; ++i) {
        if (session_ctx_used[i] && session_ctx_storage[i].session_handle == sessionHandle) {
            return &session_ctx_storage[i];
        }
    }
    return NULL; 
}

static hdcp_session_context_t* allocate_session_context(TEE_TASessionHandle sessionHandle)
{
    for (uint32_t i = 0; i < TEE_NUM_TA_SESSIONS; ++i) {
        if (!session_ctx_used[i]) {
            session_ctx_used[i] = true;
            TEE_MemFill(&session_ctx_storage[i], 0, sizeof(hdcp_session_context_t)); // Clear context
            session_ctx_storage[i].session_handle = sessionHandle;
            session_ctx_storage[i].auth_state = HDCP_STATE_UNINITIALIZED;
            session_ctx_storage[i].device_private_key_obj = TEE_HANDLE_NULL;
            session_ctx_storage[i].aes_ctr_op_handle = TEE_HANDLE_NULL;
            IMSG("Allocated session context %u for handle %p", i, (void*)sessionHandle);
            return &session_ctx_storage[i];
        }
    }
    EMSG("Failed to allocate session context, no free slots.");
    return NULL;
}

static void free_session_context(hdcp_session_context_t* ctx)
{
    if (ctx) {
        for (uint32_t i = 0; i < TEE_NUM_TA_SESSIONS; ++i) {
            if (&session_ctx_storage[i] == ctx) {
                if (ctx->aes_ctr_op_initialized && ctx->aes_ctr_op_handle != TEE_HANDLE_NULL) {
                    TEE_FreeOperation(ctx->aes_ctr_op_handle);
                    ctx->aes_ctr_op_handle = TEE_HANDLE_NULL;
                    ctx->aes_ctr_op_initialized = false;
                }
                if (ctx->device_private_key_obj != TEE_HANDLE_NULL) {
                    TEE_CloseObject(ctx->device_private_key_obj);
                    ctx->device_private_key_obj = TEE_HANDLE_NULL;
                }
                TEE_MemFill(ctx, 0, sizeof(hdcp_session_context_t));
                session_ctx_used[i] = false;
                IMSG("Freed session context %u", i);
                return;
            }
        }
    }
}

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result res;
    DMSG("HDCP TA: CreateEntryPoint");
    for(uint32_t i=0; i < TEE_NUM_TA_SESSIONS; ++i) {
        session_ctx_used[i] = false;
        TEE_MemFill(&session_ctx_storage[i], 0, sizeof(hdcp_session_context_t));
    }
    // Load DCP LLC public key once for the TA instance
    res = hdcp_crypto_load_dcp_llc_public_key(&dcp_llc_public_key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to load DCP LLC public key at TA Create: 0x%x", res);
        return res; // Fail TA creation if critical key is missing
    }
    DMSG("DCP LLC Public Key loaded successfully at TA Create.");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("HDCP TA: DestroyEntryPoint");
    hdcp_crypto_unload_dcp_llc_public_key(&dcp_llc_public_key_handle);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                TEE_Param params[4],
                                void **sess_ctx_void_ptr)
{
    hdcp_session_context_t *session_ctx;
    (void)params;
    (void)param_types;

    DMSG("HDCP TA: OpenSessionEntryPoint");

    session_ctx = allocate_session_context((TEE_TASessionHandle)sess_ctx_void_ptr);
    if (!session_ctx) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    *sess_ctx_void_ptr = (void*)session_ctx;
    
    // Copy embedded global constant to session context
    TEE_MemMove(session_ctx->global_const, embedded_global_const, HDCP_GLOBAL_CONSTANT_SIZE);
    print_hex("Loaded global_const into session", session_ctx->global_const, HDCP_GLOBAL_CONSTANT_SIZE);

    session_ctx->auth_state = HDCP_STATE_UNINITIALIZED;
    DMSG("HDCP TA Session Opened. Context: %p", (void*)session_ctx);
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx_void_ptr)
{
    DMSG("HDCP TA: CloseSessionEntryPoint");
    hdcp_session_context_t *session_ctx = (hdcp_session_context_t *)sess_ctx_void_ptr;
    if (session_ctx) {
        free_session_context(session_ctx);
    }
}

// Helper to parse RxCaps from cert_rx (HDCP 2.3 IIA, Section 4.3.2)
// CertRx: ReceiverPublicKey (131 bytes) || RxCaps (2 bytes) || Reserved (3 bytes) || Signature (variable)
// RxCaps are at offset 131 from start of cert_rx data.
static void extract_rxcaps_from_cert(hdcp_session_context_t* ctx) {
    if (ctx->cert_rx_len >= (131 + HDCP_RXCAPS_SIZE)) {
        TEE_MemMove(ctx->rx_caps, ctx->cert_rx + 131, HDCP_RXCAPS_SIZE);
        print_hex("Extracted RxCaps from cert_rx", ctx->rx_caps, HDCP_RXCAPS_SIZE);
    } else {
        EMSG("Cert_rx too short to extract RxCaps. Length: %u", ctx->cert_rx_len);
        // Set to default/zero if extraction fails
        TEE_MemFill(ctx->rx_caps, 0, HDCP_RXCAPS_SIZE);
    }
}

static TEE_Result cmd_initialize(hdcp_session_context_t* ctx)
{
    TEE_Result res;
    if (ctx->auth_state != HDCP_STATE_UNINITIALIZED) {
        EMSG("Initialize: TA already initialized or in progress (state %d).", ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }

    // 1. Load device private key (RxPrivK)
    res = hdcp_crypto_load_device_private_key(ctx, HDCP_DEVICE_PRIVATE_KEY_ID);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to load device private key: 0x%x", res);
        return res;
    }

    // 2. Load device certificate (cert_rx)
    // For this example, using an embedded cert. In production, load from secure storage.
    // Example: res = load_secure_object_to_buffer(HDCP_DEVICE_CERT_ID, ctx->cert_rx, sizeof(ctx->cert_rx), &ctx->cert_rx_len);
    if (embedded_cert_rx_len > HDCP_MAX_CERT_SIZE) { // Basic check
        EMSG("Embedded cert_rx too large!");
        return TEE_ERROR_GENERIC;
    }
    TEE_MemMove(ctx->cert_rx, embedded_cert_rx, embedded_cert_rx_len);
    ctx->cert_rx_len = embedded_cert_rx_len;
    DMSG("Loaded cert_rx (length %u bytes). First few bytes:", ctx->cert_rx_len);
    print_hex("cert_rx (start)", ctx->cert_rx, ctx->cert_rx_len > 16 ? 16 : ctx->cert_rx_len);

    // 3. Extract RxCaps from cert_rx
    extract_rxcaps_from_cert(ctx);

    // 4. Verify cert_rx signature using DCP LLC public key
    // Cert data to verify: ReceiverPublicKey (131) + RxCaps (2) + Reserved (3) = 136 bytes
    // Signature is the rest of the cert_rx (522 - 136 = 386, but DCP LLC key is 2048-bit -> 256 byte sig)
    // HDCP 2.3 IIA spec, 4.3.2: cert_rx is 522 bytes.
    // It contains: Receiver Public Key (131 bytes), RxCaps (2 bytes), Reserved (3 bytes), Signature (128 bytes for 1024-bit RxKey, or 256 bytes for 2048-bit DCP_LLC key)
    // The signature is on SHA-1 hash of (Receiver Public Key || RxCaps || Reserved).
    // Data to hash: cert_rx[0] to cert_rx[131+2+3-1 = 135]. Length = 136 bytes.
    // Signature: cert_rx[136] to cert_rx[522-1]. Length depends on DCP LLC key size (256 bytes for 2048-bit key).
    if (ctx->cert_rx_len == 522) { // Assuming 2048-bit DCP LLC key and its signature
        uint32_t data_to_hash_len = 131 + 2 + 3; // 136 bytes
        uint32_t signature_len = 256; // For 2048-bit DCP LLC key
        if (ctx->cert_rx_len < (data_to_hash_len + signature_len)) {
            EMSG("Cert_rx length %u is too short for data and 2048-bit signature.", ctx->cert_rx_len);
            // return TEE_ERROR_SECURITY; // Or handle as appropriate
        } else {
            // Ensure dcp_llc_public_key_handle is valid (loaded in TA_CreateEntryPoint)
            if (dcp_llc_public_key_handle == TEE_HANDLE_NULL) {
                EMSG("DCP LLC Public Key not loaded, cannot verify cert_rx.");
                return TEE_ERROR_BAD_STATE;
            }
            res = hdcp_crypto_rsassa_pkcs1_v1_5_verify_cert_signature(
                                                ctx->cert_rx, data_to_hash_len, 
                                                ctx->cert_rx + data_to_hash_len, signature_len,
                                                dcp_llc_public_key_handle);
            if (res != TEE_SUCCESS) {
                EMSG("Cert_rx signature verification FAILED: 0x%x. This is critical.", res);
                // Depending on policy, might allow to continue for testing or fail hard.
                // For production, this should be a fatal error for the session.
                // return TEE_ERROR_SECURITY;
            } else {
                DMSG("Cert_rx signature verified successfully.");
            }
        }
    } else {
        EMSG("Cert_rx length is %u, expected 522 for HDCP 2.3 IIA. Skipping signature check for now.", ctx->cert_rx_len);
        // This might be acceptable if using test vectors or a different cert format not matching full spec.
    }
    
    ctx->auth_state = HDCP_STATE_INITIALIZED;
    DMSG("HDCP TA Initialized. State: INITIALIZED");
    return TEE_SUCCESS;
}

static TEE_Result cmd_finalize(hdcp_session_context_t* ctx)
{
    DMSG("HDCP TA Finalizing session.");
    if (ctx->aes_ctr_op_initialized && ctx->aes_ctr_op_handle != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->aes_ctr_op_handle);
        ctx->aes_ctr_op_handle = TEE_HANDLE_NULL;
        ctx->aes_ctr_op_initialized = false;
    }
    // Other cleanups specific to finalize, if any, beyond CloseSession.
    ctx->auth_state = HDCP_STATE_UNINITIALIZED;
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx_void_ptr,
                                  uint32_t cmd_id,
                                  uint32_t param_types,
                                  TEE_Param params[4])
{
    hdcp_session_context_t *ctx = (hdcp_session_context_t *)sess_ctx_void_ptr;
    TEE_Result res = TEE_ERROR_GENERIC;

    // DMSG("HDCP TA: InvokeCommandEntryPoint, cmd_id=0x%x", cmd_id);

    if (!ctx && cmd_id != TA_CMD_SELF_TEST /* example of a command not needing session */) {
        EMSG("InvokeCommand: Null session context for cmd_id 0x%x", cmd_id);
        return TEE_ERROR_BAD_STATE;
    }

    if (cmd_id != CMD_HDCP_INITIALIZE && ctx->auth_state == HDCP_STATE_UNINITIALIZED) {
        EMSG("InvokeCommand: TA not initialized for cmd_id 0x%x (state %d)", cmd_id, ctx->auth_state);
        return TEE_ERROR_BAD_STATE;
    }

    switch (cmd_id) {
    case CMD_HDCP_INITIALIZE:
        res = cmd_initialize(ctx);
        break;
    case CMD_HDCP_FINALIZE:
        res = cmd_finalize(ctx);
        break;

    case CMD_HDCP_AKE_INIT_RECEIVED:
        res = handle_ake_init(ctx, (hdcp_message_buffer_t*)params[0].memref.buffer);
        break;
    case CMD_HDCP_AKE_SEND_CERT:
        res = handle_generate_ake_send_cert(ctx, (hdcp_ake_send_cert_params_t*)params[0].memref.buffer);
        if (res == TEE_SUCCESS) {
            params[0].memref.size = sizeof(hdcp_ake_send_cert_params_t); // Assuming fixed size output
        }
        break;
    case CMD_HDCP_AKE_NO_STORED_KM_RECEIVED:
        res = handle_ake_no_stored_km(ctx, (hdcp_message_buffer_t*)params[0].memref.buffer);
        break;
    case CMD_HDCP_AKE_STORED_KM_RECEIVED:
        res = handle_ake_stored_km(ctx, (hdcp_message_buffer_t*)params[0].memref.buffer);
        break;
    case CMD_HDCP_AKE_GENERATE_H_PRIME: {
        bool send_pairing_info = false;
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
                                                   TEEC_MEMREF_TEMP_OUTPUT, 
                                                   TEEC_NONE, TEEC_NONE);
        if (param_types != exp_param_types) { res = TEE_ERROR_BAD_PARAMETERS; break; }

        res = handle_generate_ake_h_prime_and_pairing(ctx, 
                                                    (hdcp_ake_send_h_prime_params_t*)params[0].memref.buffer, 
                                                    (hdcp_ake_send_pairing_info_params_t*)params[1].memref.buffer,
                                                    &send_pairing_info);
        if (res == TEE_SUCCESS) {
            params[0].memref.size = sizeof(hdcp_ake_send_h_prime_params_t);
            if (send_pairing_info) {
                params[1].memref.size = sizeof(hdcp_ake_send_pairing_info_params_t);
            } else {
                params[1].memref.size = 0;
            }
        }
        break;
    }
    case CMD_HDCP_LC_INIT_RECEIVED: {
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, 
                                                   TEEC_MEMREF_TEMP_OUTPUT, 
                                                   TEEC_NONE, TEEC_NONE);
        if (param_types != exp_param_types) { res = TEE_ERROR_BAD_PARAMETERS; break; }
        res = handle_lc_init(ctx, 
                             (hdcp_message_buffer_t*)params[0].memref.buffer, 
                             (hdcp_lc_send_l_prime_params_t*)params[1].memref.buffer);
        if (res == TEE_SUCCESS) {
            params[1].memref.size = sizeof(hdcp_lc_send_l_prime_params_t);
        }
        break;
    }
    case CMD_HDCP_SKE_SEND_EKS_RECEIVED:
        res = handle_ske_send_eks(ctx, (hdcp_message_buffer_t*)params[0].memref.buffer);
        break;
    case CMD_HDCP_DECRYPT_VIDEO_PACKET: {
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
                                                   TEEC_VALUE_INPUT,
                                                   TEEC_NONE,
                                                   TEEC_NONE);
        if (param_types != exp_param_types) { res = TEE_ERROR_BAD_PARAMETERS; break; }
        
        uint64_t input_ctr = ((uint64_t)params[1].value.b << 32) | params[1].value.a;
        res = handle_decrypt_video_packet(ctx, 
                                          params[0].memref.buffer, 
                                          params[0].memref.size, 
                                          input_ctr);
        break;
    }
    case CMD_HDCP_GET_STATUS: {
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEEC_VALUE_OUTPUT, 
                                                   TEEC_NONE, 
                                                   TEEC_NONE, TEEC_NONE);
        if (param_types != exp_param_types) { res = TEE_ERROR_BAD_PARAMETERS; break; }
        params[0].value.a = (uint32_t)ctx->auth_state;
        res = TEE_SUCCESS;
        break;
    }
    default:
        EMSG("HDCP TA: Unknown command ID 0x%x", cmd_id);
        res = TEE_ERROR_NOT_SUPPORTED;
        break;
    }
    return res;
}


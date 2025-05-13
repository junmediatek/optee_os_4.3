#ifndef HDCP_TA_TYPES_H
#define HDCP_TA_TYPES_H

#include <tee_api_types.h>
#include "hdcp_common_ta_ca.h" // For shared structures and command IDs

#define HDCP_DEVICE_PRIVATE_KEY_ID "hdcp_rx_priv_key.pem" // Example, could be an object ID
#define HDCP_DEVICE_CERT_ID "hdcp_rx_cert.der"
#define HDCP_GLOBAL_CONSTANT_SIZE 16      // 128 bits
#define HDCP_KM_SIZE 16                   // 128 bits
#define HDCP_KS_SIZE 16                   // 128 bits
#define HDCP_RIV_SIZE 8                   // 64 bits
#define HDCP_RN_SIZE 8                    // 64 bits
#define HDCP_RTX_SIZE 8                   // 64 bits
#define HDCP_RRX_SIZE 8                   // 64 bits
#define HDCP_LC128_SIZE 16                // 128 bits
#define HDCP_DKEY0_SIZE 16
#define HDCP_DKEY1_SIZE 16
#define HDCP_DKEY2_SIZE 16
#define HDCP_KH_SIZE 16
#define HDCP_TXCAPS_SIZE 3                // Transmitter Capabilities (3 bytes)
#define HDCP_RXCAPS_SIZE 2                // Receiver Capabilities (2 bytes, part of certrx)

// HDCP Protocol State (example, needs to align with spec's state machine)
typedef enum {
    HDCP_STATE_UNINITIALIZED,
    HDCP_STATE_INITIALIZED,
    HDCP_STATE_AKE_INIT_RECEIVED,
    HDCP_STATE_AKE_CERT_SENT,
    HDCP_STATE_AKE_KM_RECEIVED,     // After AKE_No_Stored_km or AKE_Stored_km from Tx
    HDCP_STATE_AKE_H_PRIME_GENERATED, // After H' (and pairing info if any) is ready
    HDCP_STATE_LC_INIT_RECEIVED,
    HDCP_STATE_LC_L_PRIME_GENERATED,
    HDCP_STATE_SKE_EKS_RECEIVED,
    HDCP_STATE_AUTHENTICATED,       // Authentication successful, ks and riv available
    HDCP_STATE_FAILED
} hdcp_auth_state_t;

// Structure to hold HDCP session context for one CA session
typedef struct {
    TEE_TASessionHandle session_handle; // For logging or session-specific resources
    hdcp_auth_state_t auth_state;

    // Device specific (loaded once or per TA instance)
    TEE_ObjectHandle device_private_key_obj; // Handle to RSA private key object
    uint8_t cert_rx[HDCP_MAX_CERT_SIZE];
    uint32_t cert_rx_len;
    uint8_t rx_caps[HDCP_RXCAPS_SIZE]; // Extracted from cert_rx
    // Global constant should be securely embedded or loaded
    uint8_t global_const[HDCP_GLOBAL_CONSTANT_SIZE];

    // AKE related values
    uint8_t rtx[HDCP_RTX_SIZE];
    uint8_t tx_caps[HDCP_TXCAPS_SIZE];
    uint8_t rrx[HDCP_RRX_SIZE];
    uint8_t km[HDCP_KM_SIZE];
    bool km_available; // Flag indicating if km is available (either stored or newly computed)
    bool pairing_intended; // Flag if pairing was intended by Tx (from AKE_Init)

    // Intermediate keys from km (Core Values)
    uint8_t dkey0[HDCP_DKEY0_SIZE];
    uint8_t dkey1[HDCP_DKEY1_SIZE];
    uint8_t dkey2[HDCP_DKEY2_SIZE];
    uint8_t kh[HDCP_KH_SIZE];

    // LC related values
    uint8_t rn_lc[HDCP_RN_SIZE]; // rn from LC_Init
    uint8_t lc128[HDCP_LC128_SIZE]; // Derived for locality check

    // SKE related values
    uint8_t ks[HDCP_KS_SIZE];
    uint8_t riv[HDCP_RIV_SIZE];
    bool ske_completed;

    // Cryptographic operation contexts (e.g., for AES-CTR)
    TEE_OperationHandle aes_ctr_op_handle; // For content decryption
    bool aes_ctr_op_initialized;

} hdcp_session_context_t;

// Structure for persisted pairing information
typedef struct {
    uint8_t rtx[HDCP_RTX_SIZE]; // Or some other Transmitter identifier
    uint8_t km[HDCP_KM_SIZE];
    // Potentially other info like ReceiverID of Tx if available
} hdcp_pairing_data_t;

#endif // HDCP_TA_TYPES_H


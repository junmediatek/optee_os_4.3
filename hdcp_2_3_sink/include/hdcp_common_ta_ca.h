// In a shared header file, e.g., hdcp_common_ta_ca.h
#ifndef HDCP_COMMON_TA_CA_H
#define HDCP_COMMON_TA_CA_H

#include <stdint.h>

// HDCP Protocol Message Sizes (from HDCP 2.3 Spec)
#define HDCP_RTX_SIZE 8         // Size of rtx (Transmitter nonce)
#define HDCP_TXCAPS_SIZE 3      // Size of TxCaps (Transmitter capabilities)
#define HDCP_RRX_SIZE 8         // Size of rrx (Receiver nonce)
#define HDCP_RXCAPS_SIZE 3      // Size of RxCaps (Receiver capabilities, part of cert_rx)
#define HDCP_RN_SIZE 8          // Size of rn (Locality Check nonce)
#define HDCP_RIV_SIZE 8         // Size of riv (Session Key Exchange)
#define HDCP_CERT_RX_SIZE 522   // Size of cert_rx (Receiver certificate)
#define HDCP_EKHPUB_KM_SIZE 128 // Size of Ekpub(km) for 1024-bit Rx_pub_k (RSA-1024)
#define HDCP_EKH_KM_SIZE 16     // Size of Ekh(km)
#define HDCP_M_SIZE 16          // Size of m (used with Ekh(km))
#define HDCP_H_PRIME_SIZE 32    // Size of H' (SHA256 hash)
#define HDCP_L_PRIME_SIZE 32    // Size of L' (SHA256 hash)
#define HDCP_EDKEY_KS_SIZE 16   // Size of Edkey(ks)

#define HDCP_MAX_MESSAGE_SIZE 530 // Max of cert_rx + rrx + RxCaps, or other large messages
#define HDCP_MAX_CERT_SIZE HDCP_CERT_RX_SIZE
// #define HDCP_MAX_EKH_KM_SIZE HDCP_EKH_KM_SIZE // Already defined above
// #define HDCP_MAX_EKS_SIZE (HDCP_EDKEY_KS_SIZE + HDCP_RIV_SIZE) // Edkey(ks) || riv

// HDCP Authentication States (TA internal, can be reported to CA)
typedef enum {
    HDCP_STATE_UNINITIALIZED = 0,
    HDCP_STATE_INITIALIZED,
    HDCP_STATE_AKE_INIT_RECEIVED,
    HDCP_STATE_AKE_CERT_SENT,
    HDCP_STATE_AKE_KM_RECEIVED, // Covers both No_Stored_Km and Stored_Km
    HDCP_STATE_AKE_H_PRIME_GENERATED,
    HDCP_STATE_LC_INIT_RECEIVED,
    HDCP_STATE_SKE_EKS_RECEIVED,
    HDCP_STATE_AUTHENTICATED,
    HDCP_STATE_FAILED
} hdcp_auth_state_t;

typedef struct {
    uint32_t message_len;         // Actual message length
    uint8_t message_buf[HDCP_MAX_MESSAGE_SIZE]; // Message content
} hdcp_message_buffer_t;

// For AKE_Send_Cert
typedef struct {
    uint8_t cert_rx[HDCP_CERT_RX_SIZE];
    uint8_t rrx[HDCP_RRX_SIZE]; 
    // RxCaps are part of cert_rx in HDCP 2.3 IIA
} hdcp_ake_send_cert_params_t;

// For AKE_Send_H_prime
typedef struct {
    uint8_t h_prime[HDCP_H_PRIME_SIZE]; 
} hdcp_ake_send_h_prime_params_t;

// For AKE_Send_Pairing_Info
typedef struct {
    uint8_t ekh_km[HDCP_EKH_KM_SIZE]; 
} hdcp_ake_send_pairing_info_params_t;

// For LC_Send_L_prime
typedef struct {
    uint8_t l_prime[HDCP_L_PRIME_SIZE]; 
} hdcp_lc_send_l_prime_params_t;


// For video decryption (parameters for the command)
typedef struct {
    uint64_t input_ctr; // AES-CTR's initial counter value
} hdcp_video_decrypt_params_t; 


// HDCP TA Command IDs
#define CMD_HDCP_INITIALIZE                             0x0001
#define CMD_HDCP_FINALIZE                               0x0002 

// AKE Commands
#define CMD_HDCP_AKE_INIT_RECEIVED                      0x0101 
#define CMD_HDCP_AKE_SEND_CERT                          0x0102 
#define CMD_HDCP_AKE_NO_STORED_KM_RECEIVED              0x0103 
#define CMD_HDCP_AKE_STORED_KM_RECEIVED                 0x0104 
#define CMD_HDCP_AKE_GENERATE_H_PRIME                   0x0105 

// LC Commands
#define CMD_HDCP_LC_INIT_RECEIVED                       0x0201 

// SKE Commands
#define CMD_HDCP_SKE_SEND_EKS_RECEIVED                  0x0301 

// Repeater Commands (Placeholders)
#define CMD_HDCP_REPEATERAUTH_SEND_RECEIVERID_LIST_RECEIVED 0x0401
#define CMD_HDCP_REPEATERAUTH_STREAM_MANAGE_RECEIVED    0x0402
#define CMD_HDCP_REPEATERAUTH_STREAM_READY_RECEIVED     0x0403

// Content Decryption Command
#define CMD_HDCP_DECRYPT_VIDEO_PACKET                   0x0501 

// Status/Error Reporting
#define CMD_HDCP_GET_STATUS                             0x0F01

#endif // HDCP_COMMON_TA_CA_H


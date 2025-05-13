#ifndef HDCP_TA_CRYPTO_H
#define HDCP_TA_CRYPTO_H

#include "hdcp_ta_types.h"
#include "tee_api_types.h"

// --- Cryptographic Engine --- 

// RSA Operations
TEE_Result hdcp_crypto_load_device_private_key(hdcp_session_context_t* ctx, const char* key_id_in_secure_storage_or_embedded);
TEE_Result hdcp_crypto_rsaes_pkcs1_v1_5_decrypt(hdcp_session_context_t* ctx, const uint8_t* cipher_text, uint32_t cipher_text_len, uint8_t* plain_text, uint32_t* plain_text_len);
TEE_Result hdcp_crypto_rsassa_pkcs1_v1_5_verify_cert_signature(const uint8_t* cert_data, uint32_t cert_data_len, const uint8_t* signature, uint32_t signature_len, const TEE_ObjectHandle dcp_llc_pub_key_obj);
TEE_Result hdcp_crypto_load_dcp_llc_public_key(TEE_ObjectHandle* dcp_llc_pub_key_obj);
void hdcp_crypto_unload_dcp_llc_public_key(TEE_ObjectHandle* dcp_llc_pub_key_obj);


// AES Operations
TEE_Result hdcp_crypto_aes_128_ecb_encrypt(const uint8_t* key, const uint8_t* plain_text, uint32_t plain_text_len, uint8_t* cipher_text, uint32_t* cipher_text_len);
TEE_Result hdcp_crypto_aes_128_cbc_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* cipher_text, uint32_t len, uint8_t* plain_text);
TEE_Result hdcp_crypto_aes_128_ctr_init(hdcp_session_context_t* ctx, const uint8_t* key, const uint8_t* iv_ctr_64bit);
TEE_Result hdcp_crypto_aes_128_ctr_update(hdcp_session_context_t* ctx, const uint8_t* cipher_text, uint32_t len, uint8_t* plain_text);
void hdcp_crypto_aes_128_ctr_final(hdcp_session_context_t* ctx);

// HMAC & Hash Operations
TEE_Result hdcp_crypto_hmac_sha256(const uint8_t* key, uint32_t key_len, const uint8_t* message, uint32_t message_len, uint8_t* mac, uint32_t* mac_len);
TEE_Result hdcp_crypto_sha256(const uint8_t* message, uint32_t message_len, uint8_t* digest);
TEE_Result hdcp_crypto_sha1(const uint8_t* message, uint32_t message_len, uint8_t* digest);

// Key Derivation Functions (KDF for dkey, kh, lc128)
TEE_Result hdcp_crypto_derive_kd(const uint8_t* rtx, const uint8_t* rrx, const uint8_t* km, const uint8_t* rn_for_kd_derivation, uint8_t* dkey0, uint8_t* dkey1, uint8_t* dkey2, uint8_t* kh);
TEE_Result hdcp_crypto_derive_lc128(const uint8_t* rn_lc, const uint8_t* kh, uint8_t* lc128);

// Random Number Generation
TEE_Result hdcp_crypto_generate_random(uint8_t* buffer, uint32_t buffer_len);

#endif // HDCP_TA_CRYPTO_H


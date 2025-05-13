#ifndef HDCP_TA_STORAGE_H
#define HDCP_TA_STORAGE_H

#include "hdcp_ta_types.h"
#include "tee_api_types.h"

// --- Secure Storage Interface ---
TEE_Result hdcp_storage_save_pairing_data(const uint8_t* rtx, const uint8_t* km);
TEE_Result hdcp_storage_load_pairing_data(const uint8_t* rtx, uint8_t* km_out, bool* found);
TEE_Result hdcp_storage_delete_pairing_data(const uint8_t* rtx);

// Helper to create a unique object ID for pairing data based on rtx
TEE_Result hdcp_storage_get_pairing_object_id(const uint8_t* rtx, char* obj_id, uint32_t obj_id_len);


#endif // HDCP_TA_STORAGE_H


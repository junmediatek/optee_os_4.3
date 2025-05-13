#ifndef FUZZER_H
#define FUZZER_H

#include <tee_client_api.h>
#include "hdcp_common_ta_ca.h" // Assuming this path will be resolved by include paths

// Forward declarations if needed

// Structure for TA Command Specification
typedef struct {
    uint32_t command_id;
    const char* command_name;
    uint32_t expected_param_types; // TEEC_PARAM_TYPES(...)
    size_t expected_param_sizes[TEEC_CONFIG_PAYLOAD_REF_COUNT]; 
    bool requires_initialized_state; 
} TA_Command_Spec_t;

// FuzzerCore functions
void FuzzerCore_Init(void);
void FuzzerCore_RunFuzzingLoop(uint32_t num_iterations);
void FuzzerCore_SelectNextCommand(TEEC_Session* session, uint32_t* cmd_id, TEEC_Operation* operation, const TA_Command_Spec_t** cmd_spec);
void FuzzerCore_Shutdown(void);

#endif // FUZZER_H


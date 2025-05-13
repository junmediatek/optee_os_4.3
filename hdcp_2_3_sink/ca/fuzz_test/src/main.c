#include "fuzzer.h"
#include "input_mutator.h"
#include "ta_interactor.h"
#include "crash_detector.h"
#include "logger.h"
#include "hdcp_common_ta_ca.h" // For command definitions
#include "ta_hdcp_uuid.h"      // For TA_HDCP_UUID

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global TEE Context and Session
static TEEC_Context tee_ctx;
static TEEC_Session tee_session;
static bool ta_session_opened = false;
static bool is_ta_fully_initialized = false; // Tracks if CMD_HDCP_INITIALIZE was successful

// Define the TA UUID
static TEEC_UUID ta_uuid = TA_HDCP_UUID;

#define MAX_FUZZ_BUFFER_ALLOC_SIZE 4096 // Max size for a single fuzzed buffer allocation

// Command Specifications
static const TA_Command_Spec_t command_specs[] = {
    { CMD_HDCP_INITIALIZE, "CMD_HDCP_INITIALIZE", TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE), {0,0,0,0}, false },
    { CMD_HDCP_FINALIZE, "CMD_HDCP_FINALIZE", TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE), {0,0,0,0}, true },
    { CMD_HDCP_AKE_INIT_RECEIVED, "CMD_HDCP_AKE_INIT_RECEIVED", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_message_buffer_t),0,0,0}, true },
    { CMD_HDCP_AKE_SEND_CERT, "CMD_HDCP_AKE_SEND_CERT", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_ake_send_cert_params_t),0,0,0}, true },
    { CMD_HDCP_AKE_NO_STORED_KM_RECEIVED, "CMD_HDCP_AKE_NO_STORED_KM_RECEIVED", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_message_buffer_t),0,0,0}, true },
    { CMD_HDCP_AKE_STORED_KM_RECEIVED, "CMD_HDCP_AKE_STORED_KM_RECEIVED", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_message_buffer_t),0,0,0}, true },
    { CMD_HDCP_AKE_GENERATE_H_PRIME, "CMD_HDCP_AKE_GENERATE_H_PRIME", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_ake_send_h_prime_params_t), sizeof(hdcp_ake_send_pairing_info_params_t),0,0}, true },
    { CMD_HDCP_LC_INIT_RECEIVED, "CMD_HDCP_LC_INIT_RECEIVED", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_message_buffer_t), sizeof(hdcp_lc_send_l_prime_params_t),0,0}, true },
    { CMD_HDCP_SKE_SEND_EKS_RECEIVED, "CMD_HDCP_SKE_SEND_EKS_RECEIVED", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE), {sizeof(hdcp_message_buffer_t),0,0,0}, true },
    { CMD_HDCP_DECRYPT_VIDEO_PACKET, "CMD_HDCP_DECRYPT_VIDEO_PACKET", TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE), {MAX_FUZZ_BUFFER_ALLOC_SIZE,0,0,0}, true }, // Use a larger fuzzable size
    { CMD_HDCP_GET_STATUS, "CMD_HDCP_GET_STATUS", TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE), {0,0,0,0}, true },
};
static const int num_command_specs = sizeof(command_specs) / sizeof(command_specs[0]);

void FuzzerCore_Init(void) {
    Logger_Init("fuzzer_log.txt");
    Logger_Log(LOG_LEVEL_INFO, "FuzzerCore initializing...");
    srand(time(NULL));

    TEEC_Result res = TAInteractor_InitializeContext(&tee_ctx);
    if (res != TEEC_SUCCESS) {
        Logger_Log(LOG_LEVEL_ERROR, "Failed to initialize TEE Context: 0x%x", res);
        exit(1);
    }

    uint32_t err_origin;
    res = TAInteractor_OpenSession(&tee_ctx, &tee_session, &ta_uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        Logger_Log(LOG_LEVEL_ERROR, "Failed to open TA session: 0x%x (origin: 0x%x)", res, err_origin);
        TAInteractor_FinalizeContext(&tee_ctx);
        exit(1);
    }
    ta_session_opened = true;
    is_ta_fully_initialized = false; // TA is not yet initialized by CMD_HDCP_INITIALIZE
    Logger_Log(LOG_LEVEL_INFO, "FuzzerCore initialized. TA Session opened.");
}

void FuzzerCore_RunFuzzingLoop(uint32_t num_iterations) {
    Logger_Log(LOG_LEVEL_INFO, "Starting fuzzing loop for %u iterations.", num_iterations);
    TEEC_Operation op;
    uint32_t cmd_id;
    TEEC_Result res;
    uint32_t err_origin;
    const TA_Command_Spec_t* current_cmd_spec = NULL;

    for (uint32_t i = 0; i < num_iterations; ++i) {
        Logger_Log(LOG_LEVEL_DEBUG, "Fuzzing iteration %u/%u...", i + 1, num_iterations);
        
        FuzzerCore_SelectNextCommand(&tee_session, &cmd_id, &op, &current_cmd_spec);
        if (!current_cmd_spec) {
            Logger_Log(LOG_LEVEL_WARNING, "No command selected. Skipping iteration %u.", i + 1);
            continue;
        }

        // Prepare TEEC_Operation parameters (allocate buffers for memrefs)
        for (int j = 0; j < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++j) {
            uint32_t param_type = TEEC_PARAM_TYPE_GET(current_cmd_spec->expected_param_types, j);
            if (param_type == TEEC_MEMREF_TEMP_INPUT || 
                param_type == TEEC_MEMREF_TEMP_OUTPUT || 
                param_type == TEEC_MEMREF_TEMP_INOUT) {
                
                size_t alloc_size = current_cmd_spec->expected_param_sizes[j];
                if (alloc_size == 0) { // If spec size is 0, use a default max for fuzzing
                    alloc_size = MAX_FUZZ_BUFFER_ALLOC_SIZE;
                } else if (alloc_size > MAX_FUZZ_BUFFER_ALLOC_SIZE) {
                    alloc_size = MAX_FUZZ_BUFFER_ALLOC_SIZE; // Cap at max alloc
                }
                if (alloc_size == 0 && (param_type == TEEC_MEMREF_TEMP_INPUT || param_type == TEEC_MEMREF_TEMP_INOUT)){
                     alloc_size = 1; // Ensure at least 1 byte for input/inout if expected is 0, to allow fuzzing size to 0 later
                }

                op.params[j].tmpref.buffer = NULL;
                if (alloc_size > 0) {
                    op.params[j].tmpref.buffer = malloc(alloc_size);
                    if (!op.params[j].tmpref.buffer) {
                        Logger_Log(LOG_LEVEL_ERROR, "Failed to allocate buffer for param %d of cmd 0x%x", j, cmd_id);
                        // Skip this iteration or handle error more gracefully
                        goto cleanup_params; 
                    }
                    memset(op.params[j].tmpref.buffer, 0, alloc_size); // Initialize buffer
                }
                op.params[j].tmpref.size = alloc_size; // This is buffer capacity for mutator
            }
        }

        Logger_Log(LOG_LEVEL_INFO, "Fuzzing command: %s (0x%x)", current_cmd_spec->command_name, cmd_id);
        InputMutator_FuzzOperation(&op, cmd_id, current_cmd_spec);

        // Log fuzzed operation details (consider verbosity)
        Logger_LogData(LOG_LEVEL_DEBUG, "Fuzzed Op ParamTypes:", (uint8_t*)&op.paramTypes, sizeof(op.paramTypes));
        for(int k=0; k<4; ++k) {
            uint32_t pt = TEEC_PARAM_TYPE_GET(op.paramTypes, k);
            if(pt == TEEC_MEMREF_TEMP_INPUT || pt == TEEC_MEMREF_TEMP_OUTPUT || pt == TEEC_MEMREF_TEMP_INOUT) {
                char prefix[50];
                sprintf(prefix, "Fuzzed Op Param %d (Memref, size %zu)", k, op.params[k].tmpref.size);
                Logger_LogData(LOG_LEVEL_DEBUG, prefix, op.params[k].tmpref.buffer, op.params[k].tmpref.size > 256 ? 256 : op.params[k].tmpref.size); // Log first 256 bytes
            } else if (pt == TEEC_VALUE_INPUT || pt == TEEC_VALUE_OUTPUT) {
                Logger_Log(LOG_LEVEL_DEBUG, "Fuzzed Op Param %d (Value): a=0x%x, b=0x%x", k, op.params[k].value.a, op.params[k].value.b);
            }
        }

        res = TAInteractor_InvokeCommand(&tee_session, cmd_id, &op, &err_origin);
        
        // Update TA initialization state based on CMD_HDCP_INITIALIZE result
        if (cmd_id == CMD_HDCP_INITIALIZE) {
            if (res == TEEC_SUCCESS) {
                is_ta_fully_initialized = true;
                Logger_Log(LOG_LEVEL_INFO, "CMD_HDCP_INITIALIZE successful. TA is now considered initialized.");
            } else {
                is_ta_fully_initialized = false;
                Logger_Log(LOG_LEVEL_WARNING, "CMD_HDCP_INITIALIZE failed. TA is NOT initialized.");
            }
        } else if (cmd_id == CMD_HDCP_FINALIZE) {
             is_ta_fully_initialized = false; // Assume finalize always de-initializes state for fuzzing purposes
             Logger_Log(LOG_LEVEL_INFO, "CMD_HDCP_FINALIZE called. TA is now considered uninitialized.");
        }

        bool crash_detected = CrashDetector_AnalyzeResult(cmd_id, res, err_origin, &op, current_cmd_spec);
        if (crash_detected) {
            Logger_Log(LOG_LEVEL_CRASH, "Potential crash/issue detected for command %s (0x%x) on iteration %u!", current_cmd_spec->command_name, cmd_id, i + 1);
        }

cleanup_params:
        for (int j = 0; j < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++j) {
            uint32_t param_type = TEEC_PARAM_TYPE_GET(current_cmd_spec->expected_param_types, j);
            if (param_type == TEEC_MEMREF_TEMP_INPUT || 
                param_type == TEEC_MEMREF_TEMP_OUTPUT || 
                param_type == TEEC_MEMREF_TEMP_INOUT) {
                if (op.params[j].tmpref.buffer) {
                    free(op.params[j].tmpref.buffer);
                    op.params[j].tmpref.buffer = NULL; // Avoid double free
                }
            }
        }

        if (res == TEEC_ERROR_TARGET_DEAD) {
            Logger_Log(LOG_LEVEL_ERROR, "TA died. Attempting to reopen session.");
            TAInteractor_CloseSession(&tee_session);
            ta_session_opened = false;
            is_ta_fully_initialized = false;
            TEEC_Result reopen_res = TAInteractor_OpenSession(&tee_ctx, &tee_session, &ta_uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
            if (reopen_res == TEEC_SUCCESS) {
                ta_session_opened = true;
                Logger_Log(LOG_LEVEL_INFO, "TA Session reopened successfully.");
            } else {
                Logger_Log(LOG_LEVEL_ERROR, "Failed to reopen TA session: 0x%x. Exiting loop.", reopen_res);
                break; 
            }
        }
        if (i % 100 == 0 && i > 0) { // Log progress periodically
             Logger_Log(LOG_LEVEL_INFO, "Progress: Iteration %u/%u completed.", i + 1, num_iterations);
        }
    }
    Logger_Log(LOG_LEVEL_INFO, "Fuzzing loop completed.");
}

void FuzzerCore_SelectNextCommand(TEEC_Session* session, uint32_t* cmd_id, TEEC_Operation* operation, const TA_Command_Spec_t** cmd_spec_ptr) {
    static int current_cmd_index = -1; // Start before the first command to ensure CMD_HDCP_INITIALIZE is tried first if needed
    
    // Simple strategy: try to initialize first if not initialized, then cycle through commands.
    if (!is_ta_fully_initialized) {
        bool found_init = false;
        for(int i=0; i<num_command_specs; ++i) {
            if(command_specs[i].command_id == CMD_HDCP_INITIALIZE) {
                *cmd_spec_ptr = &command_specs[i];
                current_cmd_index = i; // Set index to INITIALIZE command
                found_init = true;
                break;
            }
        }
        if (!found_init) { // Should not happen if INITIALIZE is in specs
            Logger_Log(LOG_LEVEL_ERROR, "CMD_HDCP_INITIALIZE not found in specs!");
            *cmd_spec_ptr = &command_specs[0]; // Fallback
            current_cmd_index = 0;
        }
    } else {
        current_cmd_index = (current_cmd_index + 1) % num_command_specs;
        *cmd_spec_ptr = &command_specs[current_cmd_index];
        // Skip trying to re-initialize if already initialized, unless it's its turn in the cycle
        if ((*cmd_spec_ptr)->command_id == CMD_HDCP_INITIALIZE && is_ta_fully_initialized && num_command_specs > 1) {
            current_cmd_index = (current_cmd_index + 1) % num_command_specs;
            *cmd_spec_ptr = &command_specs[current_cmd_index];
        }
    }

    *cmd_id = (*cmd_spec_ptr)->command_id;
    
    memset(operation, 0, sizeof(TEEC_Operation));
    operation->paramTypes = (*cmd_spec_ptr)->expected_param_types;

    // If a command requires initialized state but we are not (and it's not INITIALIZE itself)
    // then force INITIALIZE. This is a fallback, primary logic is above.
    if ((*cmd_spec_ptr)->requires_initialized_state && !is_ta_fully_initialized && *cmd_id != CMD_HDCP_INITIALIZE) {
        Logger_Log(LOG_LEVEL_DEBUG, "Override: TA not initialized, attempting CMD_HDCP_INITIALIZE.");
        for(int i=0; i<num_command_specs; ++i) {
            if(command_specs[i].command_id == CMD_HDCP_INITIALIZE) {
                *cmd_spec_ptr = &command_specs[i];
                current_cmd_index = i;
                break;
            }
        }
        *cmd_id = CMD_HDCP_INITIALIZE;
        operation->paramTypes = (*cmd_spec_ptr)->expected_param_types;
    }
}

void FuzzerCore_Shutdown(void) {
    Logger_Log(LOG_LEVEL_INFO, "FuzzerCore shutting down...");
    if (ta_session_opened) {
        TAInteractor_CloseSession(&tee_session);
        ta_session_opened = false;
    }
    TAInteractor_FinalizeContext(&tee_ctx);
    Logger_Log(LOG_LEVEL_INFO, "FuzzerCore shut down complete.");
    Logger_Shutdown();
}

int main(int argc, char* argv[]) {
    uint32_t iterations = 1000; 
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations == 0 && strcmp(argv[1], "0") != 0) {
            fprintf(stderr, "Invalid number of iterations: %s\n", argv[1]);
            return 1;
        }
    }
    if (argc > 2) {
        // Could add more params, e.g., log level
        LogLevel new_level = (LogLevel)atoi(argv[2]);
        if (new_level >= LOG_LEVEL_DEBUG && new_level <= LOG_LEVEL_CRASH) {
             Logger_SetLevel(new_level); // Assuming Logger_SetLevel is exposed and works before Init
        }
    }

    FuzzerCore_Init();
    // If log level was passed as arg, set it after Logger_Init if it's safer
    // Logger_SetLevel(LOG_LEVEL_DEBUG); // Example: set desired log level

    FuzzerCore_RunFuzzingLoop(iterations);
    FuzzerCore_Shutdown();

    return 0;
}


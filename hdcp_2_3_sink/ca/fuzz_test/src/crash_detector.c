#include "crash_detector.h"
#include "fuzzer.h" // For TA_Command_Spec_t
#include "logger.h"
#include <stdio.h> // For sprintf, if used
#include <string.h>

// Helper to convert TEEC_Result to string if needed (basic version)
const char* teec_result_to_string(TEEC_Result res) {
    switch (res) {
        case TEEC_SUCCESS: return "TEEC_SUCCESS";
        case TEEC_ERROR_GENERIC: return "TEEC_ERROR_GENERIC";
        case TEEC_ERROR_ACCESS_DENIED: return "TEEC_ERROR_ACCESS_DENIED";
        case TEEC_ERROR_CANCEL: return "TEEC_ERROR_CANCEL";
        case TEEC_ERROR_ACCESS_CONFLICT: return "TEEC_ERROR_ACCESS_CONFLICT";
        case TEEC_ERROR_EXCESS_DATA: return "TEEC_ERROR_EXCESS_DATA";
        case TEEC_ERROR_BAD_FORMAT: return "TEEC_ERROR_BAD_FORMAT";
        case TEEC_ERROR_BAD_PARAMETERS: return "TEEC_ERROR_BAD_PARAMETERS";
        case TEEC_ERROR_BAD_STATE: return "TEEC_ERROR_BAD_STATE";
        case TEEC_ERROR_ITEM_NOT_FOUND: return "TEEC_ERROR_ITEM_NOT_FOUND";
        case TEEC_ERROR_NOT_IMPLEMENTED: return "TEEC_ERROR_NOT_IMPLEMENTED";
        case TEEC_ERROR_NOT_SUPPORTED: return "TEEC_ERROR_NOT_SUPPORTED";
        case TEEC_ERROR_NO_DATA: return "TEEC_ERROR_NO_DATA";
        case TEEC_ERROR_OUT_OF_MEMORY: return "TEEC_ERROR_OUT_OF_MEMORY";
        case TEEC_ERROR_BUSY: return "TEEC_ERROR_BUSY";
        case TEEC_ERROR_COMMUNICATION: return "TEEC_ERROR_COMMUNICATION";
        case TEEC_ERROR_SECURITY: return "TEEC_ERROR_SECURITY";
        case TEEC_ERROR_SHORT_BUFFER: return "TEEC_ERROR_SHORT_BUFFER";
        case TEEC_ERROR_EXTERNAL_CANCEL: return "TEEC_ERROR_EXTERNAL_CANCEL";
        case TEEC_ERROR_TARGET_DEAD: return "TEEC_ERROR_TARGET_DEAD";
        default: return "UNKNOWN TEEC_Result";
    }
}

bool CrashDetector_AnalyzeResult(uint32_t cmd_id, TEEC_Result result, uint32_t errorOrigin, TEEC_Operation* operation, const void* cmd_spec_void) {
    const TA_Command_Spec_t* cmd_spec = (const TA_Command_Spec_t*)cmd_spec_void;
    bool potential_crash = false;

    if (result == TEEC_SUCCESS) {
        // Logger_Log(LOG_LEVEL_DEBUG, "Command 0x%x (%s) executed successfully.", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown");
        // Even success can be interesting if input was clearly invalid but TA accepted it.
        // This logic can be expanded.
    } else {
        Logger_Log(LOG_LEVEL_WARNING, "Command 0x%x (%s) failed! Result: 0x%x (%s), Origin: 0x%x", 
                   cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown", result, teec_result_to_string(result), errorOrigin);
        
        // Define what constitutes a potential crash or interesting failure
        if (result == TEEC_ERROR_TARGET_DEAD) {
            Logger_Log(LOG_LEVEL_CRASH, "CRASH DETECTED: TEEC_ERROR_TARGET_DEAD for command 0x%x (%s)", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown");
            potential_crash = true;
        } else if (result == TEEC_ERROR_COMMUNICATION) {
            Logger_Log(LOG_LEVEL_CRASH, "POTENTIAL ISSUE: TEEC_ERROR_COMMUNICATION for command 0x%x (%s). May indicate TA issue.", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown");
            potential_crash = true; // Or a high warning
        } else if (result == TEEC_ERROR_GENERIC && errorOrigin == TEEC_ORIGIN_TRUSTED_APP) {
             Logger_Log(LOG_LEVEL_WARNING, "Command 0x%x (%s) returned TEEC_ERROR_GENERIC from TA. Investigate.", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown");
            // Generic errors from TA can sometimes hide more serious issues.
        } else if (result == TEEC_ERROR_ACCESS_DENIED || result == TEEC_ERROR_SECURITY) {
            Logger_Log(LOG_LEVEL_WARNING, "Security related error for command 0x%x (%s): 0x%x. Investigate.", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown", result);
        }
        // Add more specific checks based on expected TA behavior for malformed inputs.
        // For example, if a command should always return BAD_PARAMETERS for certain inputs but returns something else.
    }

    if (potential_crash) {
        CrashDetector_LogCrash(cmd_id, result, errorOrigin, operation, cmd_spec, "Automatically detected based on return code.");
    }
    return potential_crash;
}

void CrashDetector_LogCrash(uint32_t cmd_id, TEEC_Result result, uint32_t errorOrigin, TEEC_Operation* operation, const void* cmd_spec_void, const char* additional_info) {
    const TA_Command_Spec_t* cmd_spec = (const TA_Command_Spec_t*)cmd_spec_void;
    char crash_filename[256];
    // Create a unique filename for the crash details, e.g., based on timestamp or an incrementing counter
    // For simplicity, using cmd_id and a generic name here.
    sprintf(crash_filename, "crash_cmd_0x%x_res_0x%x.log", cmd_id, result);

    // Log to the main logger first
    Logger_Log(LOG_LEVEL_CRASH, "====== CRASH/ISSUE DETAILS ======");
    Logger_Log(LOG_LEVEL_CRASH, "Command: 0x%x (%s)", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown");
    Logger_Log(LOG_LEVEL_CRASH, "Result: 0x%x (%s), Origin: 0x%x", result, teec_result_to_string(result), errorOrigin);
    Logger_Log(LOG_LEVEL_CRASH, "Additional Info: %s", additional_info ? additional_info : "N/A");
    Logger_Log(LOG_LEVEL_CRASH, "Saving details to: %s", crash_filename);

    // Log parameters to the dedicated crash file
    // This is a simplified version. A real fuzzer would dump more state.
    FILE* f = fopen(crash_filename, "w");
    if (f) {
        fprintf(f, "Crash/Issue Report\n");
        fprintf(f, "Command ID: 0x%x (%s)\n", cmd_id, cmd_spec ? cmd_spec->command_name : "Unknown");
        fprintf(f, "TEEC_Result: 0x%x (%s)\n", result, teec_result_to_string(result));
        fprintf(f, "Error Origin: 0x%x\n", errorOrigin);
        fprintf(f, "Additional Info: %s\n", additional_info ? additional_info : "N/A");
        fprintf(f, "\nTEEC_Operation Details:\n");
        fprintf(f, "paramTypes: 0x%x\n", operation->paramTypes);
        for (int i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++i) {
            uint32_t param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
            fprintf(f, "  Param %d (type 0x%x):\n", i, param_type);
            if (param_type == TEEC_MEMREF_TEMP_INPUT || param_type == TEEC_MEMREF_TEMP_OUTPUT || param_type == TEEC_MEMREF_TEMP_INOUT || param_type == TEEC_MEMREF_WHOLE) {
                fprintf(f, "    memref.buffer: %p\n", operation->params[i].tmpref.buffer);
                fprintf(f, "    memref.size: %zu\n", operation->params[i].tmpref.size);
                if (operation->params[i].tmpref.buffer && operation->params[i].tmpref.size > 0) {
                    fprintf(f, "    memref.data (hex): ");
                    for (size_t j = 0; j < operation->params[i].tmpref.size; ++j) {
                        fprintf(f, "%02x", ((uint8_t*)operation->params[i].tmpref.buffer)[j]);
                    }
                    fprintf(f, "\n");
                }
            } else if (param_type == TEEC_VALUE_INPUT || param_type == TEEC_VALUE_OUTPUT) {
                fprintf(f, "    value.a: 0x%x (%u)\n", operation->params[i].value.a, operation->params[i].value.a);
                fprintf(f, "    value.b: 0x%x (%u)\n", operation->params[i].value.b, operation->params[i].value.b);
            }
        }
        fclose(f);
    } else {
        Logger_Log(LOG_LEVEL_ERROR, "Failed to open crash log file: %s", crash_filename);
    }
    Logger_Log(LOG_LEVEL_CRASH, "===============================");

    // In a more advanced fuzzer, this might also save QEMU state or other environment details.
}



#ifndef CRASH_DETECTOR_H
#define CRASH_DETECTOR_H

#include <tee_client_api.h>
#include <stdbool.h>
#include <stdint.h>

// Forward declaration from fuzzer.h if needed
// For TEEC_Operation

bool CrashDetector_AnalyzeResult(uint32_t cmd_id, TEEC_Result result, uint32_t errorOrigin, TEEC_Operation* operation, const void* cmd_spec /* TA_Command_Spec_t* */);
void CrashDetector_LogCrash(uint32_t cmd_id, TEEC_Result result, uint32_t errorOrigin, TEEC_Operation* operation, const void* cmd_spec /* TA_Command_Spec_t* */, const char* additional_info);

#endif // CRASH_DETECTOR_H


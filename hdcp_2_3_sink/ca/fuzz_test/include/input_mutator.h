#ifndef INPUT_MUTATOR_H
#define INPUT_MUTATOR_H

#include <tee_client_api.h>
#include <stddef.h>
#include <stdint.h>

// Forward declaration from fuzzer.h if needed, or include fuzzer.h
// For now, assume TEEC_Operation is available via tee_client_api.h

void InputMutator_FuzzOperation(TEEC_Operation* operation, uint32_t cmd_id, const void* cmd_spec /* TA_Command_Spec_t* */);
void InputMutator_FuzzMemref(TEEC_TempMemoryReference* memref, size_t expected_size, uint32_t cmd_id, uint32_t param_index, uint32_t param_type);
void InputMutator_FuzzValue(TEEC_Value* value, bool is_a_value, uint32_t cmd_id, uint32_t param_index);

#endif // INPUT_MUTATOR_H


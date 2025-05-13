#include "input_mutator.h"
#include "fuzzer.h" // For TA_Command_Spec_t
#include "logger.h"
#include <string.h> // For memset, memcpy
#include <stdlib.h> // For rand, malloc, free
#include <stdio.h>  // For NULL if not in stdlib

// Helper function to get a random number in a range
static int get_random_int(int min, int max) {
    if (min > max) {
        // Swap if min > max to prevent modulo by zero or negative
        int temp = min;
        min = max;
        max = temp;
    }
    if (min == max) return min;
    return min + rand() % (max - min + 1);
}

// Basic mutation: randomly flip some bits in a buffer
static void simple_bit_flip_mutation(uint8_t* buffer, size_t size) {
    if (!buffer || size == 0) return;
    // Flip up to 10% of bits, or at least 1 bit if size is small
    int num_flips = get_random_int(1, (size * 8 / 10) > 0 ? (size * 8 / 10) : 1);
    for (int i = 0; i < num_flips; ++i) {
        int byte_idx = get_random_int(0, size - 1);
        int bit_idx = get_random_int(0, 7);
        buffer[byte_idx] ^= (1 << bit_idx);
    }
}

void InputMutator_FuzzOperation(TEEC_Operation* operation, uint32_t cmd_id, const void* cmd_spec_void) {
    const TA_Command_Spec_t* cmd_spec = (const TA_Command_Spec_t*)cmd_spec_void;
    if (!operation || !cmd_spec) {
        Logger_Log(LOG_LEVEL_WARNING, "InputMutator_FuzzOperation: Null operation or cmd_spec.");
        return;
    }

    // Logger_Log(LOG_LEVEL_DEBUG, "Fuzzing operation for command ID: 0x%x (%s)", cmd_id, cmd_spec->command_name);

    // paramTypes is set by FuzzerCore before calling this based on cmd_spec->expected_param_types.
    // operation->paramTypes = cmd_spec->expected_param_types; // This should already be set.

    for (int i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++i) {
        uint32_t param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
        switch (param_type) {
            case TEEC_MEMREF_TEMP_INPUT:
            case TEEC_MEMREF_TEMP_OUTPUT:
            case TEEC_MEMREF_TEMP_INOUT:
            case TEEC_MEMREF_WHOLE: // TEEC_MEMREF_WHOLE might need special handling if it refers to a registered shared memory block
                                  // For now, treat similarly to TEMP memrefs assuming FuzzerCore allocated it.
                // operation->params[i].tmpref.size initially holds the allocated buffer capacity from FuzzerCore.
                InputMutator_FuzzMemref(&operation->params[i].tmpref, operation->params[i].tmpref.size, cmd_id, i, param_type);
                break;
            case TEEC_VALUE_INPUT:
            case TEEC_VALUE_OUTPUT: // Fuzzing output values as input doesn't make sense unless TA reads them.
                                  // We fuzz based on whether it's an INPUT type.
                InputMutator_FuzzValue(&operation->params[i].value, (param_type == TEEC_VALUE_INPUT), cmd_id, i);
                break;
            case TEEC_NONE:
            default:
                break;
        }
    }
}

// buffer_capacity is the actual allocated size of memref->buffer.
void InputMutator_FuzzMemref(TEEC_TempMemoryReference* memref, size_t buffer_capacity, uint32_t cmd_id, uint32_t param_index, uint32_t param_type) {
    if (!memref) return;

    size_t fuzzed_reported_size;
    int size_mutation_strategy = rand() % 7;

    // Determine the fuzzed size to *report* to the TA via memref->size
    switch (size_mutation_strategy) {
        case 0: fuzzed_reported_size = 0; break; // Zero size
        case 1: fuzzed_reported_size = 1; break; // Size of 1
        case 2: fuzzed_reported_size = buffer_capacity / 2; break; // Half of allocated
        case 3: fuzzed_reported_size = buffer_capacity; break; // Full allocated capacity
        case 4: fuzzed_reported_size = buffer_capacity + get_random_int(1, 128); break; // Slightly larger than allocated
        case 5: fuzzed_reported_size = get_random_int(0, buffer_capacity); break; // Random within allocated
        case 6: default: fuzzed_reported_size = get_random_int(0, buffer_capacity * 2 + 128); break; // Random, possibly larger
    }

    // For OUTPUT buffers, TA writes, so we provide a buffer and a size. 
    // The TA might respect memref->size as the max it can write.
    // Fuzzing content of OUTPUT-only buffers before call is usually not meaningful, but size is.
    // For INPUT or INOUT, we fuzz content.
    if (param_type == TEEC_MEMREF_TEMP_INPUT || param_type == TEEC_MEMREF_TEMP_INOUT) {
        if (!memref->buffer && buffer_capacity > 0) {
            // This case should ideally be prevented by FuzzerCore ensuring buffer is allocated if capacity > 0
            Logger_Log(LOG_LEVEL_WARNING, "InputMutator_FuzzMemref: memref->buffer is NULL for INPUT/INOUT param (cmd 0x%x, param %d) but capacity is %zu. Cannot fuzz content.", cmd_id, param_index, buffer_capacity);
            // We will still set the fuzzed_reported_size, TA might crash with NULL buffer and non-zero size.
        } else if (memref->buffer && buffer_capacity > 0) {
            // Determine how much of the buffer to actually fill with fuzzed data.
            // This should not exceed the actual allocated capacity.
            size_t content_to_fuzz_len = (fuzzed_reported_size < buffer_capacity) ? fuzzed_reported_size : buffer_capacity;
            if (fuzzed_reported_size == 0) content_to_fuzz_len = 0; // If reported size is 0, don't fuzz content.
            
            if (content_to_fuzz_len > 0) {
                int mutation_choice = rand() % 4;
                if (mutation_choice == 0) { // Completely random bytes
                    for(size_t k=0; k<content_to_fuzz_len; ++k) ((uint8_t*)memref->buffer)[k] = rand() % 256;
                } else if (mutation_choice == 1) { // Pattern: 0xAA
                    memset(memref->buffer, 0xAA, content_to_fuzz_len);
                } else if (mutation_choice == 2) { // Pattern: 0x00 then bit flips
                    memset(memref->buffer, 0x00, content_to_fuzz_len);
                    simple_bit_flip_mutation((uint8_t*)memref->buffer, content_to_fuzz_len);
                } else { // Pattern: 0xFF then bit flips
                    memset(memref->buffer, 0xFF, content_to_fuzz_len);
                    simple_bit_flip_mutation((uint8_t*)memref->buffer, content_to_fuzz_len);
                }
            }
        } else if (memref->buffer && buffer_capacity == 0 && fuzzed_reported_size > 0) {
             Logger_Log(LOG_LEVEL_DEBUG, "InputMutator_FuzzMemref: cmd 0x%x, param %d. Buffer exists but capacity is 0. Reporting size %zu.", cmd_id, param_index, fuzzed_reported_size);
        }
    }
    // For TEEC_MEMREF_TEMP_OUTPUT, the TA writes into memref->buffer up to memref->size.
    // We've already allocated memref->buffer in FuzzerCore with 'buffer_capacity'.
    // The 'fuzzed_reported_size' will tell the TA how much space it *thinks* it has.
    // If fuzzed_reported_size > buffer_capacity, TA might write out of bounds if it trusts the size.

    memref->size = fuzzed_reported_size; // This is the size reported to the TA.

    Logger_Log(LOG_LEVEL_DEBUG, "Fuzzed memref for cmd 0x%x, param %d: reported_size=%zu (allocated_capacity=%zu, type=0x%x)", 
                cmd_id, param_index, memref->size, buffer_capacity, param_type);
}

void InputMutator_FuzzValue(TEEC_Value* value, bool is_input_value, uint32_t cmd_id, uint32_t param_index) {
    if (!value) return;

    uint32_t original_a = value->a;
    uint32_t original_b = value->b;

    // Only fuzz if it's an INPUT value parameter, or if we decide to fuzz all value params regardless.
    // For now, only fuzz if is_input_value is true for 'a'. 'b' is often used for output size or secondary input.
    // Let's fuzz both 'a' and 'b' if is_input_value is true, assuming both could be inputs.
    if (is_input_value) {
        int mutation_type_a = rand() % 5;
        switch (mutation_type_a) {
            case 0: value->a = 0; break;
            case 1: value->a = 1; break;
            case 2: value->a = 0xFFFFFFFF; break;
            case 3: value->a = get_random_int(0, 255); break;
            case 4: default: value->a = rand(); break;
        }
    }
    // Fuzz 'b' more generally or if it's also known to be an input for this command.
    // For simplicity, let's apply some fuzzing to 'b' always, but could be conditional.
    int mutation_type_b = rand() % 5;
    switch (mutation_type_b) {
        case 0: value->b = 0; break;
        case 1: value->b = 1; break;
        case 2: value->b = 0xFFFFFFFF; break;
        case 3: value->b = get_random_int(0, 255); break;
        case 4: default: value->b = rand(); break;
    }

    Logger_Log(LOG_LEVEL_DEBUG, "Fuzzed value for cmd 0x%x, param %d (is_input_value=%d): a=0x%x, b=0x%x (original a=0x%x, b=0x%x)", 
                cmd_id, param_index, is_input_value, value->a, value->b, original_a, original_b);
}


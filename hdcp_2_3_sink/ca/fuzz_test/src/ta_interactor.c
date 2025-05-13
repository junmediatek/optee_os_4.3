#include "ta_interactor.h"
#include "logger.h"
#include <stdio.h> // For printf or error logging if Logger is not yet fully available

TEEC_Result TAInteractor_InitializeContext(TEEC_Context* context) {
    if (!context) {
        // Cannot log if logger is not up or if context is for logger itself.
        // fprintf(stderr, "TAInteractor_InitializeContext: Null context provided.\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    Logger_Log(LOG_LEVEL_DEBUG, "Initializing TEE context...");
    TEEC_Result res = TEEC_InitializeContext(NULL, context);
    if (res != TEEC_SUCCESS) {
        Logger_Log(LOG_LEVEL_ERROR, "TEEC_InitializeContext failed with code 0x%x", res);
    }
    return res;
}

TEEC_Result TAInteractor_OpenSession(TEEC_Context* context, TEEC_Session* session, const TEEC_UUID* destination, 
                                   uint32_t connectionMethod, const void* connectionData, 
                                   TEEC_Operation* operation, uint32_t* errorOrigin) {
    if (!context || !session || !destination) {
        Logger_Log(LOG_LEVEL_ERROR, "TAInteractor_OpenSession: Null context, session, or destination.");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    Logger_Log(LOG_LEVEL_DEBUG, "Opening session with TA UUID: %p...", (void*)destination); // Log UUID properly
    TEEC_Result res = TEEC_OpenSession(context, session, destination, connectionMethod, connectionData, operation, errorOrigin);
    if (res != TEEC_SUCCESS) {
        Logger_Log(LOG_LEVEL_ERROR, "TEEC_OpenSession failed with code 0x%x, origin 0x%x", res, *errorOrigin);
    }
    return res;
}

TEEC_Result TAInteractor_InvokeCommand(TEEC_Session* session, uint32_t commandID, TEEC_Operation* operation, uint32_t* errorOrigin) {
    if (!session || !operation) {
        Logger_Log(LOG_LEVEL_ERROR, "TAInteractor_InvokeCommand: Null session or operation.");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    Logger_Log(LOG_LEVEL_DEBUG, "Invoking command ID 0x%x...", commandID);
    TEEC_Result res = TEEC_InvokeCommand(session, commandID, operation, errorOrigin);
    // Detailed logging of result is usually done by CrashDetector or FuzzerCore
    // Logger_Log(LOG_LEVEL_DEBUG, "TEEC_InvokeCommand for 0x%x returned 0x%x, origin 0x%x", commandID, res, *errorOrigin);
    return res;
}

void TAInteractor_CloseSession(TEEC_Session* session) {
    if (!session) {
        Logger_Log(LOG_LEVEL_WARNING, "TAInteractor_CloseSession: Null session provided.");
        return;
    }
    Logger_Log(LOG_LEVEL_DEBUG, "Closing TA session...");
    TEEC_CloseSession(session);
}

void TAInteractor_FinalizeContext(TEEC_Context* context) {
    if (!context) {
        Logger_Log(LOG_LEVEL_WARNING, "TAInteractor_FinalizeContext: Null context provided.");
        return;
    }
    Logger_Log(LOG_LEVEL_DEBUG, "Finalizing TEE context...");
    TEEC_FinalizeContext(context);
}


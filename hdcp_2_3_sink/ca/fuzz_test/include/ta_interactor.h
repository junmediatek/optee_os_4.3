#ifndef TA_INTERACTOR_H
#define TA_INTERACTOR_H

#include <tee_client_api.h>

TEEC_Result TAInteractor_InitializeContext(TEEC_Context* context);
TEEC_Result TAInteractor_OpenSession(TEEC_Context* context, TEEC_Session* session, const TEEC_UUID* destination, uint32_t connectionMethod, const void* connectionData, TEEC_Operation* operation, uint32_t* errorOrigin);
TEEC_Result TAInteractor_InvokeCommand(TEEC_Session* session, uint32_t commandID, TEEC_Operation* operation, uint32_t* errorOrigin);
void TAInteractor_CloseSession(TEEC_Session* session);
void TAInteractor_FinalizeContext(TEEC_Context* context);

#endif // TA_INTERACTOR_H


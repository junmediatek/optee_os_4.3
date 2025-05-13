cflags-remove-Werror = y

# Include paths for fuzzer's own headers
global_cflags += -I$(LOCAL_DIR)/include

# Include paths for TEE client API and development kit
# These are typically provided by the OP-TEE build system if TA_DEV_KIT_DIR and OPTEE_CLIENT_EXPORT are set.
# If not, these might need adjustment based on the actual OP-TEE build environment.
ifeq ($(TA_DEV_KIT_DIR),)
    $(error TA_DEV_KIT_DIR is not set. Please configure your OP-TEE build environment.)
endif
ifeq ($(OPTEE_CLIENT_EXPORT),)
    $(error OPTEE_CLIENT_EXPORT is not set. Please configure your OP-TEE build environment.)
endif
global_cflags += -I$(TA_DEV_KIT_DIR)/include
global_cflags += -I$(OPTEE_CLIENT_EXPORT)/include

# Include paths for HDCP specific headers (relative to this sub.mk)
# hdcp_common_ta_ca.h is expected in ../../include/
# ta_hdcp_uuid.h is expected in ../../ta/include/
# These paths assume this fuzz_ca directory is at optee_os_4.3/hdcp_2_3_sink/ca/fuzz_ca/
global_cflags += -I../../include
global_cflags += -I../../ta/include

# Source files
srcs += src/main.c
srcs += src/input_mutator.c
srcs += src/ta_interactor.c
srcs += src/crash_detector.c
srcs += src/logger.c

# Libraries to link against
libs += -lteec # For TEE Client API functions
# libs += -lpthread # Uncomment if pthreads are used (e.g., for advanced logging)

# Name of the output binary
bin-name = hdcp_fuzzer


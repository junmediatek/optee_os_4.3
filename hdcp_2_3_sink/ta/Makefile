CROSS_COMPILE ?= arm-linux-gnueabihf-

# TA settings
BINARY_NAME := $(TA_HDCP_UUID).ta
TA_HDCP_UUID ?= 8aaaf200-2450-11e4-abe2-0002a5d5c51b # Replace with actual UUID from ta_hdcp_uuid.h
TA_VERSION := 1.0
TA_DESCRIPTION := "HDCP 2.3 Sink Trusted Application"

# Source files
SRCS += main.c
SRCS += hdcp_ta_core.c
SRCS += hdcp_ta_crypto.c
SRCS += hdcp_ta_storage.c

# Include directories
CFLAGS += -I./include
CFLAGS += -I../include # For hdcp_common_ta_ca.h

# Default flags for TA development. These might be overridden or augmented by the OP-TEE build system.
CFLAGS += -Wall -Wextra -Werror -pedantic
CFLAGS += -Os # Optimize for size
CFLAGS += -ffunction-sections -fdata-sections # For size optimization
LDFLAGS += -Wl,--gc-sections # For size optimization

# Properties for the TA binary (used by OP-TEE build system)
# These are typically set in the main OP-TEE build files, but good to have as reference.
# TA_FLAGS := TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_INSTANCE_KEEP_ALIVE
# TA_STACK_SIZE := 2048
# TA_HEAP_SIZE := 4096

# --- Standard OP-TEE TA Build System Integration --- 
# The following is a simplified representation. In a real OP-TEE build,
# this Makefile would typically be a `sub.mk` included by a parent Makefile.

# Path to OP-TEE build core. This needs to be correctly set in the actual build environment.
# Example: OPTEE_BUILD_CORE ?= /path/to/optee_os/mk/pta_dev_kit.mk
# For standalone compilation for structure checking, we might not include this.

# If OPTEE_BUILD_CORE is defined and points to a valid devkit Makefile:
# include $(OPTEE_BUILD_CORE)

# --- Fallback for standalone compilation (for syntax checking, not for final TA) ---
# This part is for basic compilation check if not integrated into full OP-TEE build.
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy

# Example CFLAGS for standalone (adjust for your TEE dev kit headers)
# You would need to point to the TEE Internal Core API headers, e.g., <tee_internal_api.h>
# CFLAGS += -I/path/to/optee_os/lib/libutee/include -I/path/to/optee_os/core/include/

OBJS := $(SRCS:.c=.o)

all: $(BINARY_NAME)

$(BINARY_NAME): $(OBJS)
	@echo "Warning: This is a standalone TA build, not using full OP-TEE build system."
	@echo "Final TA properties (UUID, flags, stack/heap) might not be correctly embedded."
	# Linking a TA usually involves a specific script or linker command from OP-TEE devkit.
	# This is a placeholder for a generic link, actual TA needs TA-specific linker script and options.
	$(CC) $(LDFLAGS) -o $(basename $@).elf $^ -nostdlib # Add TEE libs if needed
	# Convert to .ta format (this step is highly specific to OP-TEE's sign_encrypt.py or similar tools)
	# For now, just create a dummy .ta file
	$(OBJCOPY) -O binary $(basename $@).elf $@
	@echo "Built $(BINARY_NAME) (standalone placeholder)"

%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(basename $(BINARY_NAME)).elf $(BINARY_NAME)

.PHONY: all clean


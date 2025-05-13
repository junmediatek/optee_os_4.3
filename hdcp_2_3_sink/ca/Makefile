CROSS_COMPILE ?= 
CC := $(CROSS_COMPILE)gcc

# Application name
APP_NAME := test_hdcp_ca

# Source files
SRCS += ./test/test_hdcp_ca.c
SRCS += ./src/hdcp_ca_api.c

# Include directories
CFLAGS += -I./include # For hdcp_ca_api.h
CFLAGS += -I../include # For hdcp_common_ta_ca.h
CFLAGS += -I../ta/include # For ta_hdcp_uuid.h
# Add path to TEE Client API headers from cloned optee_client source
CFLAGS += -I/home/ubuntu/optee_client_source/libteec/include

# Libraries
# Link with TEE Client static libraries and their dependencies
LDFLAGS = /home/ubuntu/optee_client_source/build/libteec/libteec.a \
          /home/ubuntu/optee_client_source/build/libteeacl/libteeacl.a \
          -lpthread -luuid

# Default flags
CFLAGS += -Wall -Wextra -Werror -pedantic
CFLAGS += -g # For debugging

OBJS := $(SRCS:.c=.o)

all: $(APP_NAME)

$(APP_NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built CA test application: $(APP_NAME)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(APP_NAME)

.PHONY: all clean


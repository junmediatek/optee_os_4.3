# HDCP 2.3 Sink Implementation for WiFi-Display

This repository contains an implementation of HDCP 2.3 for WiFi-Display (Miracast) sink side based on OP-TEE 4.3.0.

## Overview

The implementation consists of:

- A User Trusted Application (UTA) that implements the core HDCP 2.3 functionality
- A Client Application (CA) that provides an API for applications to use the HDCP functionality

## Structure

- `ta/hdcp/`: Trusted Application implementation
  - `include/`: Public header files
  - `src/`: Source code
- `ca/hdcp/`: Client Application implementation

## Building

To build the implementation:

```
export TA_DEV_KIT_DIR=/path/to/optee_os_4.3/out/arm/export-ta_arm64
export TEEC_EXPORT=/path/to/optee_client/out/export
export HOST_CROSS_COMPILE=aarch64-linux-gnu-

make
```

## Testing

To test the implementation:

```
./ca/hdcp/hdcp_ca_test
```

To run fuzzing tests on the TA:

```
./tests/hdcp_ta_fuzz_test
```

## Features

- Complete HDCP 2.3 protocol implementation for WiFi-Display sink
- Authentication and Key Exchange (AKE)
- Locality Check (LC)
- Session Key Exchange (SKE)
- Secure video decryption using OP-TEE Secure Data Path
- All core cryptographic values kept securely in the TA

## Security Considerations

- All sensitive cryptographic operations are performed within the Trusted Application
- Video decryption is performed in secure memory
- Core values are never exposed to the Client Application

## License

This implementation is licensed under the BSD 2-Clause License.

/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRUSTY_APP_KEYMASTER_TRUSTY_KEYMASTER_MESSAGES_H_
#define TRUSTY_APP_KEYMASTER_TRUSTY_KEYMASTER_MESSAGES_H_

#include <keymaster/android_keymaster_messages.h>

namespace keymaster {

/**
 * Keymaster commands implemented by Trusty not used by Keymaster
 * reference implementation.
 */
enum TrustyKeymasterCommand {
    SET_BOOT_PARAMS = 0x1000,
    SET_ATTESTATION_KEY = 0x2000,
    SET_ATTESTATION_CERT_CHAIN = 0x3000,
};

/**
 * Generic struct for Keymaster responses which have no specialized response data
 */
struct NoResponse : public KeymasterResponse {
    explicit NoResponse(int32_t ver = MAX_MESSAGE_VERSION) : KeymasterResponse(ver) {}

    size_t NonErrorSerializedSize() const override { return 0; }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override { return buf; }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) { return true; }
};

struct SetBootParamsRequest : public KeymasterMessage {
    explicit SetBootParamsRequest(int32_t ver = MAX_MESSAGE_VERSION) : KeymasterMessage(ver) {}

    size_t SerializedSize() const override {
        return (sizeof(os_version) + sizeof(os_patchlevel) + sizeof(device_locked) +
                sizeof(verified_boot_state) + verified_boot_key.SerializedSize());
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint32_to_buf(buf, end, os_version);
        buf = append_uint32_to_buf(buf, end, os_patchlevel);
        buf = append_uint32_to_buf(buf, end, device_locked);
        buf = append_uint32_to_buf(buf, end, verified_boot_state);
        return verified_boot_key.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
        return copy_uint32_from_buf(buf_ptr, end, &os_version) &&
               copy_uint32_from_buf(buf_ptr, end, &os_patchlevel) &&
               copy_uint32_from_buf(buf_ptr, end, &device_locked) &&
               copy_uint32_from_buf(buf_ptr, end, &verified_boot_state) &&
               verified_boot_key.Deserialize(buf_ptr, end);
    }

    uint32_t os_version;
    uint32_t os_patchlevel;
    uint32_t device_locked;
    keymaster_verified_boot_t verified_boot_state;
    Buffer verified_boot_key;
};

struct SetBootParamsResponse : public NoResponse {};

struct SetAttestationKeyRequest : public KeymasterMessage {
    explicit SetAttestationKeyRequest(int32_t ver = MAX_MESSAGE_VERSION) : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return sizeof(uint32_t) + key_data.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint32_to_buf(buf, end, algorithm);
        return key_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
        return copy_uint32_from_buf(buf_ptr, end, &algorithm) && key_data.Deserialize(buf_ptr, end);
    }

    keymaster_algorithm_t algorithm;
    Buffer key_data;
};

struct SetAttestationKeyResponse : public NoResponse {};

// The bootloader should push certificates into Trusty, one certificate per request, starting
// with the attestation certificate. Multiple AppendAttestationCertChain requests are expected.
struct AppendAttestationCertChainRequest : public KeymasterMessage {
    explicit AppendAttestationCertChainRequest(int32_t ver = MAX_MESSAGE_VERSION)
        : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return sizeof(uint32_t) + cert_data.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint32_to_buf(buf, end, algorithm);
        return cert_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
        return copy_uint32_from_buf(buf_ptr, end, &algorithm) &&
               cert_data.Deserialize(buf_ptr, end);
    }

    keymaster_algorithm_t algorithm;
    Buffer cert_data;
};

struct AppendAttestationCertChainResponse : public NoResponse {};

// The bootloader should call the ProvisionKeybox to saved it into the securestorage
struct ProvsionAttesationKeyboxRequest : public KeymasterMessage {
    explicit ProvsionAttesationKeyboxRequest(int32_t ver = MAX_MESSAGE_VERSION)
        : KeymasterMessage(ver) {}

    size_t SerializedSize() const override {keybox_data.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return keybox_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
        return keybox_data.Deserialize(buf_ptr, end);
    }

    Buffer keybox_data;
};

struct ProvsionAttesationKeyboxResponse : public NoResponse {};

}  // namespace keymaster

#endif  // TRUSTY_APP_KEYMASTER_TRUSTY_KEYMASTER_MESSAGES_H_


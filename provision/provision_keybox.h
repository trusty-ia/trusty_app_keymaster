/*
**
** Copyright 2018, The Android Open Source Project
** Copyright (C) 2018 Intel Corporation
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef INCLUDE_PROVISION_ATTESTATION_KEYBOX__H_
#define INCLUDE_PROVISION_ATTESTATION_KEYBOX__H_

#include <keymaster/android_keymaster_messages.h>
#include <trusty_keymaster_messages.h>

namespace keymaster {

struct ProvisionAttesationKeyboxRequest : public KeymasterMessage {
    explicit ProvisionAttesationKeyboxRequest
        (int32_t ver = MAX_MESSAGE_VERSION) : KeymasterMessage(ver) {}

    size_t SerializedSize() const override {
        return keybox_data.SerializedSize();
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return keybox_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return keybox_data.Deserialize(buf_ptr, end);
    }

    Buffer keybox_data;
};

struct ProvisionAttesationKeyboxResponse : public NoResponse {};


class ProvisionKeyboxOperation {
public:
    // ProvisionAttesationKeybox can only be called from bootloader
    // it used to provision the keybox into RPMB storage
    // the original keybox will be retrieved from CSE
    void ProvisionAttesationKeybox(
            const ProvisionAttesationKeyboxRequest& request,
            ProvisionAttesationKeyboxResponse* response);
};

}  // namespace keymaster

#endif  // INCLUDE_PROVISION_ATTESTATION_KEYBOX__H_


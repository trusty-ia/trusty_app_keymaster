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

#include "trusty_keymaster.h"
#include <err.h>

namespace keymaster {

long TrustyKeymaster::GetAuthTokenKey(keymaster_key_blob_t* key) {
    keymaster_error_t error = context_->GetAuthTokenKey(key);
    if (error != KM_ERROR_OK)
        return ERR_GENERIC;
    return NO_ERROR;
}

void TrustyKeymaster::SetBootParams(const SetBootParamsRequest& request,
                                    SetBootParamsResponse* response) {
    if (response == nullptr)
        return;

    response->error = context_->SetBootParams(request.os_version, request.os_patchlevel,
                                              request.verified_boot_key,
                                              request.verified_boot_state,
                                              request.device_locked);
}

void TrustyKeymaster::SetAttestationKey(const SetAttestationKeyRequest& request,
                                        SetAttestationKeyResponse* response) {
    if (response == nullptr)
        return;
    size_t key_size = request.key_data.buffer_size();
    const uint8_t* key = request.key_data.begin();

    response->error = context_->SetAttestKey(request.algorithm, key, key_size);
}

void TrustyKeymaster::AppendAttestationCertChain(const AppendAttestationCertChainRequest& request,
                                                 AppendAttestationCertChainResponse* response) {
    if (response == nullptr)
        return;
    size_t cert_size = request.cert_data.buffer_size();
    const uint8_t* cert = request.cert_data.begin();

    response->error = context_->AppendAttestCertChain(request.algorithm, cert, cert_size);
}

void TrustyKeymaster::ProvsionAttesationKeybox(const ProvsionAttesationKeyboxRequest& request,
                                                 ProvsionAttesationKeyboxResponse* response) {
    if (response == nullptr)
        return;
    size_t keybox_size = request.keybox_data.buffer_size();
    const uint8_t* keybox = request.keybox_data.begin();

    response->error = context_->ProvisionAttestKeybox(keybox, keybox_size);
}

}  // namespace keymaster

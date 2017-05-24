/*
 * Copyright 2014 The Android Open Source Project
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

#pragma once

#include <keymaster/android_keymaster.h>
#include <keymaster/logger.h>

#include "trusty_keymaster_context.h"
#include "trusty_keymaster_messages.h"

namespace keymaster {

class TrustyKeymaster : public AndroidKeymaster {
  public:
    TrustyKeymaster(TrustyKeymasterContext* context, size_t operation_table_size)
        : AndroidKeymaster(context, operation_table_size), context_(context) {
        LOG_D("Creating TrustyKeymaster", 0);
    }

    long GetAuthTokenKey(keymaster_key_blob_t* key);
    void SetBootParams(const SetBootParamsRequest& request,
                SetBootParamsResponse* response);
    void SetAttestationKey(const SetAttestationKeyRequest& request,
                SetAttestationKeyResponse* response);
    void AppendAttestationCertChain(const AppendAttestationCertChainRequest& request,
                AppendAttestationCertChainResponse* response);

    bool ConfigureCalled() { return configure_error_ != KM_ERROR_KEYMASTER_NOT_CONFIGURED; }
    keymaster_error_t get_configure_error() { return configure_error_; }
    void set_configure_error(keymaster_error_t err) { configure_error_ = err; }

  private:
    TrustyKeymasterContext* context_;
    keymaster_error_t configure_error_ = KM_ERROR_KEYMASTER_NOT_CONFIGURED;
};

}  // namespace

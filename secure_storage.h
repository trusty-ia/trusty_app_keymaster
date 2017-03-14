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

#ifndef TRUSTY_APP_KEYMASTER_SECURE_STORAGE_H_
#define TRUSTY_APP_KEYMASTER_SECURE_STORAGE_H_

extern "C" {
#include <hardware/keymaster_defs.h>
}

namespace keymaster {

/**
 * These functions implement key and certificate chain storage on top Trusty's
 * secure storage service. All data is stored in the RPMB filesystem.
 */

/**
 * Writes |key_size| bytes at |key| to key file associated with |algorithm|.
 */
keymaster_error_t WriteKeyToStorage(keymaster_algorithm_t algorithm, const uint8_t* key,
                                    uint32_t key_size);

/**
 * Reads key associated with |algorithm|. Stores bytes read in |key_size| and allocates
 * memory to |key| containing read data. Caller takes ownership of |key|.
 */
keymaster_error_t ReadKeyFromStorage(keymaster_algorithm_t algorithm, uint8_t** key,
                                     uint32_t* key_size);

/**
 * Writes |cert_size| bytes at |cert| to cert file associated with |algorithm| and |index|.
 */
keymaster_error_t WriteCertToStorage(keymaster_algorithm_t algorithm, const uint8_t* cert,
                                     uint32_t cert_size, uint32_t index);

/**
 * Reads cert chain associated with |algorithm|. Stores certificate chain in |cert_chain|
 * and caller takes ownership of all allocated memory.
 */
keymaster_error_t ReadCertChainFromStorage(keymaster_algorithm_t algorithm,
                                           keymaster_cert_chain_t* cert_chain);

/**
 * Checks if |algorithm| attestation key exists in RPMB. On success, writes to |exists|.
 */
keymaster_error_t AttestationKeyExists(keymaster_algorithm_t algorithm, bool* exists);

/**
 * Reads the current length of the stored |algorithm| attestation certificate chain. On
 * success, writes the length to |cert_chain_length|.
 */
keymaster_error_t ReadCertChainLength(keymaster_algorithm_t algorithm, uint32_t* cert_chain_length);

}  // namespace keymaster

#endif  // TRUSTY_APP_KEYMASTER_SECURE_STORAGE_H_

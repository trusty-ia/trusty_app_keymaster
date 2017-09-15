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

// RSA and ECDSA are set to be the same as keymaster_algorithm_t.
enum class AttestationKeySlot {
    kInvalid = 0,
    kRsa = 1,
    kEcdsa = 3,
    kEddsa = 4,
    kEpid = 5,
    // 'Claimable slots are for use with the claim_key HAL method.
    kClaimable0 = 128,
    // 'Som' slots are for Android Things SoM keys. These are generic, that is
    // they are not associated with a particular model or product.
    kSomRsa = 257,
    kSomEcdsa = 259,
    kSomEddsa = 260,
    kSomEpid = 261,
};

/* The uuid size matches, by design, ATAP_HEX_UUID_LEN in system/iot/attestation/atap. */
const size_t kAttestationUuidSize = 32;

/**
 * These functions implement key and certificate chain storage on top Trusty's
 * secure storage service. All data is stored in the RPMB filesystem.
 */

/**
 * Writes |key_size| bytes at |key| to key file associated with |key_slot|.
 */
keymaster_error_t
WriteKeyToStorage(AttestationKeySlot key_slot, const uint8_t* key, uint32_t key_size);

/**
 * Reads key associated with |key_slot|. Stores bytes read in |key_size| and allocates
 * memory to |key| containing read data. Caller takes ownership of |key|.
 */
keymaster_error_t ReadKeyFromStorage(AttestationKeySlot key_slot, uint8_t** key,
                                     uint32_t* key_size);

/**
 * Writes |cert_size| bytes at |cert| to cert file associated with |key_slot| and |index|.
 */
keymaster_error_t WriteCertToStorage(AttestationKeySlot key_slot, const uint8_t* cert,
                                     uint32_t cert_size, uint32_t index);

/**
 * Reads cert chain associated with |key_slot|. Stores certificate chain in |cert_chain|
 * and caller takes ownership of all allocated memory.
 */
keymaster_error_t ReadCertChainFromStorage(AttestationKeySlot key_slot,
                                           keymaster_cert_chain_t* cert_chain);

/**
 * Checks if |key_slot| attestation key exists in RPMB. On success, writes to |exists|.
 */
keymaster_error_t AttestationKeyExists(AttestationKeySlot key_slot, bool* exists);

/**
 * Reads the current length of the stored |key_slot| attestation certificate chain. On
 * success, writes the length to |cert_chain_length|.
 */
keymaster_error_t ReadCertChainLength(AttestationKeySlot key_slot, uint32_t* cert_chain_length);

/**
 * Reads the |attestation_uuid|. If none exists, sets the uuid to all ascii zeros.
 */
keymaster_error_t ReadAttestationUuid(uint8_t attestation_uuid[kAttestationUuidSize]);

/**
 * Writes the |attestation_uuid|.
 */
keymaster_error_t WriteAttestationUuid(const uint8_t attestation_uuid[kAttestationUuidSize]);

}  // namespace keymaster

#endif  // TRUSTY_APP_KEYMASTER_SECURE_STORAGE_H_

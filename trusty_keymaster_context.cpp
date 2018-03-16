/*
 * Copyright 2015 The Android Open Source Project
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

#include "trusty_keymaster_context.h"
#include "secure_storage.h"

extern "C" {
#include <lib/hwkey/hwkey.h>
#include <lib/rng/trusty_rng.h>
}
#include <keymaster/logger.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/km_openssl/ec_key_factory.h>
#include <keymaster/km_openssl/rsa_key_factory.h>
#include <keymaster/km_openssl/aes_key.h>
#include <keymaster/km_openssl/hmac_key.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/attestation_utils.h>

#include <keymaster/key_blob_utils/auth_encrypted_key_blob.h>
#include <keymaster/key_blob_utils/ocb_utils.h>

#include "test_attestation_keys.h"


/**
 * Defining KEYMASTER_DEBUG will do the following:
 *
 * - Allow configure() to succeed without root of trust from bootloader
 * - Allow attestation keys and certificates to be overwritten once set
 */
//#define KEYMASTER_DEBUG

#ifdef KEYMASTER_DEBUG
#warning "Compiling with fake Keymaster Root of Trust values! DO NOT SHIP THIS!"
#endif

namespace keymaster {

namespace {
static const int kAesKeySize = 16;
static const int kCallsBetweenRngReseeds = 32;
static const int kRngReseedSize = 64;
static const uint8_t kMasterKeyDerivationData[kAesKeySize] = "KeymasterMaster";

bool UpgradeIntegerTag(keymaster_tag_t tag, uint32_t value, AuthorizationSet* set,
                       bool* set_changed) {
    int index = set->find(tag);
    if (index == -1) {
        keymaster_key_param_t param;
        param.tag = tag;
        param.integer = value;
        set->push_back(param);
        *set_changed = true;
        return true;
    }

    if (set->params[index].integer > value) {
        return false;
    }

    if (set->params[index].integer != value) {
        set->params[index].integer = value;
        *set_changed = true;
    }
    return true;
}

}  // anonymous namespace

TrustyKeymasterContext::TrustyKeymasterContext()
    : enforcement_policy_(this), rng_initialized_(false), calls_since_reseed_(0) {
    LOG_D("Creating TrustyKeymaster", 0);
    rsa_factory_.reset(new RsaKeyFactory(this));
    ec_factory_.reset(new EcKeyFactory(this));
    aes_factory_.reset(new AesKeyFactory(this, this));
    hmac_factory_.reset(new HmacKeyFactory(this, this));
    verified_boot_key_.Reinitialize("Unbound", 7);
}

KeyFactory* TrustyKeymasterContext::GetKeyFactory(keymaster_algorithm_t algorithm) const {
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return rsa_factory_.get();
    case KM_ALGORITHM_EC:
        return ec_factory_.get();
    case KM_ALGORITHM_AES:
        return aes_factory_.get();
    case KM_ALGORITHM_HMAC:
        return hmac_factory_.get();
    default:
        return nullptr;
    }
}

static keymaster_algorithm_t supported_algorithms[] = {KM_ALGORITHM_RSA, KM_ALGORITHM_EC,
                                                       KM_ALGORITHM_AES, KM_ALGORITHM_HMAC};

keymaster_algorithm_t*
TrustyKeymasterContext::GetSupportedAlgorithms(size_t* algorithms_count) const {
    *algorithms_count = array_length(supported_algorithms);
    return supported_algorithms;
}

OperationFactory* TrustyKeymasterContext::GetOperationFactory(keymaster_algorithm_t algorithm,
                                                              keymaster_purpose_t purpose) const {
    KeyFactory* key_factory = GetKeyFactory(algorithm);
    if (!key_factory)
        return nullptr;
    return key_factory->GetOperationFactory(purpose);
}

static keymaster_error_t TranslateAuthorizationSetError(AuthorizationSet::Error err) {
    switch (err) {
    case AuthorizationSet::OK:
        return KM_ERROR_OK;
    case AuthorizationSet::ALLOCATION_FAILURE:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    case AuthorizationSet::MALFORMED_DATA:
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterContext::SetAuthorizations(const AuthorizationSet& key_description,
                                                            keymaster_key_origin_t origin,
                                                            AuthorizationSet* hw_enforced,
                                                            AuthorizationSet* sw_enforced) const {
    sw_enforced->Clear();
    hw_enforced->Clear();

    for (auto& entry : key_description) {

        switch (entry.tag) {
        case KM_TAG_INVALID:
        case KM_TAG_BOOTLOADER_ONLY:
        case KM_TAG_NONCE:
        case KM_TAG_AUTH_TOKEN:
        case KM_TAG_MAC_LENGTH:
        case KM_TAG_ASSOCIATED_DATA:
        case KM_TAG_UNIQUE_ID:
            return KM_ERROR_INVALID_KEY_BLOB;

        case KM_TAG_ROLLBACK_RESISTANT:
        case KM_TAG_APPLICATION_ID:
        case KM_TAG_APPLICATION_DATA:
        case KM_TAG_ALL_APPLICATIONS:
        case KM_TAG_ROOT_OF_TRUST:
        case KM_TAG_ORIGIN:
        case KM_TAG_RESET_SINCE_ID_ROTATION:
        case KM_TAG_ALLOW_WHILE_ON_BODY:
        case KM_TAG_ATTESTATION_CHALLENGE:
        case KM_TAG_OS_VERSION:
        case KM_TAG_OS_PATCHLEVEL:
            // Ignore these.
            break;

        case KM_TAG_PURPOSE:
        case KM_TAG_ALGORITHM:
        case KM_TAG_KEY_SIZE:
        case KM_TAG_RSA_PUBLIC_EXPONENT:
        case KM_TAG_BLOB_USAGE_REQUIREMENTS:
        case KM_TAG_DIGEST:
        case KM_TAG_PADDING:
        case KM_TAG_BLOCK_MODE:
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
        case KM_TAG_MAX_USES_PER_BOOT:
        case KM_TAG_USER_SECURE_ID:
        case KM_TAG_NO_AUTH_REQUIRED:
        case KM_TAG_AUTH_TIMEOUT:
        case KM_TAG_CALLER_NONCE:
        case KM_TAG_MIN_MAC_LENGTH:
        case KM_TAG_KDF:
        case KM_TAG_EC_CURVE:
        case KM_TAG_ECIES_SINGLE_HASH_MODE:
            hw_enforced->push_back(entry);
            break;

        case KM_TAG_USER_AUTH_TYPE:
            if (entry.enumerated == HW_AUTH_PASSWORD)
                hw_enforced->push_back(entry);
            else
                sw_enforced->push_back(entry);
            break;

        case KM_TAG_ACTIVE_DATETIME:
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
        case KM_TAG_USAGE_EXPIRE_DATETIME:
        case KM_TAG_USER_ID:
        case KM_TAG_ALL_USERS:
        case KM_TAG_INCLUDE_UNIQUE_ID:
        case KM_TAG_EXPORTABLE:

            sw_enforced->push_back(entry);
            break;
        default:
            break;
        }
    }

    sw_enforced->push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
    hw_enforced->push_back(TAG_ORIGIN, origin);
    // these values will be 0 if not set by bootloader
    hw_enforced->push_back(TAG_OS_VERSION, boot_os_version_);
    hw_enforced->push_back(TAG_OS_PATCHLEVEL, boot_os_patchlevel_);

    if (sw_enforced->is_valid() != AuthorizationSet::OK)
        return TranslateAuthorizationSetError(sw_enforced->is_valid());
    if (hw_enforced->is_valid() != AuthorizationSet::OK)
        return TranslateAuthorizationSetError(hw_enforced->is_valid());
    return KM_ERROR_OK;
}

keymaster_error_t
TrustyKeymasterContext::BuildHiddenAuthorizations(const AuthorizationSet& input_set,
                                                  AuthorizationSet* hidden) const {
    keymaster_blob_t entry;
    if (input_set.GetTagValue(TAG_APPLICATION_ID, &entry))
        hidden->push_back(TAG_APPLICATION_ID, entry.data, entry.data_length);
    if (input_set.GetTagValue(TAG_APPLICATION_DATA, &entry))
        hidden->push_back(TAG_APPLICATION_DATA, entry.data, entry.data_length);

    // Copy verified boot key, verified boot state, and device lock state to hidden
    // authorization set for binding to key.
    keymaster_key_param_t root_of_trust;
    root_of_trust.tag = KM_TAG_ROOT_OF_TRUST;
    root_of_trust.blob.data = verified_boot_key_.begin();
    root_of_trust.blob.data_length = verified_boot_key_.buffer_size();
    hidden->push_back(root_of_trust);

    root_of_trust.blob.data = reinterpret_cast<const uint8_t*>(&verified_boot_state_);
    root_of_trust.blob.data_length = sizeof(verified_boot_state_);
    hidden->push_back(root_of_trust);

    root_of_trust.blob.data = reinterpret_cast<const uint8_t*>(&device_locked_);
    root_of_trust.blob.data_length = sizeof(device_locked_);
    hidden->push_back(root_of_trust);

    return TranslateAuthorizationSetError(hidden->is_valid());
}

keymaster_error_t TrustyKeymasterContext::CreateAuthEncryptedKeyBlob(
    const AuthorizationSet& key_description, const KeymasterKeyBlob& key_material,
    const AuthorizationSet& hw_enforced, const AuthorizationSet& sw_enforced,
    KeymasterKeyBlob* blob) const {
    AuthorizationSet hidden;
    keymaster_error_t error = BuildHiddenAuthorizations(key_description, &hidden);
    if (error != KM_ERROR_OK)
        return error;

    KeymasterKeyBlob master_key;
    error = DeriveMasterKey(&master_key);
    if (error != KM_ERROR_OK)
        return error;

    Buffer nonce(OCB_NONCE_LENGTH);
    Buffer tag(OCB_TAG_LENGTH);
    if (!nonce.peek_write() || !tag.peek_write())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    error = GenerateRandom(nonce.peek_write(), OCB_NONCE_LENGTH);
    if (error != KM_ERROR_OK)
        return error;
    nonce.advance_write(OCB_NONCE_LENGTH);

    KeymasterKeyBlob encrypted_key;
    error = OcbEncryptKey(hw_enforced, sw_enforced, hidden, master_key, key_material, nonce,
                          &encrypted_key, &tag);
    if (error != KM_ERROR_OK)
        return error;

    return SerializeAuthEncryptedBlob(encrypted_key, hw_enforced, sw_enforced, nonce, tag, blob);
}

keymaster_error_t TrustyKeymasterContext::CreateKeyBlob(const AuthorizationSet& key_description,
                                                        keymaster_key_origin_t origin,
                                                        const KeymasterKeyBlob& key_material,
                                                        KeymasterKeyBlob* blob,
                                                        AuthorizationSet* hw_enforced,
                                                        AuthorizationSet* sw_enforced) const {
    keymaster_error_t error = SetAuthorizations(key_description, origin, hw_enforced, sw_enforced);
    if (error != KM_ERROR_OK)
        return error;

    return CreateAuthEncryptedKeyBlob(key_description, key_material, *hw_enforced, *sw_enforced,
                                      blob);
}

keymaster_error_t TrustyKeymasterContext::UpgradeKeyBlob(const KeymasterKeyBlob& key_to_upgrade,
                                                         const AuthorizationSet& upgrade_params,
                                                         KeymasterKeyBlob* upgraded_key) const {
    UniquePtr<Key> key;
    keymaster_error_t error = ParseKeyBlob(key_to_upgrade, upgrade_params, &key);
    if (error != KM_ERROR_OK)
        return error;

    bool set_changed = false;

    if (boot_os_version_ == 0) {
        // We need to allow "upgrading" OS version to zero, to support upgrading from proper
        // numbered releases to unnumbered development and preview releases.

        int key_os_version_pos = key->sw_enforced().find(TAG_OS_VERSION);
        if (key_os_version_pos != -1) {
            uint32_t key_os_version = key->sw_enforced()[key_os_version_pos].integer;
            if (key_os_version != 0) {
                key->sw_enforced()[key_os_version_pos].integer = boot_os_version_;
                set_changed = true;
            }
        }
    }

    if (!UpgradeIntegerTag(TAG_OS_VERSION, boot_os_version_, &key->hw_enforced(), &set_changed) ||
        !UpgradeIntegerTag(TAG_OS_PATCHLEVEL, boot_os_patchlevel_, &key->hw_enforced(), &set_changed)) {
        // One of the version fields would have been a downgrade. Not allowed.
        return KM_ERROR_INVALID_ARGUMENT;
    }

    if (!set_changed) {
        // Don't need an upgrade.
        return KM_ERROR_OK;
    }

    return CreateAuthEncryptedKeyBlob(upgrade_params, key->key_material(), key->hw_enforced(), key->sw_enforced(),
                                      upgraded_key);
}

keymaster_error_t TrustyKeymasterContext::ParseKeyBlob(const KeymasterKeyBlob& blob,
                                                       const AuthorizationSet& additional_params,
                                                       UniquePtr<Key>* key) const {
    Buffer nonce, tag;
    KeymasterKeyBlob encrypted_key_material;
    AuthorizationSet hw_enforced;
    AuthorizationSet sw_enforced;
    KeymasterKeyBlob key_material;
    keymaster_error_t error;

    auto constructKey = [&, this] () mutable -> keymaster_error_t {
        // GetKeyFactory
        if (error != KM_ERROR_OK) return error;
        keymaster_algorithm_t algorithm;
        if (!hw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm) &&
            !sw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm)) {
            return KM_ERROR_INVALID_ARGUMENT;
        }
        auto factory = GetKeyFactory(algorithm);
        return factory->LoadKey(move(key_material), additional_params, move(hw_enforced),
                             move(sw_enforced), key);
    };

    error = DeserializeAuthEncryptedBlob(blob, &encrypted_key_material,
                                                           &hw_enforced, &sw_enforced, &nonce, &tag);
    if (error != KM_ERROR_OK)
        return error;

    if (nonce.available_read() != OCB_NONCE_LENGTH || tag.available_read() != OCB_TAG_LENGTH)
        return KM_ERROR_INVALID_KEY_BLOB;

    KeymasterKeyBlob master_key;
    error = DeriveMasterKey(&master_key);
    if (error != KM_ERROR_OK)
        return error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(additional_params, &hidden);
    if (error != KM_ERROR_OK)
        return error;

    error = OcbDecryptKey(hw_enforced, sw_enforced, hidden, master_key, encrypted_key_material,
                         nonce, tag, &key_material);
    if (error != KM_ERROR_OK)
        return error;

    return constructKey();
}

keymaster_error_t TrustyKeymasterContext::AddRngEntropy(const uint8_t* buf, size_t length) const {
    if (trusty_rng_add_entropy(buf, length) != 0)
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

bool TrustyKeymasterContext::SeedRngIfNeeded() const {
    if (ShouldReseedRng())
        const_cast<TrustyKeymasterContext*>(this)->ReseedRng();
    return rng_initialized_;
}

bool TrustyKeymasterContext::ShouldReseedRng() const {
    if (!rng_initialized_) {
        LOG_I("RNG not initalized, reseed", 0);
        return true;
    }

    if (++calls_since_reseed_ % kCallsBetweenRngReseeds == 0) {
        LOG_I("Periodic reseed", 0);
        return true;
    }
    return false;
}

bool TrustyKeymasterContext::ReseedRng() {
    UniquePtr<uint8_t[]> rand_seed(new uint8_t[kRngReseedSize]);
    memset(rand_seed.get(), 0, kRngReseedSize);
    if (trusty_rng_hw_rand(rand_seed.get(), kRngReseedSize) != 0) {
        LOG_E("Failed to get bytes from HW RNG", 0);
        return false;
    }
    LOG_I("Reseeding with %d bytes from HW RNG", kRngReseedSize);
    trusty_rng_add_entropy(rand_seed.get(), kRngReseedSize);

    rng_initialized_ = true;
    return true;
}

keymaster_error_t TrustyKeymasterContext::GenerateRandom(uint8_t* buf, size_t length) const {
    if (!SeedRngIfNeeded() || trusty_rng_secure_rand(buf, length) != 0)
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

// Gee wouldn't it be nice if the crypto service headers defined this.
enum DerivationParams {
    DERIVATION_DATA_PARAM = 0,
    OUTPUT_BUFFER_PARAM = 1,
};

keymaster_error_t TrustyKeymasterContext::DeriveMasterKey(KeymasterKeyBlob* master_key) const {
    LOG_D("Deriving master key", 0);

    long rc = hwkey_open();
    if (rc < 0) {
        return KM_ERROR_UNKNOWN_ERROR;
    }

    hwkey_session_t session = (hwkey_session_t)rc;

    if (!master_key->Reset(kAesKeySize)) {
        LOG_S("Could not allocate memory for master key buffer", 0);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    rc = hwkey_derive(session, &kdf_version, kMasterKeyDerivationData, master_key->writable_data(),
                      kAesKeySize);

    if (rc < 0) {
        LOG_S("Error deriving master key: %d", rc);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    hwkey_close(session);
    LOG_I("Key derivation complete", 0);
    return KM_ERROR_OK;
}

bool TrustyKeymasterContext::InitializeAuthTokenKey() {
    if (GenerateRandom(auth_token_key_, kAuthTokenKeySize) != KM_ERROR_OK)
        return false;
    auth_token_key_initialized_ = true;
    return auth_token_key_initialized_;
}

keymaster_error_t TrustyKeymasterContext::GetAuthTokenKey(keymaster_key_blob_t* key) const {
    if (!auth_token_key_initialized_ &&
        !const_cast<TrustyKeymasterContext*>(this)->InitializeAuthTokenKey())
        return KM_ERROR_UNKNOWN_ERROR;

    key->key_material = auth_token_key_;
    key->key_material_size = kAuthTokenKeySize;
    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterContext::SetSystemVersion(uint32_t os_version,
                                                           uint32_t os_patchlevel) {
#ifndef KEYMASTER_DEBUG
    if (!boot_params_set_ || boot_os_version_ != os_version ||
        boot_os_patchlevel_ != os_patchlevel) {
        return KM_ERROR_INVALID_ARGUMENT;
    }
#else
    Buffer fake_root_of_trust("000111222333444555666777888999000", 32);
    if (!boot_params_set_) {
        /* Sets bootloader parameters to what is expected on a 'good' device, will pass
         * attestation CTS tests. FOR DEBUGGING ONLY.
         */
        SetBootParams(os_version, os_patchlevel, fake_root_of_trust, KM_VERIFIED_BOOT_VERIFIED,
                      true);
    }
#endif

    return KM_ERROR_OK;
}

void TrustyKeymasterContext::GetSystemVersion(uint32_t* os_version, uint32_t* os_patchlevel) const {
    *os_version = boot_os_version_;
    *os_patchlevel = boot_os_patchlevel_;
}

keymaster_error_t
TrustyKeymasterContext::GetVerifiedBootParams(keymaster_blob_t* verified_boot_key,
                                              keymaster_verified_boot_t* verified_boot_state,
                                              bool* device_locked) const {
    verified_boot_key->data = verified_boot_key_.begin();
    verified_boot_key->data_length = verified_boot_key_.buffer_size();
    *verified_boot_state = verified_boot_state_;
    *device_locked = device_locked_;
    return KM_ERROR_OK;
}

const keymaster_key_blob_t* TrustyKeymasterContext::getAttestationKey(keymaster_algorithm_t algorithm,
                                                 keymaster_error_t* error) const{

    uint8_t* key = nullptr;
    uint32_t key_size = 0;
    int evp_key_type;
    UniquePtr<uint8_t[]> key_deleter;

    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        evp_key_type = EVP_PKEY_RSA;
        break;

    case KM_ALGORITHM_EC:
        evp_key_type = EVP_PKEY_EC;
        break;

    default:
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return nullptr;
    }

    *error = ReadKeyFromStorage(algorithm, &key, &key_size);
    if (*error == KM_ERROR_OK) {
        key_deleter.reset(key);
    } else {
        LOG_E("Failed to read attestation key from RPMB, falling back to test key", 0);
        *error = GetSoftwareAttestationKey(algorithm, &key, &key_size);
    }

    if (*error != KM_ERROR_OK)
        return nullptr;
#if 0
    const uint8_t* const_key = key;

    EVP_PKEY* pkey = d2i_PrivateKey(evp_key_type, nullptr, &const_key, key_size);
    if (!pkey)
        *error = TranslateLastOpenSslError();

    return pkey;
#endif
    static const keymaster_key_blob_t AttestKeyBlob = {
        (const uint8_t*)key, key_size
    };

    return &AttestKeyBlob;
}

keymaster_cert_chain_t* TrustyKeymasterContext::getAttestationChain(keymaster_algorithm_t algorithm,
                                                                 keymaster_error_t* error)  const{

    UniquePtr<keymaster_cert_chain_t, CertificateChainDelete> chain(new keymaster_cert_chain_t);
    if (!chain.get()) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return nullptr;
    }
    if (algorithm != KM_ALGORITHM_RSA && algorithm != KM_ALGORITHM_EC) {
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return nullptr;
    }
    memset(chain.get(), 0, sizeof(keymaster_cert_chain_t));

    *error = ReadCertChainFromStorage(algorithm, chain.get());
    if (*error != KM_ERROR_OK) {
        LOG_E("Failed to read attestation chain from RPMB, falling back to test chain", 0);
        *error = GetSoftwareAttestationChain(algorithm, chain.get());
    }

    if (*error != KM_ERROR_OK)
        return nullptr;
    return chain.release();
}
#if 0
keymaster_error_t TrustyKeymasterContext::GenerateAttestation(const Key& key,
        const AuthorizationSet& attest_params, CertChainPtr* cert_chain) const {

    keymaster_error_t error = KM_ERROR_OK;
    keymaster_algorithm_t key_algorithm;
    if (!key.authorizations().GetTagValue(TAG_ALGORITHM, &key_algorithm)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }

    if ((key_algorithm != KM_ALGORITHM_RSA && key_algorithm != KM_ALGORITHM_EC))
        return KM_ERROR_INCOMPATIBLE_ALGORITHM;

    // We have established that the given key has the correct algorithm, and because this is the
    // SoftKeymasterContext we can assume that the Key is an AsymmetricKey. So we can downcast.
    const AsymmetricKey& asymmetric_key = reinterpret_cast<const AsymmetricKey&>(key);

    auto attestation_chain = getAttestationChain(key_algorithm, &error);
    if (error != KM_ERROR_OK) return error;

    auto attestation_key = getAttestationKey(key_algorithm, &error);
    if (error != KM_ERROR_OK) return error;

    return generate_attestation(asymmetric_key, attest_params,
            *attestation_chain, *attestation_key, *this, cert_chain);
}
#endif
keymaster_error_t TrustyKeymasterContext::SetBootParams(
    uint32_t os_version, uint32_t os_patchlevel, const Buffer& verified_boot_key,
    keymaster_verified_boot_t verified_boot_state, bool device_locked) {
    if (boot_params_set_)
        return KM_ERROR_ROOT_OF_TRUST_ALREADY_SET;
    boot_params_set_ = true;
    boot_os_version_ = os_version;
    boot_os_patchlevel_ = os_patchlevel;

    // If no verified boot key hash is passed, then verified boot state is considered
    // unverified and unlocked.
    if (verified_boot_key.buffer_size()) {
        verified_boot_key_.Reinitialize(verified_boot_key);
        verified_boot_state_ = verified_boot_state;
        device_locked_ = device_locked;
    }
    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterContext::SetAttestKey(keymaster_algorithm_t algorithm,
                                                       const uint8_t* key, uint32_t key_size) {
    if (algorithm != KM_ALGORITHM_RSA && algorithm != KM_ALGORITHM_EC) {
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    if (key_size == 0) {
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    if (!key) {
        return KM_ERROR_INVALID_ARGUMENT;
    }
    bool exists;
    keymaster_error_t error = AttestationKeyExists(algorithm, &exists);
    if (error != KM_ERROR_OK) {
        return error;
    }
#ifndef KEYMASTER_DEBUG
    if (exists) {
        //TODO:  need to add a error code: KM_ERROR_ATTESTKEY_ALREADY_SET, and check it in the bootloader
        return KM_ERROR_UNKNOWN_ERROR;
    }
#endif
    return WriteKeyToStorage(algorithm, key, key_size);
}

keymaster_error_t TrustyKeymasterContext::AppendAttestCertChain(keymaster_algorithm_t algorithm,
                                                                const uint8_t* cert,
                                                                uint32_t cert_size) {
    if (algorithm != KM_ALGORITHM_RSA && algorithm != KM_ALGORITHM_EC) {
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    if (cert_size == 0) {
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    if (!cert) {
        return KM_ERROR_INVALID_ARGUMENT;
    }
    uint32_t cert_chain_length = 0;
    keymaster_error_t error = ReadCertChainLength(algorithm, &cert_chain_length);
    if (error != KM_ERROR_OK) {
        cert_chain_length = 0;
    }
    if (cert_chain_length >= kMaxCertChainLength) {
#ifndef KEYMASTER_DEBUG
        return KM_ERROR_UNKNOWN_ERROR;
#else
        // If debug flag is enabled, reset cert_chain_length when it hits max
        cert_chain_length = 0;
#endif
    }
    return WriteCertToStorage(algorithm, cert, cert_size, cert_chain_length);
}

keymaster_error_t TrustyKeymasterContext::ParseKeyboxToStorage(keymaster_algorithm_t algorithm,
                                        XMLElement* xml_root) {
    keymaster_error_t error = KM_ERROR_OK;

    /* provision the private key to secure storage */
    uint8_t* attest_key = NULL;
    uint32_t attest_keysize = 0;
    error =  get_prikey_from_keybox(xml_root, algorithm, &attest_key, &attest_keysize);
    if (error != KM_ERROR_OK || !attest_key ||!attest_keysize) {
       LOG_E("Error: [%d] failed to get the prikey(algo:%d) from keybox", error, algorithm);
       return KM_ERROR_UNKNOWN_ERROR;
    }
    error = SetAttestKey(algorithm, attest_key, attest_keysize);
    if (error != KM_ERROR_OK) {
        LOG_E("Error: (%d) failed to write pri_key into RPMB with algo(%d)", error, algorithm);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    /* provision the cert chain to secure storage */
    uint32_t cert_chain_len = 0;
    uint32_t index = 0;
    error = get_cert_chain_len_from_keybox(xml_root, algorithm, &cert_chain_len);
    if (error != KM_ERROR_OK) {
        LOG_E("Error: (%d) failed to get the cert_chain_len from keybox", error);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    /* save the certs one-by-one to securestorage */
    for (index = 0; index<cert_chain_len; index++) {
        uint8_t* cert;
        uint32_t cert_size = 0;
        error = get_cert_from_keybox(xml_root, algorithm, index, &cert, &cert_size);
        if (error != KM_ERROR_OK || !cert ||!cert_size) {
            LOG_E("Error: (%d) failed to get the cert(%d) from keybox with algo(%d)", error, index, algorithm);
            return KM_ERROR_UNKNOWN_ERROR;
        }

        error = AppendAttestCertChain(algorithm, cert, cert_size);
        if (error != KM_ERROR_OK) {
            LOG_E("Error: (%d) failed to append the cert(%d) into RPMB with algo(%d)", error, index, algorithm);
            return KM_ERROR_UNKNOWN_ERROR;
        }
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterContext:: ProvisionAttestKeybox(const uint8_t* keybox,
                                        uint32_t keybox_size) {
    keymaster_error_t error = KM_ERROR_OK;

    if (keybox == NULL) {
        error = RetrieveKeybox((uint8_t**)&keybox, &keybox_size);
        if(error != KM_ERROR_OK ||!keybox || !keybox_size) {
            LOG_E("failed(%d) to RetrieveKeybox", error);
            return KM_ERROR_UNKNOWN_ERROR;
        }
    }

    XMLElement* xml_root = NULL;
    error = keybox_xml_initialize(keybox, &xml_root);
    if (error != KM_ERROR_OK || !xml_root) {
        LOG_E("Error: (%d) failed to initialize the keybox", error);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    error = ParseKeyboxToStorage(KM_ALGORITHM_RSA, xml_root);
    if(error != KM_ERROR_OK) {
        LOG_E("ParseKeyboxToStorage failed(%d) wih KM_ALGORITHM_RSA", error);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    error = ParseKeyboxToStorage(KM_ALGORITHM_EC, xml_root);
    if(error != KM_ERROR_OK) {
        LOG_E("ParseKeyboxToStorage failed(%d) with KM_ALGORITHM_EC", error);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    return KM_ERROR_OK;
}

}  // namespace keymaster


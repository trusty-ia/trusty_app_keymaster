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

#include "trusty_keymaster_enforcement.h"

#include <openssl/hmac.h>

extern "C" {
#include <trusty_std.h>
}

#include <hardware/hw_auth_token.h>
#include <keymaster/android_keymaster_utils.h>
//#include <initializer_list>
//#include <limits>

#include "trusty_keymaster_context.h"
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <keymaster/km_openssl/ckdf.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>

namespace keymaster {

bool TrustyKeymasterEnforcement::auth_token_timed_out(const hw_auth_token_t& token,
                                                      uint32_t timeout_seconds) const {
    uint64_t token_timestamp_millis = ntoh(token.timestamp);
    uint64_t timeout_millis = static_cast<uint64_t>(timeout_seconds) * 1000;
    uint64_t millis_since_boot = milliseconds_since_boot();
    return (millis_since_boot >= token_timestamp_millis &&
            (millis_since_boot - token_timestamp_millis) > timeout_millis);
}

uint64_t TrustyKeymasterEnforcement::get_current_time_ms() const {
    return milliseconds_since_boot();
}

inline size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

bool TrustyKeymasterEnforcement::ValidateTokenSignature(const hw_auth_token_t& token) const {
    keymaster_key_blob_t auth_token_key;
    keymaster_error_t error = context_->GetAuthTokenKey(&auth_token_key);
    if (error != KM_ERROR_OK)
        return false;

    // Signature covers entire token except HMAC field.
    const uint8_t* hash_data = reinterpret_cast<const uint8_t*>(&token);
    size_t hash_data_length = reinterpret_cast<const uint8_t*>(&token.hmac) - hash_data;

    uint8_t computed_hash[EVP_MAX_MD_SIZE];
    unsigned int computed_hash_length;
    if (!HMAC(EVP_sha256(), auth_token_key.key_material, auth_token_key.key_material_size,
              hash_data, hash_data_length, computed_hash, &computed_hash_length)) {
        LOG_S("Error %d computing token signature", TranslateLastOpenSslError());
        return false;
    }

    return 0 == memcmp_s(computed_hash, token.hmac, min(sizeof(token.hmac), computed_hash_length));
}

uint64_t TrustyKeymasterEnforcement::milliseconds_since_boot() const {
    status_t rv;
    int64_t secure_time_ns = 0;
    rv = gettime(0, 0, &secure_time_ns);
    if (rv || secure_time_ns < 0) {
        LOG_S("Error getting time. Error: %d, time: %lld", rv, secure_time_ns);
        secure_time_ns = 0xFFFFFFFFFFFFFFFFL; // UINT64_MAX isn't defined (b/22120972)
    }
    return static_cast<uint64_t>(secure_time_ns) / 1000 / 1000;
}


class EvpMdCtx {
  public:
    EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }
    ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

    EVP_MD_CTX* get() { return &ctx_; }

  private:
    EVP_MD_CTX ctx_;
};

template <typename BlobType> struct TKeymasterBlob;
typedef TKeymasterBlob<keymaster_key_blob_t> KeymasterKeyBlob;
typedef TKeymasterBlob<keymaster_blob_t> KeymasterBlob;

bool TrustyKeymasterEnforcement::CreateKeyId(const keymaster_key_blob_t& key_blob,
                                           km_id_t* keyid) const {
    EvpMdCtx ctx;

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr /* ENGINE */) &&
        EVP_DigestUpdate(ctx.get(), key_blob.key_material, key_blob.key_material_size) &&
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
        assert(hash_len >= sizeof(*keyid));
        memcpy(keyid, hash, sizeof(*keyid));
        return true;
    }

    return false;
}


keymaster_error_t
TrustyKeymasterEnforcement::GetHmacSharingParameters(HmacSharingParameters* params) {
    if (!have_saved_params_) {
        saved_params_.seed = {};
        RAND_bytes(saved_params_.nonce, 32);
        have_saved_params_ = true;
    }
    params->seed = saved_params_.seed;
    memcpy(params->nonce, saved_params_.nonce, sizeof(params->nonce));
    return KM_ERROR_OK;
}

#if 0 //need to implement the initializer_list
namespace {

DEFINE_OPENSSL_OBJECT_POINTER(HMAC_CTX);

keymaster_error_t hmacSha256(const keymaster_key_blob_t& key,
                             std::initializer_list<const keymaster_blob_t> data_chunks,
                             KeymasterBlob* output) {
    if (!output) return KM_ERROR_UNEXPECTED_NULL_POINTER;

    unsigned digest_len = SHA256_DIGEST_LENGTH;
    if (!output->Reset(digest_len)) return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    HMAC_CTX_Ptr ctx(HMAC_CTX_new());
    if (!HMAC_Init_ex(ctx.get(), key.key_material, key.key_material_size, EVP_sha256(),
                      nullptr /* engine*/)) {
        return TranslateLastOpenSslError();
    }

    for (auto& chunk : data_chunks) {
        if (!HMAC_Update(ctx.get(), chunk.data, chunk.data_length)) {
            return TranslateLastOpenSslError();
        }
    }

    if (!HMAC_Final(ctx.get(), output->writable_data(), &digest_len)) {
        return TranslateLastOpenSslError();
    }

    if (digest_len != output->data_length) return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
}

// Helpers for converting types to keymaster_blob_t, for easy feeding of hmacSha256.
template <typename T, typename = std::enable_if<std::is_integral<T>::value>>
inline keymaster_blob_t toBlob(const T& t) {
    return {reinterpret_cast<const uint8_t*>(&t), sizeof(t)};
}
inline keymaster_blob_t toBlob(const char* str) {
    return {reinterpret_cast<const uint8_t*>(str), strlen(str)};
}

// Perhaps these shoud be in utils, but the impact of that needs to be considered carefully.  For
// now, just define it here.
inline bool operator==(const keymaster_blob_t& a, const keymaster_blob_t& b) {
    if (!a.data_length && !b.data_length) return true;
    if (!(a.data && b.data)) return a.data == b.data;
    return (a.data_length == b.data_length && !memcmp(a.data, b.data, a.data_length));
}

bool operator==(const HmacSharingParameters& a, const HmacSharingParameters& b) {
    return a.seed == b.seed && !memcmp(a.nonce, b.nonce, sizeof(a.nonce));
}

}  // namespace

keymaster_error_t
TrustyKeymasterEnforcement::ComputeSharedHmac(const HmacSharingParametersArray& params_array,
                                            KeymasterBlob* sharingCheck) {
    size_t num_chunks = params_array.num_params * 2;
    UniquePtr<keymaster_blob_t[]> context_chunks(new (std::nothrow) keymaster_blob_t[num_chunks]);
    if (!context_chunks.get()) return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    bool found_mine = false;
    auto context_chunks_pos = context_chunks.get();
    for (auto& params : array_range(params_array.params_array, params_array.num_params)) {
        *context_chunks_pos++ = params.seed;
        *context_chunks_pos++ = {params.nonce, sizeof(params.nonce)};
        found_mine = found_mine || params == saved_params_;
    }
    assert(context_chunks_pos - num_chunks == context_chunks.get());

    if (!found_mine) return KM_ERROR_INVALID_ARGUMENT;

    if (!hmac_key_.Reset(SHA256_DIGEST_LENGTH)) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    keymaster_error_t error = ckdf(
        KeymasterKeyBlob(kFakeKeyAgreementKey, sizeof(kFakeKeyAgreementKey)),
        KeymasterBlob(reinterpret_cast<const uint8_t*>(kSharedHmacLabel), strlen(kSharedHmacLabel)),
        context_chunks.get(), num_chunks,  //
        &hmac_key_);
    if (error != KM_ERROR_OK) return error;

    keymaster_blob_t data = {reinterpret_cast<const uint8_t*>(kMacVerificationString),
                             strlen(kMacVerificationString)};
    return hmacSha256(hmac_key_, {data}, sharingCheck);
}

VerifyAuthorizationResponse
TrustyKeymasterEnforcement::VerifyAuthorization(const VerifyAuthorizationRequest& request) {
    // The only thing this implementation provides is timestamp and security level.  Note that this
    // is an acceptable implementation strategy for production use as well.  Additional verification
    // need only be provided by an implementation if it is interoperating with another
    // implementation that requires more.
    VerifyAuthorizationResponse response;
    response.token.challenge = request.challenge;
    response.token.timestamp = get_current_time_ms();
    response.token.security_level = SecurityLevel();
    response.error = hmacSha256(hmac_key_,
                                {
                                    toBlob(kAuthVerificationLabel),
                                    toBlob(response.token.challenge),
                                    toBlob(response.token.timestamp),
                                    toBlob(response.token.security_level),
                                    {},  // parametersVerified
                                },
                                &response.token.mac);

    return response;
}
#endif
}  // namespace keymaster

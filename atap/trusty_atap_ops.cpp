/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "trusty_atap_ops.h"

#include "secure_storage.h"
#include "trusty_logger.h"

namespace {

using keymaster::AttestationKeySlot;

AttestationKeySlot MapKeyTypeToSlot(AtapKeyType atap_key_type) {
    switch (atap_key_type) {
    case ATAP_KEY_TYPE_RSA:
        return AttestationKeySlot::kRsa;
    case ATAP_KEY_TYPE_ECDSA:
        return AttestationKeySlot::kEcdsa;
    case ATAP_KEY_TYPE_edDSA:
        return AttestationKeySlot::kEddsa;
    case ATAP_KEY_TYPE_EPID:
        return AttestationKeySlot::kEpid;
    case ATAP_KEY_TYPE_SPECIAL:
        return AttestationKeySlot::kClaimable0;
    default:
        return AttestationKeySlot::kInvalid;
    }
    return AttestationKeySlot::kInvalid;
}

}  // namespace

namespace keymaster {

TrustyAtapOps::TrustyAtapOps() {}
TrustyAtapOps::~TrustyAtapOps() {}

void TrustyAtapOps::set_product_id(uint8_t product_id[ATAP_PRODUCT_ID_LEN]) {
    memcpy(product_id_, product_id, ATAP_PRODUCT_ID_LEN);
}

const char* TrustyAtapOps::GetLastUuid() {
    return uuid_;
}

AtapResult TrustyAtapOps::read_product_id(uint8_t product_id[ATAP_PRODUCT_ID_LEN]) {
    memcpy(product_id, product_id_, ATAP_PRODUCT_ID_LEN);
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::get_auth_key_type(AtapKeyType* key_type) {
    *key_type = ATAP_KEY_TYPE_NONE;
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::read_auth_key_cert_chain(AtapCertChain* cert_chain) {
    return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
}

AtapResult TrustyAtapOps::write_attestation_key(AtapKeyType key_type, const AtapBlob* key,
                                                const AtapCertChain* cert_chain) {
    AttestationKeySlot slot = MapKeyTypeToSlot(key_type);
    if (slot == AttestationKeySlot::kInvalid) {
        LOG_E("Invalid key type: %d", key_type);
        return ATAP_RESULT_ERROR_INVALID_INPUT;
    }
    keymaster_error_t result = WriteKeyToStorage(slot, key->data, key->data_length);
    if (result != KM_ERROR_OK) {
        LOG_E("Failed to write key to slot %d (err = %d)", slot, result);
        return ATAP_RESULT_ERROR_STORAGE;
    }
    for (uint32_t i = 0; i < cert_chain->entry_count; ++i) {
        result = WriteCertToStorage(slot, cert_chain->entries[i].data,
                                    cert_chain->entries[i].data_length, i);
        if (result != KM_ERROR_OK) {
            LOG_E("Failed to write cert %d to slot %d (err = %d)", i, slot, result);
            return ATAP_RESULT_ERROR_STORAGE;
        }
    }
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::read_attestation_public_key(AtapKeyType key_type,
                                                      uint8_t pubkey[ATAP_KEY_LEN_MAX],
                                                      uint32_t* pubkey_len) {
    return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
}

AtapResult TrustyAtapOps::read_soc_global_key(uint8_t global_key[ATAP_AES_128_KEY_LEN]) {
    return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
}

AtapResult TrustyAtapOps::write_hex_uuid(const uint8_t uuid[ATAP_HEX_UUID_LEN]) {
    memcpy(uuid_, uuid, ATAP_HEX_UUID_LEN);
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::auth_key_sign(const uint8_t* nonce, uint32_t nonce_len,
                                        uint8_t sig[ATAP_SIGNATURE_LEN_MAX], uint32_t* sig_len) {
    return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
}

}  // namespace keymaster

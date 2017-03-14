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

#include "secure_storage.h"

extern "C" {
#include <err.h>
#include <errno.h>
#include <stdio.h>

#include <lib/storage/storage.h>
}

#include "trusty_keymaster_context.h"
#include "trusty_logger.h"
#include <UniquePtr.h>

namespace keymaster {

namespace {

// Name of the attestation key file is kAttestKeyPrefix.%algorithm, where
// algorithm is either "ec" or "rsa".
const char* kAttestKeyPrefix = "AttestKey.";

// Name of the attestation certificate file is kAttestCertPrefix.%algorithm.%index,
// where index is the index within the certificate chain.
const char* kAttestCertPrefix = "AttestCert.";

// Maximum file name size.
static const int kStorageIdLengthMax = 64;

// RAII wrapper for storage_session_t
class StorageSession {
  public:
    StorageSession() {
        error_ = storage_open_session(&handle_, STORAGE_CLIENT_TP_PORT);
        if (error_ < 0) {
            LOG_E("Error: [%d] opening storage session", error_);
        }
    }
    ~StorageSession() {
        if (error_ < 0) {
            return;
        }
        storage_close_session(handle_);
        error_ = -EINVAL;
    }

    int error() const { return error_; }
    storage_session_t handle() { return handle_; }

  private:
    storage_session_t handle_ = 0;
    int error_ = -EINVAL;
};

// RAII wrapper for file_handle_t
class FileHandle {
  public:
    FileHandle(const char* filename) {
        if (session_.error() == 0) {
            error_ = storage_open_file(session_.handle(), &handle_, const_cast<char*>(filename),
                                       STORAGE_FILE_OPEN_CREATE, 0);
        } else {
            error_ = session_.error();
        }
    }
    ~FileHandle() {
        if (error_ != 0) {
            return;
        }
        storage_close_file(handle_);
        error_ = -EINVAL;
    }
    int error() const { return error_; }
    file_handle_t handle() { return handle_; }

  private:
    StorageSession session_;
    int error_ = -EINVAL;
    file_handle_t handle_ = 0;
};

bool SecureStorageWrite(const char* filename, const uint8_t* data, uint32_t size) {
    FileHandle file(filename);
    if (file.error() < 0) {
        return false;
    }
    int rc = storage_write(file.handle(), 0, data, size, STORAGE_OP_COMPLETE);
    if (rc < 0) {
        LOG_E("Error: [%d] writing storage object '%s'", rc, filename);
        return false;
    }
    if (static_cast<uint32_t>(rc) < size) {
        LOG_E("Error: invalid object size [%d] from '%s'", rc, filename);
        return false;
    }
    return true;
}

bool SecureStorageRead(const char* filename, uint8_t* data, uint32_t size) {
    FileHandle file(filename);
    if (file.error() < 0) {
        return false;
    }
    int rc = storage_read(file.handle(), 0, data, size);
    if (rc < 0) {
        LOG_E("Error: [%d] reading storage object '%s'", rc, filename);
        return false;
    }
    if (static_cast<uint32_t>(rc) < size) {
        LOG_E("Error: invalid object size [%d] from '%s'", rc, filename);
        return false;
    }
    return true;
}

bool SecureStorageGetFileSize(const char* filename, uint64_t* size) {
    FileHandle file(filename);
    if (file.error() < 0) {
        return false;
    }
    int rc = storage_get_file_size(file.handle(), size);
    if (rc < 0) {
        LOG_E("Error: [%d] reading storage object '%s'", rc, filename);
        return false;
    }
    return true;
}

bool SecureStorageDeleteFile(const char* filename) {
    StorageSession session;
    if (session.error() < 0) {
        return false;
    }
    int rc = storage_delete_file(session.handle(), filename, STORAGE_OP_COMPLETE);
    if (rc < 0 && rc != ERR_NOT_FOUND) {
        LOG_E("Error: [%d] deleting storage object '%s'", rc, filename);
        return false;
    }
    return true;
}

const char* GetAlgorithmStr(keymaster_algorithm_t algorithm) {
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return "rsa";
    case KM_ALGORITHM_EC:
        return "ec";
    default:
        return "";
    }
}

}  //  unnamed namespace

keymaster_error_t WriteKeyToStorage(keymaster_algorithm_t algorithm, const uint8_t* key,
                                    uint32_t key_size) {
    UniquePtr<char[]> key_file(new char[kStorageIdLengthMax]);

    snprintf(key_file.get(), kStorageIdLengthMax, "%s.%s", kAttestKeyPrefix,
             GetAlgorithmStr(algorithm));
    if (!SecureStorageDeleteFile(key_file.get()) ||
        !SecureStorageWrite(key_file.get(), key, key_size)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t ReadKeyFromStorage(keymaster_algorithm_t algorithm, uint8_t** key,
                                     uint32_t* key_size) {
    UniquePtr<char[]> key_file(new char[kStorageIdLengthMax]);

    snprintf(key_file.get(), kStorageIdLengthMax, "%s.%s", kAttestKeyPrefix,
             GetAlgorithmStr(algorithm));

    uint64_t key_size_64;
    if (!SecureStorageGetFileSize(key_file.get(), &key_size_64) || key_size_64 == 0) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *key_size = static_cast<uint32_t>(key_size_64);
    *key = new uint8_t[*key_size];
    if (*key == nullptr) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    if (!SecureStorageRead(key_file.get(), *key, *key_size)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t WriteCertToStorage(keymaster_algorithm_t algorithm, const uint8_t* cert,
                                     uint32_t cert_size, uint32_t index) {
    UniquePtr<char[]> cert_file(new char[kStorageIdLengthMax]);
    UniquePtr<char[]> cert_chain_length_file(new char[kStorageIdLengthMax]);
    uint32_t cert_chain_length = index + 1;

    snprintf(cert_file.get(), kStorageIdLengthMax, "%s.%s.%d", kAttestCertPrefix,
             GetAlgorithmStr(algorithm), index);
    snprintf(cert_chain_length_file.get(), kStorageIdLengthMax, "%s.%s.length", kAttestKeyPrefix,
             GetAlgorithmStr(algorithm));

    if (!SecureStorageDeleteFile(cert_file.get()) ||
        !SecureStorageWrite(cert_file.get(), cert, cert_size) ||
        !SecureStorageWrite(cert_chain_length_file.get(),
                            reinterpret_cast<const uint8_t*>(&cert_chain_length),
                            sizeof(cert_chain_length))) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t ReadCertChainFromStorage(keymaster_algorithm_t algorithm,
                                           keymaster_cert_chain_t* cert_chain) {
    UniquePtr<char[]> cert_file(new char[kStorageIdLengthMax]);
    uint32_t cert_chain_length;
    uint64_t cert_size;

    if (ReadCertChainLength(algorithm, &cert_chain_length) != KM_ERROR_OK ||
        cert_chain_length == 0) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    cert_chain->entry_count = cert_chain_length;
    cert_chain->entries = new keymaster_blob_t[cert_chain_length];
    if (!cert_chain->entries) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    memset(cert_chain->entries, 0, sizeof(cert_chain->entries[0]) * cert_chain_length);

    // Read |cert_chain_length| certs from storage
    for (size_t i = 0; i < cert_chain_length; ++i) {
        snprintf(cert_file.get(), kStorageIdLengthMax, "%s.%s.%d", kAttestCertPrefix,
                 GetAlgorithmStr(algorithm), i);
        if (!SecureStorageGetFileSize(cert_file.get(), &cert_size) || cert_size == 0) {
            return KM_ERROR_UNKNOWN_ERROR;
        }
        UniquePtr<uint8_t[]> cert_data(new uint8_t[cert_size]);
        if (!cert_data.get()) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        if (!SecureStorageRead(cert_file.get(), cert_data.get(), cert_size)) {
            return KM_ERROR_UNKNOWN_ERROR;
        }
        cert_chain->entries[i].data_length = static_cast<uint32_t>(cert_size);
        cert_chain->entries[i].data = cert_data.release();
    }
    return KM_ERROR_OK;
}

keymaster_error_t AttestationKeyExists(keymaster_algorithm_t algorithm, bool* exists) {
    UniquePtr<char[]> key_file(new char[kStorageIdLengthMax]);

    snprintf(key_file.get(), kStorageIdLengthMax, "%s.%s", kAttestKeyPrefix,
             GetAlgorithmStr(algorithm));
    uint64_t size;
    if (!SecureStorageGetFileSize(key_file.get(), &size)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *exists = size > 0;
    return KM_ERROR_OK;
}

keymaster_error_t ReadCertChainLength(keymaster_algorithm_t algorithm,
                                      uint32_t* cert_chain_length) {
    UniquePtr<char[]> cert_chain_length_file(new char[kStorageIdLengthMax]);
    snprintf(cert_chain_length_file.get(), kStorageIdLengthMax, "%s.%s.length", kAttestKeyPrefix,
             GetAlgorithmStr(algorithm));
    if (!SecureStorageRead(cert_chain_length_file.get(),
                           reinterpret_cast<uint8_t*>(cert_chain_length), sizeof(uint32_t)) ||
        *cert_chain_length > kMaxCertChainLength) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

}  // namespace keymaster

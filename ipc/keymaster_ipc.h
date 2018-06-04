/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2016 Intel Corporation
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

#define KEYMASTER_PORT "com.android.trusty.keymaster"
#define KEYMASTER_MAX_BUFFER_LENGTH 4096

// Commands
enum keymaster_command {
    KEYMASTER_RESP_BIT               = 1,
    KEYMASTER_STOP_BIT               = 2,
    KEYMASTER_REQ_SHIFT              = 2,

    KM_GENERATE_KEY                 = (0 << KEYMASTER_REQ_SHIFT),
    KM_BEGIN_OPERATION              = (1 << KEYMASTER_REQ_SHIFT),
    KM_UPDATE_OPERATION             = (2 << KEYMASTER_REQ_SHIFT),
    KM_FINISH_OPERATION             = (3 << KEYMASTER_REQ_SHIFT),
    KM_ABORT_OPERATION              = (4 << KEYMASTER_REQ_SHIFT),
    KM_IMPORT_KEY                   = (5 << KEYMASTER_REQ_SHIFT),
    KM_EXPORT_KEY                   = (6 << KEYMASTER_REQ_SHIFT),
    KM_GET_VERSION                  = (7 << KEYMASTER_REQ_SHIFT),
    KM_ADD_RNG_ENTROPY              = (8 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_ALGORITHMS     = (9 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_BLOCK_MODES    = (10 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_PADDING_MODES  = (11 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_DIGESTS        = (12 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_IMPORT_FORMATS = (13 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_EXPORT_FORMATS = (14 << KEYMASTER_REQ_SHIFT),
    KM_GET_KEY_CHARACTERISTICS      = (15 << KEYMASTER_REQ_SHIFT),
    KM_ATTEST_KEY                    = (16 << KEYMASTER_REQ_SHIFT),
    KM_UPGRADE_KEY                   = (17 << KEYMASTER_REQ_SHIFT),
    KM_CONFIGURE                     = (18 << KEYMASTER_REQ_SHIFT),
    KM_DELETE_KEY                    = (19 << KEYMASTER_REQ_SHIFT),
    KM_DELETE_ALL_KEYS               = (20 << KEYMASTER_REQ_SHIFT),

    KM_SET_BOOT_PARAMS               = (0x1000 << KEYMASTER_REQ_SHIFT),
    KM_SET_ATTESTATION_KEY           = (0x2000 << KEYMASTER_REQ_SHIFT),
    KM_APPEND_ATTESTATION_CERT_CHAIN = (0x3000 << KEYMASTER_REQ_SHIFT),
    KM_PROVISION_KEYBOX              = (0x8000 << KEYMASTER_REQ_SHIFT),
};

#ifdef __ANDROID__

/**
 * keymaster_message - Serial header for communicating with KM server
 * @cmd: the command, one of keymaster_command.
 * @payload: start of the serialized command specific payload
 */
struct keymaster_message {
    uint32_t cmd;
    uint8_t payload[0];
};

#endif

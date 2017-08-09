/*******************************************************************************
 * Copyright (c) 2017 Intel Corporation
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
 *******************************************************************************/

#ifndef TRUSTY_APP_KEYMASTER_ATTEST_KEYBOX_H_
#define TRUSTY_APP_KEYMASTER_ATTEST_KEYBOX_H_
#include "tinyxml2.h"
using namespace tinyxml2;

namespace keymaster {

keymaster_error_t RetrieveKeybox(uint8_t** keybox, uint32_t* keybox_size);

keymaster_error_t keybox_xml_initialize(const uint8_t* keybox, XMLElement** xml_root);

keymaster_error_t get_prikey_from_keybox(XMLElement* xml_root,
                keymaster_algorithm_t algorithm,
                uint8_t** key,
                uint32_t* key_size);

keymaster_error_t get_cert_chain_len_from_keybox(XMLElement* xml_root,
                keymaster_algorithm_t algorithm,
                uint32_t* cert_chain_len);

keymaster_error_t get_cert_from_keybox(XMLElement* xml_root,
                keymaster_algorithm_t algorithm,
                uint32_t cert_index,
                uint8_t** cert,
                uint32_t* cert_size);

}  // namespace keymaster

#endif  // TRUSTY_APP_KEYMASTER_ATTEST_KEYBOX_H_



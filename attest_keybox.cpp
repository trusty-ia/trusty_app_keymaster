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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_std.h>
#include <openssl/base64.h>
#include "trusty_keymaster.h"
#include "attest_keybox.h"
#include "LzmaDec.h"

#define XML_KEY_ALGORITHM_EC_STRING     "ecdsa"
#define XML_KEY_ALGORITHM_RSA_STRING    "rsa"

namespace keymaster {

#define LZMA_HEADER_SIZE    (LZMA_PROPS_SIZE + 8)
#define UNUSED_VAR(x) (void)x;
static void *AllocForLzma(void *p, size_t size) { UNUSED_VAR(p); return malloc(size); }
static void FreeForLzma(void *p, void *address) { UNUSED_VAR(p); free(address); }
static ISzAlloc g_AllocForLzma = { &AllocForLzma, &FreeForLzma };

static XMLElement *tinyxml2_WalkNextElement(XMLElement *root, XMLElement *element)
{
    XMLElement *next_element;
    XMLNode *next_node;

    if ((root == NULL) || (element == NULL))
        return NULL;

    next_element = element->FirstChildElement();
    if (next_element)
        return next_element;

    next_element = element->NextSiblingElement();
    if (next_element)
        return next_element;

    next_node = dynamic_cast<XMLNode*>(element)->Parent();
    while (1) {
        if ((next_node == NULL) || (next_node->ToElement() == root))
            return NULL;

        next_element = next_node->ToElement()->NextSiblingElement();
        if (next_element)
            return next_element;
        next_node = next_node->Parent();
    }
}

static XMLElement *tinyxml2_FindElement(XMLElement *root, XMLElement *element, const char *name, const char *attr, const char *value)
{
    XMLElement *get_element;

    if ((root == NULL) || (name == NULL))
        return NULL;

    if (root && (element == NULL)) {
        if (strcmp(root->Name(), name) == 0) {
            if (attr && value) {
                if (root->Attribute(attr, value))
                    return root;
            }
            else
                return root;
        }

        for (element = root->FirstChildElement(); element; element = element->NextSiblingElement()) {
            get_element = tinyxml2_FindElement(element, NULL, name, attr, value);
            if (get_element)
                return get_element;
        }

        return NULL;
    }

    if (root && element) {
        while (1) {
            element = tinyxml2_WalkNextElement(root, element);
            if (element == NULL)
                return NULL;
            if (strcmp(element->Name(), name) == 0) {
                if (attr && value) {
                    if (element->Attribute(attr, value))
                        return element;
                }
                else
                    return element;
            }
        }
    }
    return NULL;
}

static uint8_t *decompress_attkb(uint8_t* keybox, size_t compressed_size) {
    size_t outlen = 0, inlen = compressed_size - LZMA_HEADER_SIZE;
    uint8_t *s = NULL, *decompressed_attkb = NULL;
    ELzmaStatus status;
    SRes res;

    s = keybox;
    outlen = s[LZMA_PROPS_SIZE] |
            (s[LZMA_PROPS_SIZE + 1] << 8) |
            (s[LZMA_PROPS_SIZE + 2] << 16) |
            (s[LZMA_PROPS_SIZE + 3] << 24);

    decompressed_attkb = (uint8_t *)malloc(outlen);
    if(decompressed_attkb == NULL)
        return NULL;

    res = LzmaDecode(decompressed_attkb, &outlen, s + LZMA_HEADER_SIZE, &inlen,
               s, LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status, &g_AllocForLzma);
    if(res) {
        LOG_E("attkb decompression failed! res (%d), status(%d)", res, status);
        free(decompressed_attkb);
        return NULL;
    }

    return decompressed_attkb;
}


/* the keybox will be retrieved from the CSE side */
keymaster_error_t RetrieveKeybox(uint8_t** keybox, uint32_t* keybox_size) {
    int rc = -1;
    keymaster_error_t ret = KM_ERROR_OK;
    trusty_device_info_t *dev_info = NULL;
    uint32_t buffer_size = sizeof(trusty_device_info_t) + MAX_ATTKB_SIZE;
    attkb_header_t *attkb_hdr = NULL;
    size_t attkb_hdr_size = 0;

    if((keybox_size == NULL) || (keybox == NULL))
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    dev_info = (trusty_device_info_t *)malloc(buffer_size);
    if(!dev_info)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memset(dev_info, 0, buffer_size);
    rc = get_device_info(dev_info);
    if(rc != 0) {
        LOG_E("RetrieveKeybox failed!", 0);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto clear_sensitive_data;
    }

    *keybox_size = dev_info->attkb_size;
    *keybox = (uint8_t *)malloc(dev_info->attkb_size);
    if(*keybox == NULL) {
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto clear_sensitive_data;
    }
    memcpy_s(*keybox, *keybox_size, dev_info->attkb, *keybox_size);

    attkb_hdr = (attkb_header_t *)(*keybox);
    /* indicates file format, 0 = plain, 1 = LZMA */
    if((attkb_hdr->version == 1) && (attkb_hdr->format == 1)) {
        uint8_t* decompressed_attkb = NULL;
        attkb_hdr_size = sizeof(attkb_header_t);
        decompressed_attkb = decompress_attkb(*keybox + attkb_hdr_size, attkb_hdr->size);
        free(*keybox);
        *keybox = decompressed_attkb;
        if(decompressed_attkb == NULL) {
            ret = KM_ERROR_UNKNOWN_ERROR;
            goto clear_sensitive_data;
        }
    }

clear_sensitive_data:
    memset(dev_info, 0, buffer_size);
    free(dev_info);
    return ret;
}

keymaster_error_t keybox_xml_initialize(const uint8_t* keybox, XMLElement** xml_root) {
    if ((keybox == NULL) || (xml_root == NULL))
        return KM_ERROR_INVALID_ARGUMENT;

    XMLDocument *doc = new XMLDocument;
    if (doc == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    doc->LoadXmlData((char *)keybox);

    if (doc->Error()) {
        LOG_E("Parsing XML data failed!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *xml_root = doc->RootElement();
    if (*xml_root == NULL) {
        LOG_E("Parsing XML data failed!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    return KM_ERROR_OK;
}

keymaster_error_t get_prikey_from_keybox(XMLElement* xml_root,
                keymaster_algorithm_t algorithm,
                uint8_t** key,
                uint32_t* key_size) {
    XMLElement *subroot, *element;
    char *base64data;
    uint8_t *decodedata;
    char *p, *pstart, *pend;
    char *text;
    uint32_t count;

    if ((key == NULL) || (key_size == NULL))
        return KM_ERROR_INVALID_ARGUMENT;

    if (xml_root == NULL)
        return KM_ERROR_INVALID_ARGUMENT;

    if (algorithm == KM_ALGORITHM_RSA) {
        subroot = tinyxml2_FindElement(xml_root, NULL, "Key", "algorithm", XML_KEY_ALGORITHM_RSA_STRING);
        element = tinyxml2_FindElement(subroot, NULL, "PrivateKey", NULL, NULL);
        if (element == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        text = (char *)element->GetText();
        if (text == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        count = strlen(text);
        if ((p = strstr(text, "-----BEGIN RSA PRIVATE KEY-----")) == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        pstart = p + strlen("-----BEGIN RSA PRIVATE KEY-----");
        if ((pend = strstr(text, "-----END RSA PRIVATE KEY-----")) == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        base64data = new char[count];
        if (base64data == NULL)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        count = 0;
        for (p = pstart; p < pend; p++) {
            if (!isspace(*p))
                base64data[count++] = *p;
        }
        base64data[count] = 0x00;
    } else if (algorithm == KM_ALGORITHM_EC) {
        subroot = tinyxml2_FindElement(xml_root, NULL, "Key", "algorithm", XML_KEY_ALGORITHM_EC_STRING);
        element = tinyxml2_FindElement(subroot, NULL, "PrivateKey", NULL, NULL);
        if (element == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        text = (char *)element->GetText();
        if (text == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        count = strlen(text);
        if ((p = strstr(text, "-----BEGIN EC PRIVATE KEY-----")) == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        pstart = p + strlen("-----BEGIN EC PRIVATE KEY-----");
        if ((pend = strstr(text, "-----END EC PRIVATE KEY-----")) == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        base64data = new char[count];
        if (base64data == NULL)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        count = 0;
        for (p = pstart; p < pend; p++) {
            if (!isspace(*p))
                base64data[count++] = *p;
        }
        base64data[count] = 0x00;
    } else {
        LOG_E("No matched key in keybox!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    decodedata = new uint8_t[count];
    if (decodedata == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (!EVP_DecodeBase64(decodedata, (size_t *)&count, count, (const uint8_t *)base64data, strlen(base64data))) {
        LOG_E("Failed to do base64 decode!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *key = decodedata;
    *key_size = count;
    delete [] base64data;

    return KM_ERROR_OK;
}

keymaster_error_t get_cert_chain_len_from_keybox(XMLElement* xml_root,
                keymaster_algorithm_t algorithm,
                uint32_t* cert_chain_len) {
    XMLElement *subroot, *element;
    int count;

    if (cert_chain_len == NULL)
        return KM_ERROR_INVALID_ARGUMENT;

    if (xml_root == NULL)
        return KM_ERROR_INVALID_ARGUMENT;

    if (algorithm == KM_ALGORITHM_RSA) {
        subroot = tinyxml2_FindElement(xml_root, NULL, "Key", "algorithm", XML_KEY_ALGORITHM_RSA_STRING);
        if (subroot == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        count = 0;
        for (element = tinyxml2_FindElement(subroot, NULL, "Certificate", NULL, NULL); element;
             element = tinyxml2_FindElement(subroot, element, "Certificate", NULL, NULL)) {
            count++;
        }
    } else if (algorithm == KM_ALGORITHM_EC) {
        subroot = tinyxml2_FindElement(xml_root, NULL, "Key", "algorithm", XML_KEY_ALGORITHM_EC_STRING);
        if (subroot == NULL)
            return KM_ERROR_UNKNOWN_ERROR;
        count = 0;
        for (element = tinyxml2_FindElement(subroot, NULL, "Certificate", NULL, NULL); element;
             element = tinyxml2_FindElement(subroot, element, "Certificate", NULL, NULL)) {
            count++;
        }
    } else {
        LOG_E("No matched key in keybox!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    *cert_chain_len = count;

    return KM_ERROR_OK;
}

keymaster_error_t get_cert_from_keybox(XMLElement* xml_root,
                keymaster_algorithm_t algorithm,
                uint32_t cert_index,
                uint8_t** cert,
                uint32_t* cert_size) {
    XMLElement *subroot, *element;
    char *base64data;
    uint8_t *decodedata;
    char *p, *pstart, *pend;
    char *text;
    uint32_t count;

    if ((cert == NULL) || (cert_size == NULL))
        return KM_ERROR_INVALID_ARGUMENT;

    if (xml_root == NULL)
        return KM_ERROR_INVALID_ARGUMENT;

    if (algorithm == KM_ALGORITHM_RSA)
        subroot = tinyxml2_FindElement(xml_root, NULL, "Key", "algorithm", XML_KEY_ALGORITHM_RSA_STRING);
    else if (algorithm == KM_ALGORITHM_EC)
        subroot = tinyxml2_FindElement(xml_root, NULL, "Key", "algorithm", XML_KEY_ALGORITHM_EC_STRING);
    else {
        LOG_E("No matched key in keybox!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (subroot == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    count = 0;
    for (element = tinyxml2_FindElement(subroot, NULL, "Certificate", NULL, NULL); element;
         element = tinyxml2_FindElement(subroot, element, "Certificate", NULL, NULL)) {
        if (cert_index == count)
            break;
        else
            count++;
    }
    if (element == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    text = (char *)element->GetText();
    if (text == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    count = strlen(text);
    if ((p = strstr(text, "-----BEGIN CERTIFICATE-----")) == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    pstart = p + strlen("-----BEGIN CERTIFICATE-----");
    if ((pend = strstr(text, "-----END CERTIFICATE-----")) == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    base64data = new char[count];
    if (base64data == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    count = 0;
    for (p = pstart; p < pend; p++) {
        if (!isspace(*p))
            base64data[count++] = *p;
    }
    base64data[count] = 0x00;

    decodedata = new uint8_t[count];
    if (decodedata == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (!EVP_DecodeBase64(decodedata, (size_t *)&count, count, (const uint8_t *)base64data, strlen(base64data))) {
        LOG_E("Failed to do base64 decode!", 0);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *cert = decodedata;
    *cert_size = count;
    delete [] base64data;

    return KM_ERROR_OK;
}

}  // namespace keymaster

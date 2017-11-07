/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * cse_msg.h
 */

#ifndef _CSE_MSG_H
#define _CSE_MSG_H

#define CSE_USRCMD_SIZE            128

typedef union _MKHI_MESSAGE_HEADER {
    uint32_t Data;
    struct {
        uint32_t  GroupId : 8;
        uint32_t  Command : 7;
        uint32_t  IsResponse : 1;
        uint32_t  Reserved : 8;
        uint32_t  Result : 8;
    } Fields;
} MKHI_MESSAGE_HEADER;

/*
 * ifwi prepare for update
 */
struct HECI_REQ_IFWI_PREPARE_FOR_UPDATE
{
    MKHI_MESSAGE_HEADER MKHIHeader;
    uint8_t reset_type;
};

struct HECI_RES_IFWI_PREPARE_FOR_UPDATE
{
    MKHI_MESSAGE_HEADER MKHIHeader;
    uint8_t flag;
};

/*
 * Enter DNX mode
 */
struct HECI_REQ_CSE_DNX_REQ
{
    MKHI_MESSAGE_HEADER MKHIHeader;
};

struct HECI_RES_CSE_DNX_REQ
{
    MKHI_MESSAGE_HEADER MKHIHeader;
    uint32_t req_bios_action;
};

/*
 * End of Post ACK message
 */
typedef struct _CBM_EOP_ACK_DATA {
    uint32_t  RequestedActions;
} CBM_EOP_ACK_DATA;

//EOP-REQ
typedef struct _GEN_END_OF_POST
{
    MKHI_MESSAGE_HEADER  MKHIHeader;
} GEN_END_OF_POST;

//EOP-ACK
typedef struct _GEN_END_OF_POST_ACK {
    MKHI_MESSAGE_HEADER Header;
    CBM_EOP_ACK_DATA    Data;
} GEN_END_OF_POST_ACK;

/*
 * User command  message
 */
typedef struct __attribute__( (packed) ) _HECI_USER_CMD_REQUEST
{
    MKHI_MESSAGE_HEADER  MKHIHeader;
    uint8_t sub_command;
    uint8_t data[CSE_USRCMD_SIZE];
} HECI_USER_CMD_REQUEST;

typedef struct _HECI_USER_CMD_RESPONSE {
    MKHI_MESSAGE_HEADER Header;
} HECI_USER_CMD_RESPONSE;

/*
 * PCR Extended Interface
 */
#define MKHI_BOOTLOADER_PCR_EXTEND_CMD_REQ 0x10
#define MKHI_BOOTLOADER_PCR_EXTEND_GRP_ID  0xF0
#define MKHI_BOOTLOADER_PCR_LEN            32

typedef struct _MKHI_BOOTLOADER_PCR_EXTEND_REQ_DATA
{
    MKHI_MESSAGE_HEADER MKHIHeader;
    uint8_t               pcr[MKHI_BOOTLOADER_PCR_LEN];
} __attribute__((packed)) MKHI_BOOTLOADER_PCR_EXTEND_REQ_DATA;

typedef struct _MKHI_BOOTLOADER_PCR_EXTEND_RESPONSE_DATA
{
    MKHI_MESSAGE_HEADER MKHIHeader;
} MKHI_BOOTLOADER_PCR_EXTEND_RESP_DATA;

/*
 * Seed Interface
 */
#define MKHI_BOOTLOADER_GET_SEED_CMD_REQ 0x0F
#define MKHI_BOOTLOADER_GET_SEED_GRP_ID  0xF0
#define MKHI_BOOTLOADER_SEED_LEN         32

typedef struct _MKHI_BOOTLODAER_GET_SEED_REQ_DATA
{
    MKHI_MESSAGE_HEADER MKHIHeader;
} MKHI_BOOTLOADER_GET_SEED_REQ_DATA;

typedef struct _MKHI_BOOTLOADER_GET_SEED_RESPONSE_DATA
{
    MKHI_MESSAGE_HEADER MKHIHeader;
    uint8_t seed[MKHI_BOOTLOADER_SEED_LEN];
} __attribute__((packed)) MKHI_BOOTLOADER_GET_SEED_RESP_DATA;

/*
 * for MKHI-MCA client
 */
#define MCA_MKHI_BOOTLOADER_READ_ATTKB_CMD_REQ  0x19
#define MCA_MKHI_BOOTLOADER_READ_ATTKB_GRP_ID   0x0A
#define MCA_BUFFER_SIZE                         (16*1024)

typedef struct
{
    MKHI_MESSAGE_HEADER  MKHIHeader;
    uint32_t             Offset;
    uint32_t             Size;
    uint32_t             DstAddrLower;
    uint32_t             DstAddrUpper;
    uint32_t             Flags;
} MCA_BOOTLOADER_READ_ATTKB_REQ_DATA;

typedef struct
{
    MKHI_MESSAGE_HEADER  Header;
    uint32_t             ReadSize;
} MCA_BOOTLOADER_READ_ATTKB_RESP_DATA;

#endif    // _CSE_MSG_H

/*
################################################################################
#
#  Copyright 2019-2021 Inango Systems Ltd.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
################################################################################
*/
#ifndef RSC_PROTOCOL_H_
#define RSC_PROTOCOL_H_

#include <stdint.h>
#include <stddef.h>

#define RSC_PROTOCOL_VERSION 3

/* 0x52534321 is just 'RSC!' in ASCII */
#define RSC_MAGIC 0x52534321ul

/* aligned size to 32 bit */
#define SizeAligned32(size) (((size+3)/4)*4)

#define SO_REUSEADDR_VALUE 1
#define SO_KEEPALIVE_VALUE 1
#define TCP_KEEPCNT_VALUE 1
#define TCP_NODELAY_VALUE 1
#define TCP_KEEPINTVL_VALUE 10
#define TCP_KEEPIDLE_VALUE 30
#define TCP_USER_TIMEOUT_VALUE (TCP_KEEPIDLE_VALUE + TCP_KEEPINTVL_VALUE * TCP_KEEPCNT_VALUE)*1000

/* message client sends immediately after connect to the server for handshake procedure */
typedef struct RscSessionRequest_s
{
    /* Magic value (is always sent in network byte order) */
    uint32_t magic;
} RscSessionRequest_t;

/* message server sends to the client in response to RscSessionRequest_t */
typedef struct RscSessionResponse_s
{
    /*version of implemented protocol*/
    uint32_t protocolVersion;
    /*how many bits a pointer is?*/
    uint32_t sizeOfPointer;
    /* size of input buffer of the server*/
    uint32_t sizeOfServerBuffer;
    /* thread local event fd of the default server thread */
    int      defaultThreadEventFd;
} RscSessionResponse_t;

/*types of messages in RSC exchange protocol*/
typedef enum RscMsgType_e
{
    RSC_MSG_TYPE_NOT_INITIALIZED,
    RSC_MSG_TYPE_SYSCALL_REQUEST,
    RSC_MSG_TYPE_SYSCALL_RESPONSE,
    RSC_MSG_TYPE_INFO_REQUEST,
    RSC_MSG_TYPE_INFO_RESPONSE,
    RSC_MSG_TYPE_MEMCPY_REQUEST,
    RSC_MSG_TYPE_MEMCPY_RESPONSE,
    RSC_MSG_TYPE_NEW_THREAD_REQUEST,
    RSC_MSG_TYPE_NEW_THREAD_RESPONSE,
    RSC_MSG_TYPE_STOP_THREAD_REQUEST,
    RSC_MSG_TYPE_STOP_THREAD_RESPONSE,
    RSC_MSG_TYPE_SET_EVENT_REQUEST,
    /*here we can add types of new messages*/
    /*stub*/
    RSC_MSG_TYPE_UNDEFINED
} RscMsgType_t;

/*header of each message from RSC exchange protocol (exclude RscSessionRequest_s and RscSessionResponse_s)*/
typedef struct RscHeaderMsg_s
{
    RscMsgType_t msgType;
    /*size of message without header RscHeaderMsg_s*/
    uint32_t msgLen;
    /*thread ID determines in which thread the message must be process or was been processed*/
    uint32_t threadId;
} RscHeaderMsg_t;

/*after header in message follows the set of parameters*/
/*types of parameters:*/
typedef enum RscParamType_e
{
    RSC_PARAM_TYPE_UNDEFINED,
    /*transmitted by value*/
    RSC_PARAM_TYPE_VALUE,
    /*pointers to arrays and structures without pointers inside, this data send to server and return from it*/
    RSC_PARAM_TYPE_PTR_IN_OUT,
    /*this data we don't send to server, it does not unpacked on server side*/
    RSC_PARAM_TYPE_PTR_OUT,
    /*this data we don't send back to client*/
    RSC_PARAM_TYPE_PTR_IN,
    /*this type used for return value only, when the syscall returns a pointer*/
    RSC_PARAM_TYPE_PTR_RETURN
    /*here we can add types - pointers to not simple arrays and structures. all of them must be not equal 0 and must be pointers*/
    /* ... */
} RscParamType_t;


/*each parameter sends like a descriptor and array of data (if it is necessary)*/
/*the data of parameter must occupy the number of byte aligned to 32 bit*/
/*parameter's descriptor:*/
typedef struct RscDescParam_s
{
    /*type of parameter*/
    RscParamType_t type;
    /*size of array with data or value for TYPE_VALUE*/
    uintptr_t size;
} RscDescParam_t;


/*first required parameter for RSC_MSG_TYPE_SYSCALL_REQUEST:*/
typedef struct RscHeaderSyscallRequest_s
{
    /*number of parameters without itself. */
    uint32_t numberOfParams;
    /* Number of pre-execute actions */
    uint32_t numOfPreActions;
    /* Number of post-execute actions */
    uint32_t numOfPostActions;
} RscHeaderSyscallRequest_t;
/*second required parameter for RSC_MSG_TYPE_SYSCALL_REQUEST is the name of syscall*/
/*this parameter sends like a pointer RSC_PARAM_TYPE_PTR_IN*/

/*other parameters depends on RscHeaderSyscallRequest_s*/

/*after the parameters pre-execute actions and post-execute actions follow*/
/* Server-side actions for setting up a system call and its parameters */
typedef enum RscActionType_e
{
    RSC_ACTION_TYPE_NONE,
    RSC_ACTION_TYPE_ALLOC,
    RSC_ACTION_TYPE_SET_ADDR,
    RSC_ACTION_TYPE_PTRARRCPY,
    RSC_ACTION_TYPE_STRCPY,
    RSC_ACTION_TYPE_MEMCPY,
    RSC_ACTION_TYPE_SET_OFFS
} RscActionType_t;

/* Action description */
typedef struct RscAction_s
{
    /* Type of the action */
    RscActionType_t type;
    uint32_t paramId;
    union
    {
        struct
        {
            uint32_t length;
            uint32_t offset;
        } alloc;
        struct
        {
            uint32_t offset1;
            uint32_t offset2;
        } setaddr;
        struct
        {
            uint32_t length;
            uint32_t offset;
        } memcpy;
        struct
        {
            uint32_t offset;
        } setoffs;
        struct
        {
            uint32_t offset;
        } ptrarrcpy;
        struct
        {
            uint32_t offset;
        } strcpy;
    } u;
} RscAction_t;


/*result of work of server may be equal:*/
typedef enum RscResult_e
{
    /*ok*/
    RSC_RESULT_OK,
    /*dlsym don't find function*/
    RSC_RESULT_NOT_IMPLEMENTED_SYSCALL,
    /*run out of data, when try get data of one of param*/
    RSC_RESULT_NOT_ENOUGH_DATA,
    /*run out of data, when try get next desc_param*/
    RSC_RESULT_NOT_ENOUGH_PARAMS,
    /*input message too big*/
    RSC_RESULT_MSG_TOO_BIG,
    /*invalid pre-execute action presents*/
    RSC_INVALID_PRE_ACTION,
    /*invalid post-execute action presents*/
    RSC_INVALID_POST_ACTION,
    /*not enough memory to processing the allocate action*/
    RSC_RESULT_NOT_ENOUGH_MEMORY,
    /*wrong offset in the action*/
    RSC_RESULT_WRONG_OFFSET,
    /*error occurred during send*/
    RSC_RESULT_SEND_ERROR,
    /*error occurred during recv*/
    RSC_RESULT_RECV_ERROR,
    /*invalid thread id*/
    RSC_INVALID_THREAD_ID,
    /*can't create thread, number of threads is maximum*/
    RSC_THREADS_MAX,
    /*the thread doesn't exist*/
    RSC_THREAD_NO_EXISTS,
    /*mutex initialisation error*/
    RSC_MUTEX_INIT_ERROR,
    /*cond initialisation error*/
    RSC_COND_INIT_ERROR,
    /* event initialisation error */
    RSC_EVENT_INIT_ERROR,
    /*thread initialisation error*/
    RSC_THREAD_INIT_ERROR,
    /*call to busy thread*/
    RSC_THREAD_BUSY,
    /* event file descriptor I/O operation error */
    RSC_RESULT_EVENT_IO_ERROR,
    /*invalid response*/
    RSC_INVALID_RESPONSE,
    /* invalid function argument value: NULL pointer, zero size, etc. */
    RSC_RESULT_INVALID_ARGUMENT,
    /*stub*/
    RSC_RESULT_UNDEFINED_ERROR
} RscResult_t;

/*first required parameter for RSC_MSG_TYPE_SYSCALL_RESPONSE:*/
typedef struct RscHeaderSyscallResponse_s
{
    /*result of work rsc, =0 if system call was running in real, =error code - if something wrong happened*/
    RscResult_t rscResult;
    /*errno from server after running of system call*/
    int         returnErrno;
    int         returnHerrno;
} RscHeaderSyscallResponse_t;
/*other parameters for RSC_PACKET_TYPE_SYSCALL_RESPONSE depends on syscall and received parameters from client*/

typedef struct RscMemcpyItem_s
{
    /* Server-side pointer*/
    void   *ptr;
    /* Number of bytes to copy (if zero - assume a zero-terminated string) */
    size_t  length;
} RscMemcpyItem_t;

/*header of message of type RSC_MSG_TYPE_MEMCPY_RESPONSE*/
typedef struct RscHeaderMemcpyResponse_s
{
    /*result of memcpy work*/
    RscResult_t rscResult;
} RscHeaderMemcpyResponse_t;

/*payload of the new thread response*/
typedef struct RscNewThreadResponse_s
{
    /*result of the new thread request processing*/
    RscResult_t rscResult;
    /*id of the new thread*/
    uint32_t    newThreadID;
    /* thread local event fd */
    int         eventFd;
} RscNewThreadResponse_t;

const char * RscResultToStr(RscResult_t result);

#endif /* RSC_PROTOCOL_H_ */

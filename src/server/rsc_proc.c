/*
################################################################################
#
#  Copyright 2019 Inango Systems Ltd.
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

#include <limits.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "rsc_protocol.h"
#include "rsc_malloc.h"
#include "rsc_syscall.h"
#include "rsc_server.h"
#include "rsc_packing.h"
#include "rsc_transport.h"
#include "rsc_threads.h"
#include "rsc_logger.h"


/*numbers of required parameters in RSC_MSG_TYPE_SYSCALL_REQUEST*/
#define RSC_REQ_PARAM_HEADER            0
#define RSC_REQ_PARAM_SYSCALL_NAME      1
#define RSC_REQ_PARAM_RETURN            2
#define RSC_REQ_PARAM_FIRST_ARG         3

#define NUMBER_OF_SERVICE_PARAMS (RSC_REQ_PARAM_FIRST_ARG - RSC_REQ_PARAM_SYSCALL_NAME)

/*input and output buffers*/
uint8_t gRscInDataBuffer[MAX_DATA_SIZE];
uint8_t gRscOutDataBuffer[MAX_DATA_SIZE];


/*possible value of result of handshake procedure*/
typedef enum RscHandshakeResult_e
{
    RSC_HANDSHAKE_RESULT_OK,
    RSC_HANDSHAKE_RESULT_NOT_MAGIC,
    RSC_HANDSHAKE_RESULT_RECV_ERROR,
    RSC_HANDSHAKE_RESULT_RECV_NOT_ALL_DATA,
    RSC_HANDSHAKE_RESULT_SEND_ERROR,
    RSC_HANDSHAKE_RESULT_UNKNOWN_ERROR
} RscHandshakeResult_t;

/*procedure of handshake between server and client after connection*/
static RscHandshakeResult_t RscHandshake(int eventFd)
{
    RscSessionRequest_t infoIn;
    RscSessionResponse_t infoOut;
    ssize_t res;

    res = RscRecv(&infoIn, sizeof(infoIn));
    if (res == -1)
        return RSC_HANDSHAKE_RESULT_RECV_ERROR;

    infoIn.magic = ntohl(infoIn.magic);
    RSC_LOG_INFO("Client info: MAGIC = 0x%08X", infoIn.magic);
    if (infoIn.magic != RSC_MAGIC)
        return RSC_HANDSHAKE_RESULT_NOT_MAGIC;

    infoOut.protocolVersion = RSC_PROTOCOL_VERSION;
    infoOut.sizeOfPointer = CHAR_BIT * sizeof(void*);
    infoOut.sizeOfServerBuffer = sizeof(gRscOutDataBuffer);
    infoOut.defaultThreadEventFd = eventFd;
    RSC_LOG_INFO("Server info: protocolVersion = %u, sizeOfPointer = %u, sizeOfBuffer = %u, eventFd = %d", infoOut.protocolVersion, infoOut.sizeOfPointer, infoOut.sizeOfServerBuffer, eventFd);

    res = RscSend(&infoOut, sizeof(infoOut));
    if (res == -1)
        return RSC_HANDSHAKE_RESULT_SEND_ERROR;

    return RSC_HANDSHAKE_RESULT_OK;
}

/* Return =1 if segment [a, a + sizeA] is included in [b, b + sizeB]
 * else return =0
 * */
static int IsSegmentInsideSegment(uint32_t a, uint32_t sizeA, uint32_t b, uint32_t sizeB)
{
    if ((a >= b) && (a + sizeA <= b + sizeB))
    {
        return 1;
    }
    return 0;
}

/* Complex parameter = body of parameter received from the client + memory allocated by pre-actions + memory allocated by post-actions
 * This functions return the address of the 'offs' byte of complex parameter from its begin
 * and 0 if
 * (1) size of complex parameter less then 'offs'
 * (2) impossible to get the address (value with size = sizeof(char*)) from the pointed memory cell because the cell located near the border of some part of complex parameter
 * */
static uint8_t * GetAddressByOffsetInComplexParameter(RscDescParam_t *desc, uintptr_t syscallArg, RscParamAddons_t preAddon, RscParamAddons_t postAddon, uint32_t offs)
{
    uint8_t *tempP = 0;

    if (IsSegmentInsideSegment(offs, sizeof(tempP), 0, desc->size))
    {
        /*if the offset points to the body of the parameter*/
        tempP = (uint8_t*)syscallArg + offs;
    }
    else if (IsSegmentInsideSegment(offs, sizeof(tempP), desc->size, preAddon.size))
    {
        /*if the offset points to the addon of the parameter*/
        tempP = (uint8_t*)preAddon.p + offs - desc->size;
    }
    else if (IsSegmentInsideSegment(offs, sizeof(tempP), desc->size + preAddon.size, postAddon.size))
    {
        /*if the offset points to the addon of the parameter*/
        tempP = (uint8_t*)postAddon.p + offs - desc->size - preAddon.size;
    }
    return tempP;
}

/* Processing of all pre-executed actions
 * buf - buffer with actions from the msg, inLen - length of the buffer, numPreActions - number of pre-executed actions
 * descs - descriptors of parameters, syscallArgs - pointers to buffers with parameters data, numberOfParams - number of parameters
 * preAddons - pointers and sizes of allocated memory during pre-executed actions (return)
 * */
static RscResult_t RscDoPreActions(const uint8_t *buf, uint32_t inLen, uint32_t numPreActions, RscDescParam_t *descs[], uintptr_t syscallArgs[], uint32_t numberOfParams, RscParamAddons_t preAddons[], RscMemForMalloc_t *allocBuf)
{
    uint32_t doneActions = 0;
    uint32_t param;
    uint32_t action;
    uint8_t *tempP;
    uint8_t *destP;
    uint8_t *sourceP;
    RscAction_t *pCurAction;
    RscParamAddons_t postAddonStub = {0,0};

    if(inLen < numPreActions * sizeof(RscAction_t))
    {
        RSC_LOG_ERROR("Not all pre-executed actions presents (len = %u, num = %u)", inLen, numPreActions);
        return RSC_RESULT_NOT_ENOUGH_DATA;
    }

    /*execute the actions for the each parameter*/
    for (param = 0; param < numberOfParams; param++)
    {
        if(descs[param]->type == RSC_PARAM_TYPE_VALUE)
            continue;

        for (action = 0; action < numPreActions; action++)
        {
            pCurAction = (RscAction_t*)buf+action;
            /*if the action for this parameter then execute it*/
            if (pCurAction->paramId == param)
            {
                doneActions++; /*count the processed actions*/
                switch (pCurAction->type)
                {
                case RSC_ACTION_TYPE_ALLOC:
                    tempP = RscMalloc(allocBuf, pCurAction->u.alloc.length);
                    if (!tempP)
                    {
                        RSC_LOG_ERROR("Not enough memory to processing the allocate action. size = %u", pCurAction->u.alloc.length);
                        return RSC_RESULT_NOT_ENOUGH_MEMORY;
                    }
                    destP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddonStub, pCurAction->u.alloc.offset);
                    if (destP)
                    {
                        memcpy(destP, &tempP, sizeof(tempP));
                    }
                    else
                    {
                        RSC_LOG_ERROR("Wrong offset in the allocate action. offset = %u", pCurAction->u.alloc.offset);
                        return RSC_RESULT_WRONG_OFFSET;
                    }
                    if (!preAddons[param].p)
                    {
                        /*it is the first malloc*/
                        preAddons[param].p = (uintptr_t)tempP;
                    }
                    /*here we use the continuity of allocated by RscMalloc data*/
                    preAddons[param].size += pCurAction->u.alloc.length;
                    break;
                case RSC_ACTION_TYPE_SET_ADDR:
                    destP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddonStub, pCurAction->u.setaddr.offset1);
                    sourceP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddonStub, pCurAction->u.setaddr.offset2);
                    if(!destP || !sourceP)
                    {
                        RSC_LOG_ERROR("Wrong offset in the setaddr action. offset1 = %u  offset2 = %u", pCurAction->u.setaddr.offset1, pCurAction->u.setaddr.offset2);
                        return RSC_RESULT_WRONG_OFFSET;
                    }
                    memcpy(destP, &sourceP, sizeof(sourceP));
                    break;
                default:
                    RSC_LOG_ERROR("Invalid pre-executed action. type = %d", ((RscAction_t*)buf+action)->type);
                    return RSC_INVALID_PRE_ACTION;
                }
            }
        }
    }

    /*error if not all pre-actions was processed*/
    if (doneActions < numPreActions)
    {
        RSC_LOG_ERROR("Not all pre-executed action was processed. num = %u  processed = %u", numPreActions, doneActions);
        return RSC_INVALID_PRE_ACTION;
    }

    return RSC_RESULT_OK;
}

/* Processing of all post-executed actions
 * buf - buffer with actions from the msg, inLen - length of the buffer, numPostActions - number of post-executed actions
 * descs - descriptors of parameters, syscallArgs - pointers to buffers with parameters data, numberOfParams - number of parameters
 * preAddons - pointers and sizes of allocated memory during pre-executed actions
 * postAddons - pointers and sizes of allocated memory during pre-executed actions (return)
 * */
static RscResult_t RscDoPostActions(const uint8_t *buf, uint32_t inLen, uint32_t numPostActions, RscDescParam_t *descs[], uintptr_t syscallArgs[], uint32_t numberOfParams, RscParamAddons_t preAddons[], RscParamAddons_t postAddons[], RscMemForMalloc_t *allocBuf)
{
    uint32_t doneActions = 0;
    uint32_t param;
    uint32_t action;
    uint32_t strL;
    uint8_t *tempP;
    uint8_t *sourceP;
    uintptr_t tempAddr;
    RscAction_t *pCurAction;

    if(inLen < numPostActions * sizeof(RscAction_t))
    {
        RSC_LOG_ERROR("Not all post-executed actions presents");
        return RSC_RESULT_NOT_ENOUGH_DATA;
    }

    /*execute the actions for the each parameter*/
    for (param = 0; param < numberOfParams; param++)
    {
        if(descs[param]->type == RSC_PARAM_TYPE_VALUE)
            continue;

        for (action = 0; action < numPostActions; action++)
        {
            pCurAction = (RscAction_t*)buf+action;
            /*if the action for this parameter then execute it*/
            if (pCurAction->paramId == param)
            {
                doneActions++; /*count the processed actions*/
                /*skip post-actions for NULL-pointers*/
                if (descs[param]->size == 0)
                    continue;
                switch (pCurAction->type)
                {
                case RSC_ACTION_TYPE_SET_OFFS:
                    sourceP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddons[param], pCurAction->u.setoffs.offset);
                    if (!sourceP)
                    {
                        RSC_LOG_ERROR("Wrong offset in the setoffs action. offset = %u", pCurAction->u.setoffs.offset);
                        return RSC_RESULT_WRONG_OFFSET;
                    }
                    tempAddr = *((uintptr_t*)sourceP);
                    if ((tempAddr >= syscallArgs[param]) && (tempAddr < syscallArgs[param] + descs[param]->size))
                    {
                        /*addr located in the param body*/
                        tempAddr -= syscallArgs[param];
                    }
                    else if ((tempAddr >= preAddons[param].p) && (tempAddr < preAddons[param].p + preAddons[param].size))
                    {
                        /*addr located in the pre-executed addon*/
                        tempAddr -= preAddons[param].p;
                        tempAddr += descs[param]->size;
                    }
                    else if ((tempAddr >= postAddons[param].p) && (tempAddr < postAddons[param].p + postAddons[param].size))
                    {
                        /*addr located in the post-executed addon (it is useless may be)*/
                        tempAddr -= postAddons[param].p;
                        tempAddr += descs[param]->size;
                        tempAddr += preAddons[param].size;
                    }
                    else
                    {
                        RSC_LOG_ERROR("Wrong offset in the setoffs action. offset = %u", pCurAction->u.setoffs.offset);
                        return RSC_RESULT_WRONG_OFFSET;
                    }
                    memcpy(sourceP, &tempAddr, sizeof(tempAddr));
                    break;
                case RSC_ACTION_TYPE_MEMCPY:
                    tempP = RscMalloc(allocBuf, pCurAction->u.memcpy.length);
                    if (!tempP)
                    {
                        RSC_LOG_ERROR("Not enough memory to processing the memcpy action. size = %u", pCurAction->u.memcpy.length);
                        return RSC_RESULT_NOT_ENOUGH_MEMORY;
                    }
                    sourceP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddons[param], pCurAction->u.memcpy.offset);
                    if (sourceP)
                    {
                        memcpy(tempP, *((char**)sourceP), pCurAction->u.memcpy.length);
                    }
                    else
                    {
                        RSC_LOG_ERROR("Wrong offset in the memcpy action. offset = %u", pCurAction->u.memcpy.offset);
                        return RSC_RESULT_WRONG_OFFSET;
                    }
                    if (!postAddons[param].p)
                    {
                        /*it is the first malloc*/
                        postAddons[param].p = (uintptr_t)tempP;
                    }
                    /*here we use the continuity of allocated by RscMalloc data*/
                    postAddons[param].size += pCurAction->u.memcpy.length;

                    tempP = descs[param]->size + preAddons[param].size + (tempP - postAddons[param].p);
                    memcpy(sourceP, &tempP, sizeof(tempP));
                    break;
                case RSC_ACTION_TYPE_STRCPY:
                    sourceP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddons[param], pCurAction->u.strcpy.offset);
                    if (!sourceP)
                    {
                        RSC_LOG_ERROR("Wrong offset in the strcpy action. offset = %u", pCurAction->u.strcpy.offset);
                        return RSC_RESULT_WRONG_OFFSET;
                    }
                    strL = strlen(*((char**)sourceP))+1;
                    tempP = RscMalloc(allocBuf, strL);
                    if (!tempP)
                    {
                        RSC_LOG_ERROR("Not enough memory to processing the strcpy action. size = %u", strL);
                        return RSC_RESULT_NOT_ENOUGH_MEMORY;
                    }
                    memcpy(tempP, *((char**)sourceP), strL);
                    if (!postAddons[param].p)
                    {
                        /*it is the first malloc*/
                        postAddons[param].p = (uintptr_t)tempP;
                    }
                    /*here we use the continuity of allocated by RscMalloc data*/
                    postAddons[param].size += strL;

                    tempP = descs[param]->size + preAddons[param].size + (tempP - postAddons[param].p);
                    memcpy(sourceP, &tempP, sizeof(tempP));
                    break;
                case RSC_ACTION_TYPE_PTRARRCPY:
                    sourceP = GetAddressByOffsetInComplexParameter(descs[param], syscallArgs[param], preAddons[param], postAddons[param], pCurAction->u.ptrarrcpy.offset);
                    if (!sourceP)
                    {
                        RSC_LOG_ERROR("Wrong offset in the PTRARRCPY action. offset = %u", pCurAction->u.ptrarrcpy.offset);
                        return RSC_RESULT_WRONG_OFFSET;
                    }

                    /*count the size of the zero-ended array*/
                    strL = 0;
                    while (*(*((uintptr_t**)sourceP) + strL))
                        strL++;
                    strL++;/*zero included*/
                    strL *= sizeof(uintptr_t);

                    tempP = RscMalloc(allocBuf, strL);
                    if (!tempP)
                    {
                        RSC_LOG_ERROR("Not enough memory to processing the PTRARRCPY action. size = %u", strL);
                        return RSC_RESULT_NOT_ENOUGH_MEMORY;
                    }
                    memcpy(tempP, *((char**)sourceP), strL);
                    if (!postAddons[param].p)
                    {
                        /*it is the first malloc*/
                        postAddons[param].p = (uintptr_t)tempP;
                    }
                    /*here we use the continuity of allocated by RscMalloc data*/
                    postAddons[param].size += strL;

                    tempP = descs[param]->size + preAddons[param].size + (tempP - postAddons[param].p);
                    memcpy(sourceP, &tempP, sizeof(tempP));
                    break;
                default:
                    RSC_LOG_ERROR("Invalid post-executed action. type = %u", ((RscAction_t*)buf+action)->type);
                    return RSC_INVALID_POST_ACTION;
                }
            }
        }
    }

    /*error if not all post-actions was processed*/
    if (doneActions < numPostActions)
    {
        RSC_LOG_ERROR("Not all post-executed action was processed. num = %u  processed = %u", numPostActions, doneActions);
        return RSC_INVALID_POST_ACTION;
    }

    return RSC_RESULT_OK;
}

/*unpack and check all parameters for syscall
 * this function fill the array of descriptors of parameters descs[],
 * array of arguments of syscall function syscallArgs[] and number of parameters *pNumberOfParams
 * all data with size inLen gets from pointer buf*/
static RscResult_t RscUnpackSyscallParams(const uint8_t *buf, uint32_t inLen, RscDescParam_t *descs[], uintptr_t syscallArgs[], uint32_t *pNumberOfParams, RscMemForMalloc_t *allocBuf)
{
    uint32_t i;
    RscResult_t resUnpack = RSC_RESULT_OK;
    uint32_t unpackedParams = 0;

    do
    {
        /*get first necessary parameter*/
        descs[RSC_REQ_PARAM_HEADER] = (RscDescParam_t *)buf;
        if (RscUnpackParameter(descs[RSC_REQ_PARAM_HEADER], inLen, &syscallArgs[RSC_REQ_PARAM_HEADER], &descs[RSC_REQ_PARAM_HEADER + 1], allocBuf) != RSC_RESULT_OK)
        {
            resUnpack = RSC_RESULT_NOT_ENOUGH_PARAMS;
            RSC_LOG_ERROR("Error while processing syscall request: can't unpack first parameter");
            break;
        }

        /*check first necessary parameter for type and size*/
        if ((descs[RSC_REQ_PARAM_HEADER]->type != RSC_PARAM_TYPE_PTR_IN) || (descs[RSC_REQ_PARAM_HEADER]->size < sizeof(RscHeaderSyscallRequest_t)))
        {
            resUnpack = RSC_RESULT_NOT_ENOUGH_DATA;
            RSC_LOG_ERROR("Error while processing syscall request: first parameter is not a header");
            break;
        }
        *pNumberOfParams = ((RscHeaderSyscallRequest_t *)syscallArgs[RSC_REQ_PARAM_HEADER])->numberOfParams;

        RSC_LOG_DEBUG("Number of parameters: %d", *pNumberOfParams);

        /*check existing of second and other required parameter */
        if (*pNumberOfParams < NUMBER_OF_SERVICE_PARAMS)
        {
            resUnpack = RSC_RESULT_NOT_ENOUGH_PARAMS;
            RSC_LOG_ERROR("Error while processing syscall request: not enough parameters in syscall header (%d less than %d)", *pNumberOfParams, NUMBER_OF_SERVICE_PARAMS);
            break;
        }

        /*get all parameters and prepare arguments to system call*/
        unpackedParams = 0;
        for (i = 1; i < 1 + *pNumberOfParams; i++)
        {
            /*decrease the size of input data on the size of previous parameter*/
            inLen -= (char*)descs[i] - (char*)descs[i-1];
            resUnpack = RscUnpackParameter(descs[i], inLen, &syscallArgs[i], &descs[i+1], allocBuf);
            if (resUnpack != RSC_RESULT_OK)
            {
                RSC_LOG_ERROR("Error while processing syscall request: can't unpack parameter %d", i);
                break;
            }
            unpackedParams++;
        }
        /*break if not all parameters were read*/
        if (unpackedParams < *pNumberOfParams)
        {
            break;
        }

        /*check the second parameter = name of syscall*/
        if (descs[RSC_REQ_PARAM_SYSCALL_NAME]->type != RSC_PARAM_TYPE_PTR_IN)
        {
            resUnpack = RSC_RESULT_UNDEFINED_ERROR;
            RSC_LOG_ERROR("Error while processing syscall request: second parameter is not a name (%d is not input array)", descs[RSC_REQ_PARAM_SYSCALL_NAME]->type);
            break;
        }

        /*check the third parameter = return value*/
        if ((descs[RSC_REQ_PARAM_RETURN]->type != RSC_PARAM_TYPE_PTR_RETURN) && (descs[RSC_REQ_PARAM_RETURN]->type != RSC_PARAM_TYPE_VALUE))
        {
            resUnpack = RSC_RESULT_UNDEFINED_ERROR;
            RSC_LOG_ERROR("Error while processing syscall request: invalid type of the return value (type = %d)", descs[RSC_REQ_PARAM_RETURN]->type);
            break;
        }
    } while(0);

    return resUnpack;
}

/*read and processing syscall request*/
static RscResult_t RscProcessingSyscallRequest(RscHeaderMsg_t inHeader)
{
    static const RscParamAddons_t addonStub = {0, 0};

    uint32_t inLen = inHeader.msgLen;
    uint32_t threadId = inHeader.threadId;
    ssize_t needSendByte;
    ssize_t resSend;
    ssize_t resRecv;
    uint64_t eventValue;
    RscHeaderMsg_t msgHeader;
    RscHeaderSyscallResponse_t responseHeader;

    msgHeader.msgType = RSC_MSG_TYPE_SYSCALL_RESPONSE;
    msgHeader.msgLen = 0;
    msgHeader.threadId = threadId;
    memset(&responseHeader, 0, sizeof(responseHeader));

    do
    {
        /*if size of input data it too large is the error*/
        if (inLen > MAX_DATA_SIZE)
        {
            responseHeader.rscResult = RSC_RESULT_MSG_TOO_BIG;
            RSC_LOG_ERROR("Error while processing syscall request: inLen > MAX_DATA_SIZE");
            break;
        }

        /*validate the thread*/
        if (threadId >= MAX_THREAD_NUMBER)
        {
            responseHeader.rscResult = RSC_INVALID_THREAD_ID;
            RSC_LOG_ERROR("Error while processing syscall request: threadId = %d is too big, MAX_THREAD_NUMBER = %d", threadId, MAX_THREAD_NUMBER);
            break;
        }

        if (0 != pthread_mutex_lock(&threadsData[threadId].mutex))
        {
            responseHeader.rscResult = RSC_MUTEX_INIT_ERROR;
            RSC_LOG_ERROR("Error while processing syscall request: thread %d can't lock the mutex", threadId);
            break;
        }

        if (threadsData[threadId].isProcessing)
        {
            responseHeader.rscResult = RSC_THREAD_BUSY;
            RSC_LOG_ERROR("Error while processing syscall request: thread %d is busy", threadId);
            pthread_mutex_unlock(&threadsData[threadId].mutex);
            break;
        }

        if (0 == threadsData[threadId].thread)
        {
            responseHeader.rscResult = RSC_THREAD_NO_EXISTS;
            RSC_LOG_ERROR("Error while processing syscall request: thread %d does not exist or is stopped", threadId);
            pthread_mutex_unlock(&threadsData[threadId].mutex);
            break;
        }

        /*if we don't receive all data is the error*/
        resRecv = RscRecv(threadsData[threadId].inDataBuffer, inLen);
        if (resRecv == -1)
        {
            responseHeader.rscResult = RSC_RESULT_NOT_ENOUGH_DATA;
            RSC_LOG_ERROR("Error while processing syscall request: received not all data");
            pthread_mutex_unlock(&threadsData[threadId].mutex);
            break;
        }

        /* Reset the event for the thread */
        if (threadsData[threadId].eventValue != 0)
        {
            if (sizeof(uint64_t) != read(threadsData[threadId].eventFds[EVENT_WAIT_FD], &eventValue, sizeof(uint64_t)))
                RSC_LOG_WARN("Failed to reset event in thread %d (pthread = %lu)", threadsData[threadId].id, (long unsigned)threadsData[threadId].thread);

            threadsData[threadId].eventValue = 0;
        }

        threadsData[threadId].isProcessing = 1;
        threadsData[threadId].inDataSize = inLen;

        pthread_cond_signal(&threadsData[threadId].cond);
        pthread_mutex_unlock(&threadsData[threadId].mutex);
        return RSC_RESULT_OK;
    } while(0);

    /* We are here because of an error while receiving the message - have to send a response about it */

    /*pack the header of response*/
    msgHeader.msgLen += RscPackParameter(gRscOutDataBuffer+sizeof(msgHeader), (uint8_t*)(&responseHeader), sizeof(responseHeader), RSC_PARAM_TYPE_PTR_IN_OUT, addonStub, addonStub);
    /*put message header to output buffer */
    memcpy(gRscOutDataBuffer, &msgHeader, sizeof(msgHeader));
    needSendByte = msgHeader.msgLen + sizeof(msgHeader);
    RSC_LOG_DEBUG("Sending as a response %ld bytes", (long)needSendByte);
    /*and write message to socket*/
    resSend = RscSend(gRscOutDataBuffer, needSendByte);
    if (resSend == -1)
    {
        RSC_LOG_ERROR("Failed to send the response");
        return RSC_RESULT_SEND_ERROR;
    }

    RSC_LOG_DEBUG("Sent %ld bytes", (long)resSend);
    return responseHeader.rscResult;
}

RscResult_t RscProcessingSyscallRequestThread(ThreadData_t* pD)
{
    uint32_t i;
    ssize_t resSend;
    ssize_t needSendByte;
    uint32_t numberOfParams = 0;
    uint32_t numOfPreActions = 0;
    uint32_t numOfPostActions = 0;
    uint32_t inLenWOParams;
    uint32_t inLenWOParamsPreActions;
    RscDescParam_t *descs[MAX_PARAMS];
    uintptr_t syscallArgs[MAX_PARAMS];
    RscParamAddons_t preAddons[MAX_PARAMS];
    RscParamAddons_t postAddons[MAX_PARAMS];
    RscHeaderMsg_t msgHeader;
    RscHeaderSyscallResponse_t responseHeader;
    RscParamAddons_t addonStub = {0,0};

    uint32_t inLen = pD->inDataSize;

    msgHeader.msgType = RSC_MSG_TYPE_SYSCALL_RESPONSE;
    msgHeader.msgLen = 0;
    msgHeader.threadId = pD->id;
    memset(&responseHeader, 0, sizeof(responseHeader));
    memset(&preAddons, 0, MAX_PARAMS*sizeof(RscParamAddons_t));
    memset(&postAddons, 0, MAX_PARAMS*sizeof(RscParamAddons_t));
    RscResetMemBuf(pD->allocateDataBuffer);

    do
    {
        /*if data not include necessary header is the error*/
        if (inLen < sizeof(RscDescParam_t) + sizeof(RscHeaderSyscallRequest_t))
        {
            responseHeader.rscResult = RSC_RESULT_NOT_ENOUGH_PARAMS;
            RSC_LOG_ERROR("(thread = %lu) Error while processing syscall request: header does not exist (%d, %ld)", pD->thread, inLen, (long)(sizeof(RscDescParam_t) + sizeof(RscHeaderSyscallRequest_t)));
            break;
        }

        /*unpack all parameters */
        responseHeader.rscResult = RscUnpackSyscallParams(pD->inDataBuffer, inLen, descs, syscallArgs, &numberOfParams, pD->allocateDataBuffer);
        if (responseHeader.rscResult != RSC_RESULT_OK)
            break;

        numOfPreActions = ((RscHeaderSyscallRequest_t *)syscallArgs[RSC_REQ_PARAM_HEADER])->numOfPreActions;
        numOfPostActions = ((RscHeaderSyscallRequest_t *)syscallArgs[RSC_REQ_PARAM_HEADER])->numOfPostActions;

        /*calculate the number of remaining bytes in message after unpacking of parameters*/
        /*here descs[numberOfParams+1] points to first byte after parameters*/
        inLenWOParams = inLen-((uint8_t*)descs[numberOfParams+1] - pD->inDataBuffer);
        /*processing of all pre-execute actions*/
        responseHeader.rscResult = RscDoPreActions((uint8_t*)descs[numberOfParams+1], inLenWOParams, numOfPreActions, descs, syscallArgs, numberOfParams+1, preAddons, pD->allocateDataBuffer);
        if (responseHeader.rscResult != RSC_RESULT_OK)
            break;

        /*Its majesty syscall*/
        RSC_LOG_INFO("(thread = %lu) Run syscall '%s' with %d parameters", pD->thread, (char*)syscallArgs[RSC_REQ_PARAM_SYSCALL_NAME], numberOfParams - NUMBER_OF_SERVICE_PARAMS);

        responseHeader.rscResult = RscSyscallFunction((char*)syscallArgs[RSC_REQ_PARAM_SYSCALL_NAME], numberOfParams - NUMBER_OF_SERVICE_PARAMS, &(syscallArgs[RSC_REQ_PARAM_FIRST_ARG]), &(syscallArgs[RSC_REQ_PARAM_RETURN]));
        responseHeader.returnErrno = errno;
        responseHeader.returnHerrno = h_errno;
        if (responseHeader.rscResult != RSC_RESULT_OK)
        {
            RSC_LOG_ERROR("(thread = %lu) Result of syscall is %s (%d)", pD->thread, RscResultToStr(responseHeader.rscResult), responseHeader.rscResult);
            break;
        }

        RSC_LOG_INFO("(thread = %lu) Result of syscall is %s (%d) with retvalue %lu", pD->thread, RscResultToStr(responseHeader.rscResult), responseHeader.rscResult, (unsigned long int)syscallArgs[RSC_REQ_PARAM_RETURN]);

        /* if syscall returns a pointer at something*/
        if (descs[RSC_REQ_PARAM_RETURN]->type == RSC_PARAM_TYPE_PTR_RETURN)
        {
            /* if syscall returned the zero pointer*/
            if (0 == syscallArgs[RSC_REQ_PARAM_RETURN])
            {
                descs[RSC_REQ_PARAM_RETURN]->size = 0;
            }
            else
            {
                uint8_t* tmpPtr;
                tmpPtr = RscMalloc(pD->allocateDataBuffer, descs[RSC_REQ_PARAM_RETURN]->size);
                if (NULL == tmpPtr)
                {
                    responseHeader.rscResult = RSC_RESULT_NOT_ENOUGH_MEMORY;
                    RSC_LOG_ERROR("(thread = %lu) Error while processing syscall request: can't allocate memory for the return value", pD->thread);
                    break;
                }
                memcpy(tmpPtr, (uint8_t*)syscallArgs[RSC_REQ_PARAM_RETURN], descs[RSC_REQ_PARAM_RETURN]->size);
                syscallArgs[RSC_REQ_PARAM_RETURN] = (uintptr_t)tmpPtr;
            }
        }

        /*calculate the number of remaining bytes in message after unpacking of parameters and pre-actions*/
        inLenWOParamsPreActions = inLenWOParams - numOfPreActions * sizeof(RscAction_t);
        /*processing of all post-execute actions*/
        responseHeader.rscResult = RscDoPostActions((uint8_t*)descs[numberOfParams+1] + numOfPreActions * sizeof(RscAction_t), inLenWOParamsPreActions, numOfPostActions, descs, syscallArgs, numberOfParams+1, preAddons, postAddons, pD->allocateDataBuffer);

    } while(0);

    /*pack the header of response*/
    msgHeader.msgLen += RscPackParameter(pD->outDataBuffer+sizeof(msgHeader), (uint8_t*)(&responseHeader), sizeof(responseHeader), RSC_PARAM_TYPE_PTR_IN_OUT, addonStub, addonStub);

    /*pack the return value*/
    i = RSC_REQ_PARAM_RETURN;
    msgHeader.msgLen += RscPackParameter(pD->outDataBuffer+sizeof(msgHeader)+msgHeader.msgLen, (uint8_t*)syscallArgs[i], descs[i]->size, descs[i]->type, preAddons[i], postAddons[i]);

    /*if result of syscall is good then pack all necessary parameters to output buffer*/
    if (responseHeader.rscResult == RSC_RESULT_OK)
        for (i = RSC_REQ_PARAM_FIRST_ARG; i < 1 + numberOfParams; i++)
        {
            /*we must return all pointers*/
            if (descs[i]->type != RSC_PARAM_TYPE_VALUE)
                msgHeader.msgLen += RscPackParameter(pD->outDataBuffer+sizeof(msgHeader)+msgHeader.msgLen, (uint8_t*)syscallArgs[i], descs[i]->size, descs[i]->type, preAddons[i], postAddons[i]);
        }

    /*put message header to output buffer */
    memcpy(pD->outDataBuffer, &msgHeader, sizeof(msgHeader));
    needSendByte = msgHeader.msgLen + sizeof(msgHeader);
    RSC_LOG_DEBUG("(thread = %lu) Sending as a response %ld bytes", pD->thread, (long)needSendByte);
    /*and write message to socket*/
    pthread_mutex_lock(&pD->mutex);
    pD->isProcessing = 0;
    pthread_mutex_unlock(&pD->mutex);
    resSend = RscSend(pD->outDataBuffer, needSendByte);
    if (resSend == -1)
    {
        RSC_LOG_ERROR("(thread = %lu) Failed to send the response", pD->thread);
        return RSC_RESULT_SEND_ERROR;
    }

    RSC_LOG_DEBUG("(thread = %lu) Sent %ld bytes", pD->thread, (long)resSend);
    return responseHeader.rscResult;
}

/* Function processing memcpy request from server
 * 1-st arg: [inLen] - size of input data consisting of request header and array of RscMemcpyItem_t items
 * Function performs a request to the server and copies to memory binary array of data with their sizes retrieved from server
 * Return value: [RscResult_t] - 0 if data retrieved and copied successfully, otherwise error code */
static RscResult_t RscProcessingMemcpyRequest(RscHeaderMsg_t inHeader)
{
    RscHeaderMsg_t            *msgHeader  = (RscHeaderMsg_t *)gRscOutDataBuffer;
    RscHeaderMemcpyResponse_t *responseHeader = (RscHeaderMemcpyResponse_t *)(msgHeader + 1);
    RscMemcpyItem_t           *item;
    ssize_t                    bytesCount;
    uint8_t                   *outPtr;
    size_t                    *sizePtr;
    uint32_t                   countParam = 0;

    RscResetMemBuf(0);

    msgHeader->msgType = RSC_MSG_TYPE_MEMCPY_RESPONSE;
    msgHeader->msgLen = sizeof(*responseHeader);
    msgHeader->threadId = inHeader.threadId;

    RSC_LOG_INFO("Run memcpy request");

    /* validate the thread: not an error here but warning can be handy */
    if (inHeader.threadId >= MAX_THREAD_NUMBER)
    {
        RSC_LOG_WARN("Warn while processing memcpy request: threadId = %d is too big, MAX_THREAD_NUMBER = %d", inHeader.threadId, MAX_THREAD_NUMBER);
    }

    if (-1 == RscRecv(gRscInDataBuffer, inHeader.msgLen))
    {
        /* if we didn't receive all the data - its the error */
        responseHeader->rscResult = RSC_RESULT_RECV_ERROR;
        RSC_LOG_ERROR("Error while processing memcpy request: received not all data");
    }
    else
    {
        /* initializing the pointer before data processing */
        outPtr = (uint8_t *)(responseHeader + 1);

        /* process input buffer until all of the asked pointers will be retrieved */
        for(item = (RscMemcpyItem_t *)gRscInDataBuffer; item + 1 <= (RscMemcpyItem_t *)(gRscInDataBuffer + inHeader.msgLen); ++item, ++countParam)
        {
            /* defining pointer to the field with size of data */
            sizePtr = (size_t *)outPtr;

            /* writing size of data */
            if(item->length)
            {
                /* a buffer with length */
                *sizePtr = item->length;
            }
            else
            {
                /* if length of requested memory item is 0, then it is a string with 0 terminator */
                *sizePtr = strlen(item->ptr) + 1;
            }
            outPtr += sizeof(size_t);

            /* copying requested data to output buffer directly */
            memcpy(outPtr, item->ptr, *sizePtr);
            outPtr += *sizePtr;
        }

        msgHeader->msgLen += outPtr - (uint8_t *)(responseHeader + 1);
        responseHeader->rscResult = RSC_RESULT_OK;
    }

    RSC_LOG_DEBUG("Read %u parameters", countParam);
    RSC_LOG_DEBUG("Sending as a response %lu bytes", (long unsigned int) (msgHeader->msgLen + sizeof(RscHeaderMsg_t)));

    /* write message to socket */
    bytesCount = RscSend(gRscOutDataBuffer, msgHeader->msgLen + sizeof(RscHeaderMsg_t));
    if (bytesCount == -1)
    {
        RSC_LOG_ERROR("Failed to send the response");
        return RSC_RESULT_SEND_ERROR;
    }

    RSC_LOG_DEBUG("Sent %ld bytes", (long int)bytesCount);
    return RSC_RESULT_OK;
}

/*
 * processing of a create thread request
 * */
RscResult_t RscProcessingNewThreadRequest(RscHeaderMsg_t inHeader)
{
    RscHeaderMsg_t *msgHeader = (RscHeaderMsg_t *)gRscOutDataBuffer;
    RscNewThreadResponse_t response;
    uint32_t id;
    int      efd = -1;
    ssize_t  resSend;

    msgHeader->msgType = RSC_MSG_TYPE_NEW_THREAD_RESPONSE;
    msgHeader->msgLen = sizeof(response);
    msgHeader->threadId = inHeader.threadId;

    RSC_LOG_INFO("Run new thread request");

    response.rscResult = RscCreateThread(&id, &efd);
    response.newThreadID = id;
    response.eventFd = efd;

    memcpy(msgHeader + 1, &response, sizeof(response));

    RSC_LOG_DEBUG("Sending as a response %lu bytes", (long unsigned int)(msgHeader->msgLen + sizeof(RscHeaderMsg_t)));
    resSend = RscSend(gRscOutDataBuffer, msgHeader->msgLen + sizeof(RscHeaderMsg_t));
    if (resSend == -1)
    {
        RSC_LOG_ERROR("Failed to send the response");
        return RSC_RESULT_SEND_ERROR;
    }

    RSC_LOG_DEBUG("Sent %ld bytes", (long int) resSend);
    return RSC_RESULT_OK;
}

/*
 * processing of a stop thread request
 * */
RscResult_t RscProcessingStopThreadRequest(RscHeaderMsg_t inHeader)
{
    RscHeaderMsg_t *msgHeader = (RscHeaderMsg_t *)gRscOutDataBuffer;
    RscResult_t res;
    ssize_t resSend;
    uint32_t id;

    msgHeader->msgType = RSC_MSG_TYPE_STOP_THREAD_RESPONSE;
    msgHeader->msgLen = sizeof(res);
    msgHeader->threadId = inHeader.threadId;

    RSC_LOG_INFO("Run stop thread request");

    do
    {
        /* if data does not include necessary header then it's an error */
        if (inHeader.msgLen < sizeof(id))
        {
            res = RSC_RESULT_NOT_ENOUGH_DATA;
            RSC_LOG_ERROR("Error while processing stop thread request: not enough data (%u, %lu)", inHeader.msgLen, (long unsigned int)sizeof(id));
            break;
        }

        if (inHeader.msgLen > sizeof(gRscInDataBuffer))
        {
            res = RSC_RESULT_MSG_TOO_BIG;
            RSC_LOG_ERROR("Error while processing stop thread request: message is too big (%u, %lu)", inHeader.msgLen, (long unsigned int)sizeof(id));
            break;
        }

        /* if we don't receive all the data then it will be an error */
        if (-1 == RscRecv(gRscInDataBuffer, inHeader.msgLen))
        {
            res = RSC_RESULT_RECV_ERROR;
            RSC_LOG_ERROR("Error while processing stop thread request: received not all data");
            break;
        }

        memcpy(&id, gRscInDataBuffer, sizeof(id));
        res = RscStopThread(id);
    } while(0);

    memcpy(msgHeader+1, &res, sizeof(res));

    RSC_LOG_DEBUG("Sending as a response %lu bytes", (long unsigned int)(msgHeader->msgLen + sizeof(RscHeaderMsg_t)));
    resSend = RscSend(gRscOutDataBuffer, msgHeader->msgLen + sizeof(RscHeaderMsg_t));
    if (resSend == -1)
    {
        RSC_LOG_ERROR("Failed to send the response");
        return RSC_RESULT_SEND_ERROR;
    }

    RSC_LOG_DEBUG("Sent %ld bytes", (long int) resSend);
    return RSC_RESULT_OK;
}

/*
 * RSC_MSG_TYPE_SET_EVENT_REQUEST message processing
 */
RscResult_t RscRecvPayloadOfSetEventRequest(const RscHeaderMsg_t *msgHeader, uint32_t *threadId)
{
    if (msgHeader->msgLen < sizeof(*threadId))
    {
        RSC_LOG_ERROR("Error while processing set event request: message payload is too small (%u < %lu)", msgHeader->msgLen, (long unsigned int)sizeof(*threadId));
        return RSC_RESULT_NOT_ENOUGH_DATA;
    }

    if (msgHeader->msgLen > sizeof(gRscInDataBuffer))
    {
        RSC_LOG_ERROR("Error while processing set event request: message payload is too big (%u > %lu)", msgHeader->msgLen, (long unsigned int)sizeof(gRscInDataBuffer));
        return RSC_RESULT_MSG_TOO_BIG;
    }

    if (-1 == RscRecv(gRscInDataBuffer, msgHeader->msgLen))
    {
        RSC_LOG_ERROR("Error while processing set event request: failed to receive message payload");
        return RSC_RESULT_RECV_ERROR;
    }

    memcpy(threadId, gRscInDataBuffer, sizeof(*threadId));
    return RSC_RESULT_OK;
}

RscResult_t RscProcessingSetEventRequest(const RscHeaderMsg_t *msgHeader)
{
    RscResult_t     result;
    uint32_t        threadId;

    RSC_LOG_INFO("Run set event request");

    result = RscRecvPayloadOfSetEventRequest(msgHeader, &threadId);
    if (result == RSC_RESULT_OK)
        result = RscSetEventForThread(threadId);

    /* just return - server should not send any response */
    return result;
}

/*read info, check it for "magic", read requests and processing its*/
void RscProcessingClient(int eventFd)
{
    RscHeaderMsg_t       msgHeader;
    RscHandshakeResult_t resultHandshake;
    RscResult_t          result = RSC_RESULT_OK;

    RSC_LOG_INFO("New client has connected");
    resultHandshake = RscHandshake(eventFd);
    if (resultHandshake != RSC_HANDSHAKE_RESULT_OK)
    {
        RSC_LOG_ERROR("Error %d while handshaking", resultHandshake);
        return;
    }

    /* main processing loop */
    /* if something goes wrong while processing any of requests then the loop should be interrupted
     * to stop communication with the client */
    while (result == RSC_RESULT_OK && !RscIsInterrupted())
    {
        /* wait for message header and go out if it is not received */
        if (-1 == RscRecv(&msgHeader, sizeof(msgHeader)))
        {
            RSC_LOG_ERROR("Error: Recv return error code");
            break;
        }

        RSC_LOG_DEBUG("Message header received: type = 0x%X (%u), len = 0x%X (%u), tid = %u",
            msgHeader.msgType, msgHeader.msgType, msgHeader.msgLen, msgHeader.msgLen, msgHeader.threadId);

        switch(msgHeader.msgType)
        {
        case RSC_MSG_TYPE_SYSCALL_REQUEST:
            result = RscProcessingSyscallRequest(msgHeader);
            break;

        case RSC_MSG_TYPE_MEMCPY_REQUEST:
            result = RscProcessingMemcpyRequest(msgHeader);
            break;

        case RSC_MSG_TYPE_NEW_THREAD_REQUEST:
            result = RscProcessingNewThreadRequest(msgHeader);
            break;

        case RSC_MSG_TYPE_STOP_THREAD_REQUEST:
            result = RscProcessingStopThreadRequest(msgHeader);
            break;

        case RSC_MSG_TYPE_SET_EVENT_REQUEST:
            result = RscProcessingSetEventRequest(&msgHeader);
            break;

        default:
            RSC_LOG_ERROR("Unknown type of request message: %d", msgHeader.msgType);
            result = RSC_RESULT_INVALID_ARGUMENT;
        }
    }

    RSC_LOG_INFO("Stopped client session");
}

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
#include "rsc_protocol.h"

const char * RscResultToStr(RscResult_t result)
{
    static const char strRscResultUnknown[]               = "RSC_RESULT_UNKNOWN";
    static const char strRscResultOk[]                    = "RSC_RESULT_OK";
    static const char strRscResultNotImplementedSyscall[] = "RSC_RESULT_NOT_IMPLEMENTED_SYSCALL";
    static const char strRscResultNotEnoughData[]         = "RSC_RESULT_NOT_ENOUGH_DATA";
    static const char strRscResultNotEnoughParams[]       = "RSC_RESULT_NOT_ENOUGH_PARAMS";
    static const char strRscResultMsgTooBig[]             = "RSC_RESULT_MSG_TOO_BIG";
    static const char strRscInvalidPreAction[]            = "RSC_INVALID_PRE_ACTION";
    static const char strRscInvalidPostAction[]           = "RSC_INVALID_POST_ACTION";
    static const char strRscResultNotEnoughMemory[]       = "RSC_RESULT_NOT_ENOUGH_MEMORY";
    static const char strRscResultWrongOffset[]           = "RSC_RESULT_WRONG_OFFSET";
    static const char strRscResultSendError[]             = "RSC_RESULT_SEND_ERROR";
    static const char strRscResultRecvError[]             = "RSC_RESULT_RECV_ERROR";
    static const char strRscInvalidThreadId[]             = "RSC_INVALID_THREAD_ID";
    static const char strRscThreadsMax[]                  = "RSC_THREADS_MAX";
    static const char strRscThreadsNoExists[]             = "RSC_THREAD_NO_EXISTS";
    static const char strRscMutexInitError[]              = "RSC_MUTEX_INIT_ERROR";
    static const char strRscCondInitError[]               = "RSC_COND_INIT_ERROR";
    static const char strRscThreadInitError[]             = "RSC_THREAD_INIT_ERROR";
    static const char strRscThreadBusy[]                  = "RSC_THREAD_BUSY";
    static const char strRscInvalidResponse[]             = "RSC_INVALID_RESPONSE";
    static const char strRscResultUndefinedError[]        = "RSC_RESULT_UNDEFINED_ERROR";

    switch(result)
    {
    case RSC_RESULT_OK:                      return strRscResultOk;
    case RSC_RESULT_NOT_IMPLEMENTED_SYSCALL: return strRscResultNotImplementedSyscall;
    case RSC_RESULT_NOT_ENOUGH_DATA:         return strRscResultNotEnoughData;
    case RSC_RESULT_NOT_ENOUGH_PARAMS:       return strRscResultNotEnoughParams;
    case RSC_RESULT_MSG_TOO_BIG:             return strRscResultMsgTooBig;
    case RSC_INVALID_PRE_ACTION:             return strRscInvalidPreAction;
    case RSC_INVALID_POST_ACTION:            return strRscInvalidPostAction;
    case RSC_RESULT_NOT_ENOUGH_MEMORY:       return strRscResultNotEnoughMemory;
    case RSC_RESULT_WRONG_OFFSET:            return strRscResultWrongOffset;
    case RSC_RESULT_SEND_ERROR:              return strRscResultSendError;
    case RSC_RESULT_RECV_ERROR:              return strRscResultRecvError;
    case RSC_INVALID_THREAD_ID:              return strRscInvalidThreadId;
    case RSC_THREADS_MAX:                    return strRscThreadsMax;
    case RSC_THREAD_NO_EXISTS:               return strRscThreadsNoExists;
    case RSC_MUTEX_INIT_ERROR:               return strRscMutexInitError;
    case RSC_COND_INIT_ERROR:                return strRscCondInitError;
    case RSC_THREAD_INIT_ERROR:              return strRscThreadInitError;
    case RSC_THREAD_BUSY:                    return strRscThreadBusy;
    case RSC_INVALID_RESPONSE:               return strRscInvalidResponse;
    case RSC_RESULT_UNDEFINED_ERROR:         return strRscResultUndefinedError;
    default:
        return strRscResultUnknown;
    }
}

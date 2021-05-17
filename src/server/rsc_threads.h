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

#ifndef SRC_SERVER_RSC_THREADS_H_
#define SRC_SERVER_RSC_THREADS_H_

#include "rsc_protocol.h"
#include "rsc_malloc.h"

#define MAX_THREAD_NUMBER 200

#define EVENT_WAIT_FD       0
#define EVENT_REPORT_FD     1

typedef struct ThreadData_s
{
    uint32_t           id;
    pthread_t          thread;
    pthread_mutex_t    mutex;
    pthread_cond_t     cond;
    int                eventFds[2];
    uint64_t           eventValue;
    uint8_t           *inDataBuffer;
    uint8_t           *outDataBuffer;
    RscMemForMalloc_t *allocateDataBuffer;
    uint32_t           inDataSize;
    uint32_t           isProcessing;
}ThreadData_t;

extern ThreadData_t threadsData[MAX_THREAD_NUMBER];

/* initialization of mutexes and conditions */
RscResult_t RscThreadsDataInit(void);

/* deinitialization of mutexes and conditions */
RscResult_t RscThreadsDataDeinit(void);

/**
 * Creates thread and all necessary resources.
 *
 * \param[out] pid  Created thread identifier.
 * \param[out] efd  Event file descriptor to use for signalling.
 *
 * \return          Execution result.
 */
RscResult_t RscCreateThread(uint32_t *pid, int *efd);

/*
 * validate thread existing and send a stop signal to the thread
 */
RscResult_t RscStopThread(uint32_t id);

/**
 * Sets event for the remote thread.
 *
 * \param[in]  id   Thread identifier.
 *
 * \return          Execution result.
 */
RscResult_t RscSetEventForThread(uint32_t id);

#endif /* SRC_SERVER_RSC_THREADS_H_ */

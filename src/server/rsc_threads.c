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

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "rsc_protocol.h"
#include "rsc_server.h"
#include "rsc_threads.h"
#include "rsc_proc.h"
#include "rsc_malloc.h"
#include "rsc_logger.h"

#define FREE_AND_NULL(PTR__) \
    do {                     \
        if (NULL != PTR__) { \
            free(PTR__);     \
            PTR__ = NULL;    \
        }                    \
    } while(0)

ThreadData_t threadsData[MAX_THREAD_NUMBER];

RscResult_t RscThreadsDataInit(void)
{
    int id;

    memset(threadsData, 0, sizeof(threadsData));

    for (id = 0; id < MAX_THREAD_NUMBER; id++)
    {
        threadsData[id].id = id;
        threadsData[id].eventFds[EVENT_WAIT_FD] = -1;
        threadsData[id].eventFds[EVENT_REPORT_FD] = -1;

        if (0 != pthread_mutex_init(&threadsData[id].mutex, NULL))
        {
            return RSC_MUTEX_INIT_ERROR;
        }

        if (0 != pthread_cond_init(&threadsData[id].cond, NULL))
        {
            return RSC_COND_INIT_ERROR;
        }
    }
    return RSC_RESULT_OK;
}

RscResult_t RscThreadsDataDeinit(void)
{
    int id;

    for (id = 0; id < MAX_THREAD_NUMBER; id++)
    {
        pthread_mutex_destroy(&threadsData[id].mutex);
        pthread_cond_destroy(&threadsData[id].cond);
    }
    return RSC_RESULT_OK;
}

/*
 * a processing thread. runs and waits signals.
 * if got a stop signal, frees all resources and exits
 * if got a request, processes it
 * */
void * RscProcessingThread(void *inPoint)
{
    ThreadData_t *pD = (ThreadData_t *)inPoint;

    RscLoggerIdentifyThread(pD->id);

    RSC_LOG_INFO("Processing thread #%d (thread = %lu) has started", pD->id, (long unsigned)pD->thread);
    while (1)
    {
        pthread_mutex_lock(&pD->mutex);
        while (!pD->isProcessing)
            pthread_cond_wait(&pD->cond, &pD->mutex);

        if (0 == pD->inDataSize)
        {
            /* we've got a stop command */
            break;
        }

        pthread_mutex_unlock(&pD->mutex);

        RscProcessingSyscallRequestThread(pD);
    }

    RSC_LOG_INFO("Processing thread #%d (thread = %lu) stopped", pD->id, (long unsigned)pD->thread);
    if (pD->eventFds[EVENT_WAIT_FD] != pD->eventFds[EVENT_REPORT_FD])
        close(pD->eventFds[EVENT_REPORT_FD]);
    close(pD->eventFds[EVENT_WAIT_FD]);
    pD->eventFds[EVENT_WAIT_FD] = -1;
    pD->eventFds[EVENT_REPORT_FD] = -1;
    pD->thread = 0;
    pD->isProcessing = 0;
    FREE_AND_NULL(pD->inDataBuffer);
    FREE_AND_NULL(pD->outDataBuffer);
    FREE_AND_NULL(pD->allocateDataBuffer);

    pthread_mutex_unlock(&pD->mutex);

    return NULL;
}

/*
 * Creates thread and all necessary resources.
 *
 * Returns result, an id of the started thread and event file descriptor
 */
RscResult_t RscCreateThread(uint32_t *pid, int *efd)
{
    uint32_t id;
    void *buffer = NULL;

    for (id = 0; id < MAX_THREAD_NUMBER; id++)
    {
        /* if mutex is busy then thread is processing of syscall now*/
        if (EBUSY == pthread_mutex_trylock(&threadsData[id].mutex))
            continue;
        if (0 == threadsData[id].thread)
            break;
        pthread_mutex_unlock(&threadsData[id].mutex);
    }

    if (id >= MAX_THREAD_NUMBER)
        return RSC_THREADS_MAX;

    /*open eventfd OR socketpair OR pipe for threads synchronization*/
    threadsData[id].eventFds[EVENT_WAIT_FD] = eventfd(0, 0);
    if (-1 != threadsData[id].eventFds[EVENT_WAIT_FD])
    {
        threadsData[id].eventFds[EVENT_REPORT_FD] = threadsData[id].eventFds[EVENT_WAIT_FD];
        RSC_LOG_INFO("\"eventfd\" is used for threads synchronization");
    }
    else if (-1 != socketpair(AF_UNIX, SOCK_DGRAM, 0, threadsData[id].eventFds))
    {
        RSC_LOG_INFO("\"socketpair\" is used for threads synchronization");
    }
    else if (-1 != pipe(threadsData[id].eventFds))
    {
        RSC_LOG_INFO("\"pipe\" is used for threads synchronization");
    }
    else
    {
        return RSC_EVENT_INIT_ERROR;
    }
    threadsData[id].eventValue = 0;

    buffer = malloc(MAX_DATA_SIZE);
    if (buffer)
    {
        threadsData[id].inDataBuffer = buffer;
        buffer = malloc(MAX_DATA_SIZE);
        if (buffer)
        {
            threadsData[id].outDataBuffer = buffer;
            buffer = RscMallocBuf();
            if (buffer)
                threadsData[id].allocateDataBuffer = buffer;
        }
    }

    if (!buffer)
    {
        FREE_AND_NULL(threadsData[id].inDataBuffer);
        FREE_AND_NULL(threadsData[id].outDataBuffer);
        if (threadsData[id].eventFds[EVENT_WAIT_FD] != threadsData[id].eventFds[EVENT_REPORT_FD])
            close(threadsData[id].eventFds[EVENT_REPORT_FD]);
        close(threadsData[id].eventFds[EVENT_WAIT_FD]);
        threadsData[id].eventFds[EVENT_WAIT_FD] = -1;
        threadsData[id].eventFds[EVENT_REPORT_FD] = -1;
        pthread_mutex_unlock(&threadsData[id].mutex);
        return RSC_RESULT_NOT_ENOUGH_MEMORY;
    }

    threadsData[id].isProcessing = 0;

    if (0 != pthread_create(&threadsData[id].thread, NULL, RscProcessingThread, &threadsData[id]))
    {
        FREE_AND_NULL(threadsData[id].inDataBuffer);
        FREE_AND_NULL(threadsData[id].outDataBuffer);
        FREE_AND_NULL(threadsData[id].allocateDataBuffer);
        threadsData[id].thread = 0;
        if (threadsData[id].eventFds[EVENT_WAIT_FD] != threadsData[id].eventFds[EVENT_REPORT_FD])
            close(threadsData[id].eventFds[EVENT_REPORT_FD]);
        close(threadsData[id].eventFds[EVENT_WAIT_FD]);
        threadsData[id].eventFds[EVENT_WAIT_FD] = -1;
        threadsData[id].eventFds[EVENT_REPORT_FD] = -1;
        pthread_mutex_unlock(&threadsData[id].mutex);
        return RSC_THREAD_INIT_ERROR;
    }

    pthread_detach(threadsData[id].thread);
    pthread_mutex_unlock(&threadsData[id].mutex);

    *pid = id;
    *efd = threadsData[id].eventFds[EVENT_WAIT_FD];

    return RSC_RESULT_OK;
}

/*
 * validate thread existing and send a stop signal to the thread
 * */
RscResult_t RscStopThread(uint32_t id)
{
    if (id >= MAX_THREAD_NUMBER)
        return RSC_INVALID_THREAD_ID;

    if (0 != pthread_mutex_lock(&threadsData[id].mutex))
        return RSC_MUTEX_INIT_ERROR;

    if (threadsData[id].isProcessing)
        return RSC_THREAD_BUSY;

    if (0 == threadsData[id].thread)
        return RSC_THREAD_NO_EXISTS;

    threadsData[id].isProcessing = 1;
    threadsData[id].inDataSize = 0;

    pthread_cond_signal(&threadsData[id].cond);
    pthread_mutex_unlock(&threadsData[id].mutex);

    return RSC_RESULT_OK;
}

static RscResult_t SetEventForThread(ThreadData_t *threadData)
{
    const uint64_t value = 1;

    if (!threadData->isProcessing)
        return RSC_RESULT_OK;

    if (0 == threadData->thread)
        return RSC_THREAD_NO_EXISTS;

    if (!threadData->eventValue)
    {
        if (sizeof(uint64_t) != write(threadData->eventFds[EVENT_REPORT_FD], &value, sizeof(uint64_t)))
            return RSC_RESULT_EVENT_IO_ERROR;

        threadData->eventValue += value;
    }

    return RSC_RESULT_OK;
}

RscResult_t RscSetEventForThread(uint32_t id)
{
    RscResult_t result;

    if (id >= MAX_THREAD_NUMBER)
        return RSC_INVALID_THREAD_ID;

    if (0 != pthread_mutex_lock(&threadsData[id].mutex))
        return RSC_MUTEX_INIT_ERROR;

    result = SetEventForThread(&threadsData[id]);
    pthread_mutex_unlock(&threadsData[id].mutex);
    return result;
}


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
#define _GNU_SOURCE  /* => _POSIX_C_SOURCE >= 199309L */

#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* File output support */
#include <linux/limits.h>
#include <stdint.h>

#include "rsc_logger.h"

#include "rsc_tls.h"


typedef short MessageSize_t;

#define LOG_MESSAGE_BUFFER_SIZE   (MAX_LOG_MESSAGE_SIZE + sizeof(MessageSize_t))
#define LOG_IDENTITY_SIZE         (16)
#define LOG_IDENTITIES_UU_FORMAT  "%5u|%5u"
#define LOG_IDENTITIES_US_FORMAT  "%5u|%5s"

#define LOG_CONF_DEFAULTS  {                  \
        .fileName        = "",                \
        .logToConsole    = 1,                 \
        .logToFile       = 0,                 \
        .fileSizeLimit   = MAX_LOG_FILE_SIZE, \
        .rotateFileCount = 1                  \
    }

enum {
    READABLE_PIPE_END_ID = 0,
    WRITABLE_PIPE_END_ID = 1
};

#define readablePipeEnd  pipeEnds[READABLE_PIPE_END_ID]
#define writablePipeEnd  pipeEnds[WRITABLE_PIPE_END_ID]

typedef struct Logger_s
{
    LogConf_t  conf;
    size_t     fileNameLength;
    FILE      *file;
    int        pipeEnds[2];
    pthread_t  loggerThread;
} Logger_t;

typedef struct LogThreadData_s
{
    char identity[LOG_IDENTITY_SIZE];
} LogThreadData_t;


static void InitLogThreadData(LogThreadData_t *value);

DEFINE_AS_THREAD_LOCAL(LogThreadData_t, LogThreadData, InitLogThreadData)

static LogLevels  gLogLevels = RSC_LOG_LEVEL_ERROR_MASK;

static FILE      *gLogStream = NULL;

static Logger_t   gLogger    = {
    .conf           = LOG_CONF_DEFAULTS,
    .fileNameLength = 0,
    .file           = NULL,
    .pipeEnds       = {-1, -1}
};


static void InitLogThreadData(LogThreadData_t *value)
{
    snprintf(value->identity, sizeof(value->identity), LOG_IDENTITIES_US_FORMAT, getpid(), "-");
}
/*--------------------------------------------------------------------------*/
static FILE * GetLogStream(void)
{
    if (gLogStream)
        return gLogStream;
    return stdout;
}
/*--------------------------------------------------------------------------*/
static void CloseLoggerPipe(void)
{
    close(gLogger.readablePipeEnd);
    close(gLogger.writablePipeEnd);
    gLogger.readablePipeEnd = -1;
    gLogger.writablePipeEnd = -1;
}
/*--------------------------------------------------------------------------*/
/* file output support */
/*--------------------------------------------------------------------------*/
static void LogFilesCleanup(void)
{
    uint32_t i;
    char     name[MAX_LOG_FILE_PATH_SIZE + LOG_ROTATION_SUFFIX_LENGTH];

    if(!gLogger.conf.rotateFileCount || gLogger.conf.rotateFileCount >= MAX_LOG_ROTATE_FILE_COUNT)
        return;

    for(i = gLogger.conf.rotateFileCount + 1; i <= MAX_LOG_ROTATE_FILE_COUNT; ++i)
    {
        if (sprintf(name, "%s.%u", gLogger.conf.fileName, i) > 0)
        {
            name[sizeof(name) - 1] = '\0';
            unlink(name);
        }
    }
}
/*--------------------------------------------------------------------------*/
static int LogFileOpen(void)
{
    if (!gLogger.conf.logToFile)
        return 0;

    if (NULL != gLogger.file)
        return 0;

    gLogger.file = fopen(gLogger.conf.fileName, "a");
    if (NULL == gLogger.file)
    {
        fprintf(stderr, "Failed to open file '%s' for appending (%d: %s)\n", gLogger.conf.fileName, errno, strerror(errno));
        return 1;
    }
    else
    {
        setvbuf(gLogger.file, NULL, _IOLBF, BUFSIZ);  /* _IOLBF - line buffering */
    }
    return 0;
}
/*--------------------------------------------------------------------------*/
static void LogFileClose(void)
{
    if (NULL == gLogger.file)
        return;

    fflush(gLogger.file);
    fclose(gLogger.file);
    gLogger.file = NULL;
}
/*--------------------------------------------------------------------------*/
static void LogFileRotateIfNeeded(size_t addedSize)
{
    static const char digits[] = "0123456789";

    uint32_t i;
    uint32_t j;
    uint32_t suffixPos = gLogger.fileNameLength;
    char     name[2][MAX_LOG_FILE_PATH_SIZE + LOG_ROTATION_SUFFIX_LENGTH];
    long     filePos;

    if (NULL == gLogger.file)
        return;

    filePos = ftell(gLogger.file);
    if (-1 == filePos)
    {
        fprintf(stderr, "Failed to get log file position (%d: %s)", errno, strerror(errno));
        return;
    }

    if (!gLogger.conf.fileSizeLimit || filePos + (long)addedSize <= gLogger.conf.fileSizeLimit)
        return;

    LogFileClose();

    for (j = 0; j < 2; ++j)
    {
        strcpy(name[j], gLogger.conf.fileName);
        name[j][suffixPos] = '.';
        name[j][suffixPos + LOG_ROTATION_SUFFIX_LENGTH] = '\0';
    }

    ++suffixPos;
    name[0][suffixPos] = digits[gLogger.conf.rotateFileCount];

    for(j = 1, i = gLogger.conf.rotateFileCount - 1; i > 0; j = 1 - j, --i)
    {
        name[j][suffixPos] = digits[i];
        rename(name[j], name[1 - j]);
    }

    name[j][suffixPos - 1] = '\0';
    rename(name[j], name[1 - j]);

    LogFileOpen();
}
/*--------------------------------------------------------------------------*/
static void LogWriteToFile(const char *message, size_t size)
{
    if (NULL == gLogger.file)
        LogFileOpen();

    if (NULL != gLogger.file)
    {
        LogFileRotateIfNeeded(size + 1);
        fprintf(gLogger.file, "%s\n", message);
    }
}
/*--------------------------------------------------------------------------*/
/* Log worker */
/*--------------------------------------------------------------------------*/
static void LogWrite(const char *message, size_t size)
{
    if (gLogger.conf.logToConsole)
        fprintf(GetLogStream(), "%s\n", message);

    if (gLogger.conf.logToFile)
        LogWriteToFile(message, size);
}
/*--------------------------------------------------------------------------*/
static void * LoggingThread(void *arg)
{
    char           buffer[MAX_LOG_MESSAGE_SIZE] = {0};
    Logger_t      *conf  = (Logger_t *)arg;
    int            logFd = conf->readablePipeEnd;
    ssize_t        count = 0;
    MessageSize_t  size;

    if (gLogger.conf.logToFile)
    {
        LogFilesCleanup();
        LogFileOpen();
    }

    for (;;)
    {
        count = read(logFd, &size, sizeof(size));
        if (count != sizeof(size))
        {
            fprintf(stderr, "-- log: failed to read message size (count: %ld)\n", (long)count);
            break;
        }

        if (!size)
            break;  /* signal to interrupt */

        if (size < 0 || size > MAX_LOG_MESSAGE_SIZE)
        {
            fprintf(stderr, "-- log: invalid message size (size: %d)\n", size);
            break;
        }

        count = read(logFd, buffer, size);
        if (count != size)
        {
            fprintf(stderr, "-- log: failed to read message of size %d (read count: %ld)\n", size, (long)count);
            break;
        }

        LogWrite(buffer, size);
    }

    if (gLogger.conf.logToFile)
        LogFileClose();

    return NULL;
}
/*--------------------------------------------------------------------------*/
/* Interface functions */
/*--------------------------------------------------------------------------*/
void RscLoggerSetLevels(LogLevels logLevels)
{
    gLogLevels = logLevels | RSC_LOG_LEVEL_ERROR_MASK;
}
/*--------------------------------------------------------------------------*/
int  RscIsAllowedLogLevel(LogLevel logLevel)
{
    return gLogLevels & logLevel ? 1: 0;
}
/*--------------------------------------------------------------------------*/
void RscLoggerIdentifyThread(uint32_t id)
{
    LogThreadData_t *logThreadData = GetLogThreadData();
    if (UINT32_MAX == id)
        snprintf(logThreadData->identity, sizeof(logThreadData->identity), LOG_IDENTITIES_US_FORMAT, getpid(), "main");
    else
        snprintf(logThreadData->identity, sizeof(logThreadData->identity), LOG_IDENTITIES_UU_FORMAT, getpid(), id);
}
/*--------------------------------------------------------------------------*/
const char * RscLoggerGetThreadIdentity(void)
{
    return GetLogThreadData()->identity;
}
/*--------------------------------------------------------------------------*/
void RscGetTime(long *sec, int *msec)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    *sec  = ts.tv_sec;
    *msec = (int)(ts.tv_nsec / 1000000);
}
/*--------------------------------------------------------------------------*/
void RscLogMessage(const char *format, ...)
{
    char          buffer[LOG_MESSAGE_BUFFER_SIZE];
    va_list       vaList;
    MessageSize_t strLen = 0;

    va_start(vaList, format);
    strLen = vsnprintf(buffer + sizeof(MessageSize_t), MAX_LOG_MESSAGE_SIZE, format, vaList);
    va_end(vaList);

    strLen = (strLen >= MAX_LOG_MESSAGE_SIZE) ? MAX_LOG_MESSAGE_SIZE : strLen + 1;
    if (strLen > 1)  /* Send if final message contains not only the 0-terminator */
    {
        if (-1 == gLogger.writablePipeEnd)
        {
            fprintf(GetLogStream(), "%s\n", buffer + sizeof(MessageSize_t));
        }
        else
        {
            memcpy(buffer, &strLen, sizeof(strLen));
            write(gLogger.writablePipeEnd, buffer, sizeof(strLen) + strLen);
        }
    }
}
/*--------------------------------------------------------------------------*/
LogConf_t * RscLoggerConf(void)
{
    return &gLogger.conf;
}
/*--------------------------------------------------------------------------*/
int RscLoggerStart(void)
{
    if (gLogger.conf.logToFile)
        gLogger.fileNameLength = strlen(gLogger.conf.fileName);
    else
        gLogger.fileNameLength = 0;

    if (-1 == pipe(gLogger.pipeEnds))
    {
        fprintf(stderr, "Failed to create pipe for logging (%d: %s)\n", errno, strerror(errno));
        return 0;
    }

    if (LogFileOpen()) {
        fprintf(stderr, "Failed to start logging thread (%d: %s)\n", errno, strerror(errno));
        return 0;
    }

    if (0 != pthread_create(&gLogger.loggerThread, NULL, LoggingThread, &gLogger))
    {
        fprintf(stderr, "Failed to start logging thread (%d: %s)\n", errno, strerror(errno));
        CloseLoggerPipe();
        return 0;
    }

    return 1;
}
/*--------------------------------------------------------------------------*/
void RscLoggerStop(void)
{
    static const MessageSize_t termMsg = 0;

    if (-1 != gLogger.writablePipeEnd)
    {
        write(gLogger.writablePipeEnd, &termMsg, sizeof(termMsg));
        pthread_join(gLogger.loggerThread, NULL);
    }

    CloseLoggerPipe();
}
/*--------------------------------------------------------------------------*/
void RscLoggerChildProcessSetup(void)
{
    if (-1 != gLogger.readablePipeEnd)
    {
        close(gLogger.readablePipeEnd);
        gLogger.readablePipeEnd = -1;
    }
}

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
#ifndef RSC_LOGGER_H_
#define RSC_LOGGER_H_

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <linux/limits.h>
#include <unistd.h>


#define MAX_LOG_MESSAGE_SIZE    510

/* Logger level flag masks */
#define RSC_LOG_LEVEL_WARN_MASK   1U
#define RSC_LOG_LEVEL_INFO_MASK   2U
#define RSC_LOG_LEVEL_DEBUG_MASK  4U
#define RSC_LOG_LEVEL_ERROR_MASK  8U

/* Logger level string tags */
#define RSC_LOG_LEVEL_WARN_STR   "WRN: "
#define RSC_LOG_LEVEL_INFO_STR   "INF: "
#define RSC_LOG_LEVEL_DEBUG_STR  "DBG: "
#define RSC_LOG_LEVEL_ERROR_STR  "ERR: "

#define FILENAME  (strrchr("/" __FILE__, '/') + 1)

#define RSC_LOG_FORMAT(LEVEL__) \
    "%8ld.%03d|%s|" LEVEL__##_STR "%s @%s:%d"

#define RSC_LOG_ERRNO_FORMAT \
    "%8ld.%03d|%s|" RSC_LOG_LEVEL_ERROR_STR "%s (%d: %s) @%s:%d"


#define RSC_DECLARE_TIME_VALUE  \
    long sec__;                 \
    int  msec__;                \
    RscGetTime(&sec__, &msec__)

#define RSC_TIME_VALUE_SEC   (sec__)
#define RSC_TIME_VALUE_MSEC  (msec__)


#define RSC_LOG_(LEVEL__, ...)                                              \
    do {                                                                    \
        if (RscIsAllowedLogLevel(LEVEL__##_MASK)) {                         \
            RSC_DECLARE_TIME_VALUE;                                         \
            char str[MAX_LOG_MESSAGE_SIZE] = {0};                           \
            snprintf(str, sizeof(str), __VA_ARGS__);                        \
            RscLogMessage(RSC_LOG_FORMAT(LEVEL__),                          \
                RSC_TIME_VALUE_SEC,                                         \
                RSC_TIME_VALUE_MSEC,                                        \
                RscLoggerGetThreadIdentity(),                               \
                str,                                                        \
                FILENAME,                                                   \
                __LINE__                                                    \
            );                                                              \
        }                                                                   \
    } while (0)

#define RSC_LOG_ERRNO(...)                                                  \
    do {                                                                    \
        if (RscIsAllowedLogLevel(RSC_LOG_LEVEL_ERROR_MASK)) {               \
            RSC_DECLARE_TIME_VALUE;                                         \
            char str[MAX_LOG_MESSAGE_SIZE] = {0};                           \
            snprintf(str, sizeof(str), __VA_ARGS__);                        \
            RscLogMessage(RSC_LOG_ERRNO_FORMAT,                             \
                RSC_TIME_VALUE_SEC,                                         \
                RSC_TIME_VALUE_MSEC,                                        \
                RscLoggerGetThreadIdentity(),                               \
                str,                                                        \
                errno,                                                      \
                strerror(errno),                                            \
                FILENAME,                                                   \
                __LINE__                                                    \
            );                                                              \
        }                                                                   \
    } while (0)

/* Log printing macros.
 * Use printf syntax.
 * For example: RSC_LOG_INFO("some format %d %s", someStr, someInt).
 */
#ifdef RSC_NO_LOGGER
    #define RSC_LOG_DEBUG(...)
    #define RSC_LOG_INFO(...)
    #define RSC_LOG_WARN(...)
#else
    #define RSC_LOG_DEBUG(...)  RSC_LOG_(RSC_LOG_LEVEL_DEBUG, __VA_ARGS__)
    #define RSC_LOG_INFO(...)   RSC_LOG_(RSC_LOG_LEVEL_INFO, __VA_ARGS__)
    #define RSC_LOG_WARN(...)   RSC_LOG_(RSC_LOG_LEVEL_WARN, __VA_ARGS__)
#endif

/* Error logs are printed always and independently from flags and settings */
#define RSC_LOG_ERROR(...)  RSC_LOG_(RSC_LOG_LEVEL_ERROR, __VA_ARGS__)


typedef unsigned long  LogLevels;
typedef unsigned long  LogLevel;

/*
 * Definitions for file output support
 */
#define LOG_ROTATION_SUFFIX_LENGTH 2
#define MAX_LOG_ROTATE_FILE_COUNT  9
#define MAX_LOG_FILE_PATH_SIZE     (PATH_MAX - LOG_ROTATION_SUFFIX_LENGTH)
#define MAX_LOG_FILE_SIZE          INT32_MAX
#define MIN_LOG_FILE_SIZE          4096

#define MAIN_THREAD_ID             UINT32_MAX

typedef struct LogConf_s
{
    char             fileName[MAX_LOG_FILE_PATH_SIZE];
    int              logToConsole;
    int              logToFile;
    long             fileSizeLimit;
    long             rotateFileCount;
} LogConf_t;

void RscLoggerSetLevels(LogLevels logLevels);

int  RscIsAllowedLogLevel(LogLevel logLevel);

/**
 * Returns current time in form of seconds plus milliseconds since some
 * starting point.
 *
 * \param[out] sec   Seconds value
 * \param[out] msec  Milliseconds value
 */
void RscGetTime(long *sec, int *msec);

/**
 * Prints log message based on printf-like format and variable arguments.
 *
 * \param[in] format    Message printf-like format string
 * \param[in] ...       Optional arguments with values for provided format
 */
void RscLogMessage(const char *format, ...);

/**
 * Sets the thread specific identifier to appear in log messages.
 *
 * \param id  Thread identifier
 */
void RscLoggerIdentifyThread(uint32_t id);

/**
 *
 * \return    Thread identifier as string
 */
const char * RscLoggerGetThreadIdentity(void);

/**
 * Provides access to the logger configuration allowing its modification.
 *
 * Configuration shouldn't be changed after the logger is started
 * (after the call to RscLoggerStart()).
 *
 * \return  Pointer to the logger configuration
 */
LogConf_t * RscLoggerConf(void);

/**
 * Starts a logger.
 *
 * Function should be called once in the main process before any usage of
 * RscLogMessage() function or RSC_LOG_X() macros.
 *
 * \return          1 if logger was successfully started, 0 - otherwise
 */
int  RscLoggerStart(void);

/**
 * Stops the logger.
 */
void RscLoggerStop(void);

/**
 * Function should be called after fork() in child process to clean up some
 * resources.
 */
void RscLoggerChildProcessSetup(void);

#endif  /* RSC_LOGGER_H_ */

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
#ifndef RSC_TLS_H_
#define RSC_TLS_H_

#define EXIT_STATUS_TLS_ERROR  3

#ifdef USE_PTHREAD_LOCAL
    #include <pthread.h>
    #include <stdlib.h>

    #define DEFINE_AS_THREAD_LOCAL(TYPE__, NAME__, INIT__)           \
        static pthread_key_t keyTo##NAME__;                          \
                                                                     \
        static void NAME__##Destroy(void *value)                     \
        {                                                            \
            if (value == NULL)                                       \
                return;                                              \
            free(value);                                             \
        }                                                            \
                                                                     \
        static void NAME__##Init(void)                               \
        {                                                            \
            if (pthread_key_create(&keyTo##NAME__, NAME__##Destroy)) \
                exit(EXIT_STATUS_TLS_ERROR);                         \
        }                                                            \
                                                                     \
        static TYPE__ * Get##NAME__(void)                            \
        {                                                            \
            static pthread_once_t  once   = PTHREAD_ONCE_INIT;       \
            TYPE__                *value;                            \
                                                                     \
            pthread_once(&once, NAME__##Init);                       \
            value = pthread_getspecific(keyTo##NAME__);              \
            if (value == NULL)                                       \
            {                                                        \
                value = malloc(sizeof(TYPE__));                      \
                if (pthread_setspecific(keyTo##NAME__, value))       \
                    exit(EXIT_STATUS_TLS_ERROR);                     \
                INIT__(value);                                       \
            }                                                        \
                                                                     \
            return value;                                            \
        }
#else
    /* use C implementation support for thread-local storage */
    #define THREAD_LOCAL __thread

    #define DEFINE_AS_THREAD_LOCAL(TYPE__, NAME__, INIT__)           \
        static TYPE__ * Get##NAME__(void)                            \
        {                                                            \
            static THREAD_LOCAL int    once = 0;                     \
            static THREAD_LOCAL TYPE__ value;                        \
            if (!once)                                               \
            {                                                        \
                INIT__(&value);                                      \
                once = 1;                                            \
            }                                                        \
            return &value;                                           \
        }
#endif

#define DECLARE_AS_THREAD_LOCAL(TYPE__, NAME)                        \
    TYPE__ * Get##NAME(void);

#endif  /* RSC_TLS_H_ */

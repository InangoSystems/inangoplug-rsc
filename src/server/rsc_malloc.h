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

#ifndef SERVER_RSC_MALLOC_H_
#define SERVER_RSC_MALLOC_H_

#include <stdint.h>

#define MAX_SIZE_MEM_BUF 65535

typedef struct
{
    uintptr_t cur;
    uint8_t buf[MAX_SIZE_MEM_BUF];
} RscMemForMalloc_t;

/*resets all allocation of memory in global buffer*/
void RscResetMemBuf(RscMemForMalloc_t *pMemBuf);

/*simple memory allocation. allocates size bytes in global buffer*/
uint8_t* RscMalloc(RscMemForMalloc_t *pMemBuf, uintptr_t size);

/*dynamic allocate memory for later using with functions RscMalloc and RscResetMemBuf*/
RscMemForMalloc_t* RscMallocBuf(void);

#endif /* SERVER_RSC_MALLOC_H_ */

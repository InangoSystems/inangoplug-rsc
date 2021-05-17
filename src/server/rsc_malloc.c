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

#include <string.h>
#include <stdlib.h>
#include "rsc_malloc.h"


static RscMemForMalloc_t gMemBuf = {
	0,{0}
};

/*simple memory allocation. allocates 'size' bytes in buffer pMemBuf*/
/*used memory size saves in the buffer beginning*/
/*if pMemBuf = 0 then used the global buffer 'gMemBuf'*/
/*each allocated memory immediately follows the previously allocated memory. This is important, it uses in code*/
uint8_t* RscMalloc(RscMemForMalloc_t *pMemBuf, uintptr_t size)
{
    uint8_t *ret;

    if (pMemBuf == 0)
        pMemBuf = &gMemBuf;

    if (pMemBuf->cur + size <= MAX_SIZE_MEM_BUF)
    {
        ret = &pMemBuf->buf[pMemBuf->cur];
        pMemBuf->cur += size;
        return ret;
    }

    return 0;
}

/*resets all allocation of memory in buffer */
/*if pMemBuf = 0 then used the global buffer 'gMemBuf'*/
void RscResetMemBuf(RscMemForMalloc_t *pMemBuf)
{
    if (pMemBuf == 0)
        pMemBuf = &gMemBuf;
    memset(pMemBuf, 0, sizeof(RscMemForMalloc_t));
}

/*dynamic allocate memory for later using with functions RscMalloc and RscResetMemBuf*/
RscMemForMalloc_t* RscMallocBuf(void)
{
    return malloc(sizeof(RscMemForMalloc_t));
}

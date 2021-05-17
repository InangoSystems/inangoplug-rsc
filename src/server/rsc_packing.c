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
#include "rsc_packing.h"
#include "rsc_malloc.h"

/*pack parameter "source" to buffer "dest". "size" - size of variable (or value for RSC_PARAM_TYPE_VALUE), "type" - type of parameter
 * preAddon, postAddon - information about allocated memory during processing of the pre/post executed actions
 * function creates description of parameter, fill him, put him to buffer, and put parameter if it is necessary
 * returns a size of used memory in buffer*/
uint32_t RscPackParameter(uint8_t *dest, const uint8_t* source, uint32_t size, RscParamType_t type, RscParamAddons_t preAddon, RscParamAddons_t postAddon)
{
    uint32_t outSize = 0;
    RscDescParam_t desc;

    desc.type = type;
    switch (type)
    {
    case RSC_PARAM_TYPE_VALUE:
        desc.size = (uintptr_t) source;
        memcpy(dest, &desc, sizeof(desc));
        outSize = sizeof(desc);
        break;

    case RSC_PARAM_TYPE_PTR_IN_OUT:
    case RSC_PARAM_TYPE_PTR_OUT:
    case RSC_PARAM_TYPE_PTR_RETURN:
        desc.size = size + preAddon.size + postAddon.size;
        memcpy(dest, &desc, sizeof(desc));
        memcpy(dest + sizeof(desc), source, size);
        memcpy(dest + sizeof(desc) + size, (uint8_t *)preAddon.p, preAddon.size);
        memcpy(dest + sizeof(desc) + size + preAddon.size, (uint8_t *)postAddon.p, postAddon.size);
        outSize = sizeof(desc) + SizeAligned32(desc.size);
        break;

    case RSC_PARAM_TYPE_PTR_IN:
        break;

    default:
        /*TO DO: here we must handle unknown type of parameter*/
        break;
    }

    return outSize;
}

/*unpack parameter. prepare a parameter for using. "desc" - pointer to parameter description
 * "size" - number of bytes in array of data
 * "arg" - return value by pointer equal either value or pointer to parameter depend on type of parameter
 * "nextDesc" - return value by pointer equal pointer to the next descriptor
 * "allocBuf" - pointer at buffer for allocation variables
 * returns status of unpacking*/
RscResult_t RscUnpackParameter(RscDescParam_t *desc, const uint32_t size, uintptr_t *arg, RscDescParam_t **nextDesc, RscMemForMalloc_t *allocBuf)
{
    RscResult_t res = RSC_RESULT_OK;

    if (size < sizeof(*desc))
        res = RSC_RESULT_NOT_ENOUGH_DATA;
    else
    {
        switch (desc->type)
        {
        case RSC_PARAM_TYPE_VALUE:
            *arg = desc->size;
            *nextDesc = desc+1;
            break;

        case RSC_PARAM_TYPE_PTR_IN_OUT:
        case RSC_PARAM_TYPE_PTR_IN:
            if (size - sizeof(*desc) < desc->size)
            {
                res = RSC_RESULT_NOT_ENOUGH_DATA;
                break;
            }
            *arg = (uintptr_t)(desc+1);
            *nextDesc = (RscDescParam_t*)(*arg + SizeAligned32(desc->size));
            break;

        case RSC_PARAM_TYPE_PTR_OUT:
            *arg = (uintptr_t)RscMalloc(allocBuf, desc->size);
            if (!(*arg))
                res = RSC_RESULT_UNDEFINED_ERROR;/*TODO: add new type of error. CANT_ALLOCATE*/
            *nextDesc = desc+1;
            break;

        case RSC_PARAM_TYPE_PTR_RETURN:
            *nextDesc = desc+1;
            break;

        default:
            res = RSC_RESULT_NOT_IMPLEMENTED_SYSCALL;
        }
    }

    return res;
}

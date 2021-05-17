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

#ifndef SERVER_RSC_PACKING_H_
#define SERVER_RSC_PACKING_H_

#include "rsc_protocol.h"
#include "rsc_malloc.h"

/*struct for saving data about the data which the actions allocate*/
typedef struct RscParamAddons_s
{
    uintptr_t p;
    uint32_t size;
} RscParamAddons_t;

/*pack parameter "source" to buffer "dest". "size" - size of variable, "type" - type of parameter
 * preAddon, postAddon - information about allocated memory during processing of the pre/post executed actions
 * function creates description of parameter, fill him, put him to buffer, and put parameter if it is necessary
 * returns a size of used memory in buffer*/
uint32_t RscPackParameter(uint8_t *dest, const uint8_t* source, uint32_t size, RscParamType_t type, RscParamAddons_t preAddon, RscParamAddons_t postAddon);

/*unpack parameter. prepare a parameter for using. "desc" - pointer to parameter description
 * "size" - number of bytes in array of data
 * "arg" - return value by pointer equal either value or pointer to parameter depend on type of parameter
 * "nextDesc" - return value by pointer equal pointer to the next descriptor
 * "allocBuf" - pointer at buffer for allocation variables
 * returns status of unpacking*/
RscResult_t RscUnpackParameter(RscDescParam_t *desc, const uint32_t size, uintptr_t *arg, RscDescParam_t **nextDesc, RscMemForMalloc_t *allocBuf);

#endif /* SERVER_RSC_PACKING_H_ */

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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include "rsc_syscall.h"

/*defines signatures of syscalls*/
static uintptr_t (*fv)(void) = NULL;
static uintptr_t (*fl)(uintptr_t) = NULL;
static uintptr_t (*fl2)(uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl3)(uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl4)(uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl5)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl6)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl7)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl8)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl9)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl10)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl11)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl12)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl13)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl14)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl15)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl16)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl17)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl18)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl19)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;
static uintptr_t (*fl20)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = NULL;

/*running of necessary syscall*/
RscResult_t RscSyscallFunction(const char* name, uint32_t num_param, const uintptr_t *params, uintptr_t *ret)
{
    void *fPtr = NULL;

    /*try to find necessary function*/
    fPtr = dlsym(RTLD_NEXT, name);

    if (fPtr == NULL)
        return RSC_RESULT_NOT_IMPLEMENTED_SYSCALL;

    switch (num_param)
    {
        case 0: *(void **)(&fv) = fPtr;
            *ret = fv();
            break;
        case 1: *(void **)(&fl) = fPtr;
            *ret = fl(params[0]);
            break;
        case 2: *(void **)(&fl2) = fPtr;
            *ret = fl2(params[0], params[1]);
            break;
        case 3: *(void **)(&fl3) = fPtr;
            *ret = fl3(params[0], params[1], params[2]);
            break;
        case 4: *(void **)(&fl4) = fPtr;
            *ret = fl4(params[0], params[1], params[2], params[3]);
            break;
        case 5: *(void **)(&fl5) = fPtr;
            *ret = fl5(params[0], params[1], params[2], params[3], params[4]);
            break;
        case 6: *(void **)(&fl6) = fPtr;
            *ret = fl6(params[0], params[1], params[2], params[3], params[4], params[5]);
            break;
        case 7: *(void **)(&fl7) = fPtr;
            *ret = fl7(params[0], params[1], params[2], params[3], params[4], params[5], params[6]);
            break;
        case 8: *(void **)(&fl8) = fPtr;
            *ret = fl8(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7]);
            break;
        case 9: *(void **)(&fl9) = fPtr;
            *ret = fl9(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8]);
            break;
        case 10: *(void **)(&fl10) = fPtr;
            *ret = fl10(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9]);
            break;
        case 11: *(void **)(&fl11) = fPtr;
            *ret = fl11(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10]);
            break;
        case 12: *(void **)(&fl12) = fPtr;
            *ret = fl12(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11]);
            break;
        case 13: *(void **)(&fl13) = fPtr;
            *ret = fl13(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12]);
            break;
        case 14: *(void **)(&fl14) = fPtr;
            *ret = fl14(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13]);
            break;
        case 15: *(void **)(&fl15) = fPtr;
            *ret = fl15(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13], params[14]);
            break;
        case 16: *(void **)(&fl16) = fPtr;
            *ret = fl16(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13], params[14], params[15]);
            break;
        case 17: *(void **)(&fl16) = fPtr;
            *ret = fl17(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13], params[14], params[15], params[16]);
            break;
        case 18: *(void **)(&fl16) = fPtr;
            *ret = fl18(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13], params[14], params[15], params[16], params[17]);
            break;
        case 19: *(void **)(&fl16) = fPtr;
            *ret = fl19(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13], params[14], params[15], params[16], params[17], params[18]);
            break;
        case 20: *(void **)(&fl16) = fPtr;
            *ret = fl20(params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8], params[9], params[10], params[11], params[12], params[13], params[14], params[15], params[16], params[17], params[18], params[19]);
            break;
        default:
            return RSC_RESULT_NOT_IMPLEMENTED_SYSCALL;
    }
    return RSC_RESULT_OK;
}

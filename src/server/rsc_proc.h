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

#ifndef SERVER_RSC_PROC_H_
#define SERVER_RSC_PROC_H_

#include "rsc_threads.h"

/* Processing of RSC session.
 *
 * Reads info, checks it for "magic", reads requests and process them.
 *
 * Parameters:
 *     eventFd  event file descriptor for a default thread to send to a client on handshake.
 */
void RscProcessingClient(int eventFd);

/*processing of syscall*/
RscResult_t RscProcessingSyscallRequestThread(ThreadData_t *pD);

#endif /* SERVER_RSC_PROC_H_ */

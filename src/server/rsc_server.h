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

#ifndef SERVER_RSC_SERVER_H_
#define SERVER_RSC_SERVER_H_

/*maximum length of string with ip address*/
#define MAX_LEN_IP 32

/*maximum parameters in syscall request*/
#define MAX_PARAMS 20

/*size of input and output buffers*/
#define MAX_DATA_SIZE 65535

/*default port to connections*/
#define RSC_DEFAULT_PORT 50001

int RscIsInterrupted(void);

#endif /* SERVER_RSC_SERVER_H_ */

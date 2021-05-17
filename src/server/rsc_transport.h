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

#ifndef SERVER_RSC_TRANSPORT_H_
#define SERVER_RSC_TRANSPORT_H_

/*receive 'len' byte to 'buf' from RSC-connection.
* return =-1 if error or =len if all data received*/
ssize_t RscRecv(const void *buf, size_t len);

/*send 'len' byte from 'buf' to RSC-connection.
 * return =-1 if error or =len if all data sent*/
ssize_t RscSend(const void *buf, size_t len);

#endif /* SERVER_RSC_TRANSPORT_H_ */

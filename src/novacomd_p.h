/* @@@LICENSE
*
*      Copyright (c) 2008-2013 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#ifndef __NOVACOMD_P_H
#define __NOVACOMD_P_H

extern int g_listen_all;

SOCKET create_listen_socket(int port,int bindall);
SOCKET accept_socket(SOCKET socket);
int get_socket_port(SOCKET fd);
int recv_socket(int sockfd, char *buf, size_t len, int flags);

#endif


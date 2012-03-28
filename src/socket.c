/* @@@LICENSE
*
*      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <debug.h>
#include <novacom.h>
#include "novacomd_p.h"

SOCKET create_listen_socket(int port, int bind_all)
{
	/* create a socket */
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
		return s;
	/* close on exec */
	fcntl(s, F_SETFD, FD_CLOEXEC);

	/* set the reusaddr option */
	int reuse_addr = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_addr, sizeof(reuse_addr)) < 0) {
		close(s);
		return INVALID_SOCKET;
	}

	/* bind it to a local address */
	struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);

	if(!bind_all) {
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	if (bind(s, (const struct sockaddr *)&saddr,  sizeof(saddr)) < 0) {
		close(s);
		return INVALID_SOCKET;
	}

	/* start the socket listening */
	if (listen(s, SOMAXCONN) < 0) {
		close(s);
		return INVALID_SOCKET;
	}

	return s;
}

SOCKET accept_socket(SOCKET socket)
{
	SOCKET new_s;

	struct sockaddr saddr;
	memset(&saddr, 0, sizeof(saddr));
	socklen_t len = sizeof(saddr);

	new_s = accept(socket, &saddr, &len);
	if(new_s == INVALID_SOCKET)
		return new_s;

	/* close on exec */
	fcntl(new_s, F_SETFD, FD_CLOEXEC);
	return new_s;
}

int get_socket_port(SOCKET fd)
{
	struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	socklen_t len = sizeof(saddr);

	if (getsockname(fd, (struct sockaddr *)&saddr, &len) != 0)
		return -1;

	return ntohs(saddr.sin_port);
}

int recv_socket(int sockfd, char *buf, size_t len, int flags)
{
	int ret, loop;
	loop = 0;
	ret = recv(sockfd, buf, len, flags);
	while (ret < 0 && platform_socket_getlasterrno() == E_SOCKET_WOULDBLOCK && loop < 1000) {
		//nonblocking socket has a problem as long as we enter this loop; timeout in 1 sec
		log_printf(LOG_ERROR, "%s:%d: nonblocking recv failed, try again later, errno=%d, ret=%d \n", __FILE__, __LINE__, platform_socket_getlasterrno(), ret);
		usleep(1000);
		ret = recv(sockfd, buf, len, flags);
		loop++;
	}
	return ret;
}
	
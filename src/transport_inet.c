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

#include <transport_inet.h>
#include <stddef.h>
#include <sys/types.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <platform.h>
#include <novacom.h>
#include <debug.h>
#include "novacomd_p.h"

//module debug
#define LOCAL_TRACE 0

//vars
static volatile int novacom_shutdown = 0;

#define NDUID_MAGIC "nduid: "
#define IP_MAGIC "ELTSDIM"
#define IP_MAX_PACKET_SIZE 4096

//structs

/* connection control structure */
typedef struct novacom_inetctl_s {
	device_handle_t device_handle;				/* device handle */
	SOCKET socket;								/* socket */
	bool shutdown;								/* shutdown flag */
	platform_event_t tx_shutdown_event;			/* event to indicate tx thread shutdown */
} novacom_inetctl_t;

typedef struct inet_header_s {
	char		magic[sizeof(IP_MAGIC)];		/* sizeof(IP_MAGIC) */
	uint32_t	packetlen;						/* packet length */
} inet_header_t;

typedef struct inet_syn_s {
	char		magic[sizeof(NDUID_MAGIC)];		/* magic */
	char		nduid[NOVACOM_NDUID_CHRLEN];	/* nduid */
} inet_syn_t;

/* transmission */
void *inet_tx_loop(void *arg)
{
	novacom_inetctl_t			*handle = (novacom_inetctl_t *) arg;
	inet_header_t				*t_hdr;
	struct novacom_tx_packet	packet;
	int							rc;
	uint32_t					len;

	LTRACE_ENTRY;

	/* prepare */
	t_hdr = (inet_header_t *)platform_calloc(IP_MAX_PACKET_SIZE + sizeof(inet_header_t));
	platform_assert(t_hdr);
	packet.buf = ((char *)t_hdr) + sizeof(inet_header_t);

	/* tx cycle */
	while (!novacom_shutdown && !handle->shutdown) {
		packet.len = IP_MAX_PACKET_SIZE;
#if HOST
		rc = novacom_get_tx_packet(handle->device_handle, &packet, 2000);
#else
		rc = novacom_get_tx_packet(handle->device_handle, &packet, 2000);
#endif
		if(TX_NO_PACKET != rc) {
			t_hdr->packetlen = packet.len;
		} else {
			t_hdr->packetlen = 0;
		}
		/* packet hdr + data */
		len = sizeof(inet_header_t) + t_hdr->packetlen;
		memcpy(t_hdr->magic, IP_MAGIC, sizeof(IP_MAGIC));
		rc = send(handle->socket, (const char *) t_hdr, len, 0);
		LTRACEF("sent header: rc(%d), hdrsize(%d), datalen(%d)\n", rc, sizeof(t_hdr), t_hdr->packetlen);
	}
	// no packet means mux is shut down, fall out of the thread
	novacom_release_device_handle(handle->device_handle);
	platform_free(t_hdr);
	/* signal */
	platform_event_signal(&handle->tx_shutdown_event);

	LTRACE_EXIT;

	return NULL;
}


/* receiver */
void *inet_rx_loop(void *arg)
{
	SOCKET				socket;
	device_handle_t		device_handle;
	inet_syn_t			t_syn;				/* syn header */
	inet_header_t		t_hdr;				/* packet header */
	novacom_inetctl_t	*t_ctl = NULL;		/* connect control structure */
	char 				*buf = NULL;		/* data buffer */
	size_t				readlen;
	int					opt;
	char				nduid[NOVACOM_NDUID_STRLEN];

	if(!arg) {
		TRACEL(LOG_ERROR, "invalid argument\n");
		return NULL;
	}

	/* alloc/free/set */
	socket = *(SOCKET *)arg;
	platform_free(arg);
	buf = (char*)platform_alloc(IP_MAX_PACKET_SIZE);
	platform_assert(buf);
	t_ctl = (novacom_inetctl_t *)platform_calloc(sizeof(novacom_inetctl_t));
	platform_assert(t_ctl);

	/* prepare sockets */
	opt = IP_MAX_PACKET_SIZE;
	setsockopt(socket, SOL_SOCKET, SO_RCVLOWAT, (const char *)&opt, sizeof(opt));
	opt = 1;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));

	/* send data about yourself */
	memcpy(&t_syn.magic, NDUID_MAGIC, sizeof(NDUID_MAGIC));
	memcpy(&t_syn.nduid, novacom_nduid(), NOVACOM_NDUID_CHRLEN);
	send(socket, (const char *)&t_syn, sizeof(t_syn), 0);

	/* receive data from opposite side */
	memset(&t_syn, 0, sizeof(t_syn));
	readlen = recv(socket, (char *)&t_syn, sizeof(t_syn), 0);

	if( (readlen != sizeof(t_syn)) || (strncmp(t_syn.magic, NDUID_MAGIC, sizeof(NDUID_MAGIC)) != 0) ) {
		TRACEL(LOG_ERROR, "invalid connection packet, read(%d/%d)\n", readlen, sizeof(t_syn));
		goto exit;
	}

	/* recover nduid */
	memcpy(nduid, t_syn.nduid, NOVACOM_NDUID_CHRLEN);
	nduid[NOVACOM_NDUID_CHRLEN] = 0;

	// includes implicit retain
	device_handle = novacom_go_online(nduid, "tcp", "emulator", NULL);

	/* tx loop args */
	t_ctl->socket = socket;
	t_ctl->device_handle = device_handle;
	platform_event_create(&t_ctl->tx_shutdown_event);
	platform_event_unsignal(&t_ctl->tx_shutdown_event);
	novacom_retain_device_handle(device_handle); // for the tx thread

	platform_create_thread(NULL, &inet_tx_loop, t_ctl);

	/* main loop */
	while (!novacom_shutdown) {
		/* read packet header */
		readlen = recv(socket, (char *)&t_hdr, sizeof(t_hdr), 0);
		if(    (readlen != sizeof(t_hdr))
			|| (strncmp(t_hdr.magic, IP_MAGIC, sizeof(IP_MAGIC)) != 0)
			|| (t_hdr.packetlen > IP_MAX_PACKET_SIZE) ) {
			TRACEF("invalid packet header (%d/%d)\n", readlen, sizeof(t_hdr));
			break;
		}
#if defined(__linux__)
		setsockopt(socket, IPPROTO_TCP, TCP_QUICKACK, (char*)&opt, sizeof(opt));
#endif

		/* check for 0 data packets */
		if(t_hdr.packetlen) {
			readlen = recv(socket, buf, t_hdr.packetlen, 0);
			if (readlen != t_hdr.packetlen) {
				TRACEF("invalid data length (%d/%d)\n", readlen, t_hdr.packetlen);
				break;
			}
			if(PACKET_TYPE_BADPACKET == novacom_process_packet(device_handle, buf, t_hdr.packetlen) ) {
				TRACEF("invalid packet: shutdown interface\n");
				break;
			}
		}
	}

	/* signal tx_loop to shutdown tx loop && wait */
	t_ctl->shutdown = true;
	platform_event_wait(&t_ctl->tx_shutdown_event);
	platform_event_destroy(&t_ctl->tx_shutdown_event);

	// includes implicit release
	novacom_go_offline(device_handle);
exit:
	close(socket);
	platform_free(t_ctl);
	platform_free(buf);

	return NULL;
}

// Listen for incoming connections

static void *inetlisten_findandattach_thread(void *arg)
{
	SOCKET listen_sock;

	listen_sock = create_listen_socket(NOVACOM_INETPORT, g_listen_all);

	if(listen_sock == INVALID_SOCKET) {
		TRACEL(LOG_ERROR, "Unable to create socket(errno %d)\n", errno);
		return NULL;
	}

	/* */
	while (!novacom_shutdown)
	{
		struct sockaddr_storage faddr;
		socklen_t faddrlen = sizeof(faddr);
		char hostname[NI_MAXHOST];
		char servname[NI_MAXSERV];
		SOCKET s = INVALID_SOCKET;

		s = accept(listen_sock, (struct sockaddr *)&faddr, &faddrlen);

		if( s != INVALID_SOCKET) {
			SOCKET *newsock = (SOCKET *)platform_alloc(sizeof(SOCKET));

			if(newsock) {
				*newsock = s;
				fcntl(s, F_SETFD, FD_CLOEXEC);	/* close on exec */
				getnameinfo((struct sockaddr *)&faddr, faddrlen, hostname, sizeof(hostname), servname, sizeof(servname), NI_NUMERICHOST|NI_NUMERICSERV);
				log_printf(LOG_TRACE, "Incoming connection from %s/%s\n", hostname, servname);

				platform_create_thread(NULL, &inet_rx_loop, newsock);
			} else {
				close(s);
			}

		} else {
			usleep(100000); /* error, sleep 100msec */
		}
	}
		
	return NULL;
}

int inetlisten_transport_init(void)
{
	return 0;
}

int inetlisten_transport_start(void)
{
	platform_create_thread(NULL, &inetlisten_findandattach_thread, NULL);
	return 0;
}

int inetlisten_transport_stop(void)
{
	return 0;
}


// Create an outgoing connection

struct inetconnect_address {
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];
};

static void *inetconnect_findandattach_thread(void *arg)
{
	struct inetconnect_address * addy = (struct inetconnect_address*)arg;
	platform_assert(addy != NULL);

	struct addrinfo *res = NULL;
	struct addrinfo hints;

	memset(&hints, 0,sizeof(hints));
	hints.ai_flags = AI_ALL|AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;

	int r = getaddrinfo(addy->host, addy->serv, &hints, &res);

	if (r < 0) {
		if (res) 
			freeaddrinfo(res);
		platform_free(addy);
		TRACEF("Host not found\n");
		return NULL;
	}

	while(1) {
		// XXX we could get multiple addresses, but just use the first
		struct addrinfo * aip = res;
		SOCKET *newsocket = (SOCKET *)platform_alloc(sizeof(SOCKET));
		platform_assert(newsocket);

		*newsocket = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);

		if(INVALID_SOCKET != (*newsocket)) {
			/* close on exec */
			fcntl(*newsocket, F_SETFD, FD_CLOEXEC);
			if (connect(*newsocket, aip->ai_addr, aip->ai_addrlen) == 0) {
				// call as not-a-thread
				inet_rx_loop(newsocket);
			} else {
				close(*newsocket);
				platform_free(newsocket);
			}
		} else {
			platform_free(newsocket);
		}
		sleep(1);
	}

	log_printf(LOG_ALWAYS, "aborting connection attempts to %s/%s\n", addy->host, addy->serv);

	freeaddrinfo(res);
	platform_free(addy);
	return NULL;
}


// arg is a pointer to the endpoint entry we're connecting to
void inetconnect_connect_to(char *host, char *serv)
{
	struct inetconnect_address *addy = (struct inetconnect_address*)platform_alloc(sizeof(struct inetconnect_address));

	platform_assert(addy != NULL);
	
	
	if (host) {
		strncpy(addy->host, host, NI_MAXHOST);
		addy->host[NI_MAXHOST-1] = 0;
	} else {
		addy->host[0] = 0;
	}
	if (serv && (strcmp("", serv) != 0)) {
		strncpy(addy->serv, serv, NI_MAXSERV);
		addy->serv[NI_MAXSERV-1] = 0;
	} else {
		snprintf(addy->serv, NI_MAXSERV, "%d", NOVACOM_INETPORT);
	}
	
	log_printf(LOG_ALWAYS, "Connecting to %s/%s via IP\n", addy->host, addy->serv);

	platform_create_thread(NULL, &inetconnect_findandattach_thread, addy);
	// XXX save this for cancelling maybe
}


int inetconnect_transport_init(void)
{
	return 0;
}

int inetconnect_transport_start(void)
{
#if HOST
//	inetconnect_connect_to("192.168.2.101", NULL);
#elif DEVICE
//	inetconnect_connect_to("192.168.2.100", NULL);
#endif
	return 0;
}

int inetconnect_transport_stop(void)
{
	// XXX cancel and join some threads

	return 0;
}

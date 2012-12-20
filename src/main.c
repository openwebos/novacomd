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
#include <getopt.h>
#include <debug.h>
#include <unistd.h>
#include <stdint.h>
#include <platform.h>
#include <novacom.h>
#include "novacom/mux.h"
#include <transport.h>
#include <transport_inet.h>
#include <errno.h>
#include "novacomd_p.h"
#include <log.h>
#if HOST
#include "host/novacom_host.h"
#include "lib/cksum.h"
#endif

#include <termios.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <syslog.h>

int g_listen_all;
int g_recovery_timeout = TRANSPORT_RECOVERY_TIMEOUT;
int g_usbio_retry_timeout = TRANSPORT_USBIO_RETRY_TIMEOUT;
int g_usbio_retry_delay = 50;   //RETRANSMIT_WAIT_PERIOD=50ms
int g_cpuaffinity = 0;
#if !defined(W32)
int g_daemonize = 0;
#endif

#if HOST
#define LOCAL_TRACE 0
#define LOCAL_TRACE_PROCESSCMD 0
#elif DEVICE
#define LOCAL_TRACE 0
#define LOCAL_TRACE_PROCESSCMD 0
#endif

/* upper and lower tx queue thresholds */
#define TX_QUEUE_UPPER (64*1024)
#define TX_QUEUE_LOWER (32*1024)

typedef struct socketchan {
	struct socketchan *next;
	int close;
	SOCKET socket;
	size_t partial_pos;
	uint32_t channel;
	device_handle_t device_handle;
	bool tx_squelch;
} socketchan_t;

static struct socketchan *socketchan_list;

#ifdef HOST
typedef struct socketcmd_s {
	int active;                             /* being processed */
	uint32_t cmd_id;                        /* just a number, so we can track in logs */
	uint32_t channel;                       /* channel number (do we really need it) */
	int close;                              /* closing flag */
	SOCKET socket;                          /* client socket */
	char *sockreply;                        /* reply to socket client */
	size_t partial_pos;                     /* partial pos (output to client) */
	struct novacom_command_url *url;        /* command */
	device_handle_t device_handle;          /* device handle */
	TAILQ_ENTRY(socketcmd_s) entries;       /* holds pointers to prev, next entries */
} socketcmd_t;
#endif

typedef struct active_device {
	struct active_device *next;
	struct active_device *listen_next;
	
	bool closing;
	bool inactive; /* true: cert auth is taking place(should not be populated to clients) */
	int ref;
	SOCKET socket;
	int socket_port;
	char *devid;
	char *conntype;
	char *devtype;
	char *sessionid;
	device_handle_t device_handle;
#ifdef HOST
	uint32_t cmd_serviced;           /* number of processed service control commands */ 
	socketchan_t *cmd_chan;          /* service command channel */
	TAILQ_HEAD(socketcmd_queue_s, socketcmd_s)  cmd_queue;
#endif
} active_device_t;

static SOCKET opt_sock = INVALID_SOCKET;
static SOCKET device_list_socket = INVALID_SOCKET;
static SOCKET log_socket = INVALID_SOCKET;
static SOCKET ctrl_socket = INVALID_SOCKET;
static SOCKET unblock_fd = INVALID_SOCKET;
static SOCKET unblock_fd_write = INVALID_SOCKET;
static SOCKET unblock_fd_read = INVALID_SOCKET;
static platform_mutex_t device_list_mutex;
static struct active_device *device_list;

// local functions
static void add_device_ref(struct active_device *dev);
static void remove_device_ref(struct active_device *dev);
static int socketchan_read_callback(device_handle_t device_handle, uint32_t channel, int error, const void *buf, size_t len, void *cookie);
static void socketchan_write_callback(device_handle_t device_handle, uint32_t channel, int err, void *cookie);
static void destroy_socketchan(socketchan_t *sc);
static int novacom_register_client(active_device_t *dev, SOCKET newsocket);

int handleopt(const char *opt, const char *val);
int getnextopt(int argc, char **argv, const char **opt, const char **val);

#if HOST
void *novacom_deviceinit_thread(void *arg);
static int novacom_register_command(SOCKET cmdsocket, const char *_cmd);
static int novacom_process_cmdqueue(active_device_t *dev);
static int socketcmd_read_callback(device_handle_t device_handle, uint32_t channel, int err, const void *buf, size_t len, void *cookie);
static void destroy_socketcmd(socketcmd_t *sc);
void socketcmd_write_callback(device_handle_t device_handle, uint32_t channel, int err, void *cookie);
#endif

void usage(void)
{
	TRACEL(LOG_ALWAYS, "\n");
	TRACEL(LOG_ALWAYS, "Usage:  novacomd [option]...\n");
	TRACEL(LOG_ALWAYS, "options:\n");
	TRACEL(LOG_ALWAYS, "  -b                  bind ipaddress for remote access, default is 127.0.0.1 \n");
	TRACEL(LOG_ALWAYS, "  -t <seconds>        set recovery timeout interval, valid range 2 ~ 5, default is 5\n");
	TRACEL(LOG_ALWAYS, "  -c <host>:<port>    connect to specified IP address\n"); 
	TRACEL(LOG_ALWAYS, "  -e <io-retry-timeout>    timeout to retry packet I/O in milliesecond\n"); 
	TRACEL(LOG_ALWAYS, "  -s <io-retry-delay>    delay to retry packet I/O in milliesecond\n"); 
	TRACEL(LOG_ALWAYS, "  -d                  run in the background\n");
	TRACEL(LOG_ALWAYS, "  -V                  print version info\n");
	TRACEL(LOG_ALWAYS, "  -h                  display this help\n");

}

/*
 * unblock main_loop
 */
static void unblock_main_loop(void)
{
	if (unblock_fd_write == INVALID_SOCKET ) {
		struct sockaddr_in saddr;
		memset(&saddr,0,sizeof(saddr));

		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(NOVACOM_UNBLOCKPORT);
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); 

		unblock_fd_write = socket(AF_INET, SOCK_STREAM, 0);
		if (unblock_fd_write == INVALID_SOCKET) {
			TRACEL(LOG_ERROR, "unable to create socket\n");
			return;
		}
		if ( connect(unblock_fd_write, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
			close(unblock_fd_write);
			unblock_fd_write = INVALID_SOCKET;
			TRACEL(LOG_ERROR, "unable to connect\n");
			return;
		}
	}

	char c = 0;
	if (send(unblock_fd_write, &c, 1, 0) < 0) {
		close(unblock_fd_write);
		unblock_fd_write = INVALID_SOCKET;
	}
}

static int socketchan_read_callback(device_handle_t device_handle, uint32_t channel, int err, const void *buf, size_t len, void *cookie)
{
	struct socketchan *sc = (struct socketchan *)cookie;
	int written;

	/* channel closed: ignore cb */
	if (err < 0) {
		TRACEL(LOG_TRACE, "novacom channel %d closed\n", channel);
		sc->close = 1;
		sc->channel = -1;
		unblock_main_loop();
		return 0;
	}
	/* channel closing: ignore cb */
	if (sc->close) {
		TRACEL(LOG_TRACE, "novacom channel %d closing\n", channel);
		unblock_main_loop();
		return 0;
	}

	written = send(sc->socket, (char *)buf + sc->partial_pos, len - sc->partial_pos, 0);
	
	if ((written == 0)|| ((written == -1) && (errno != EAGAIN) && (errno != 0))) {
		TRACEL(LOG_TRACE, "novacom channel %d error: %d %d %d %d\n", channel, written, errno, len, sc->partial_pos);
		sc->close = 1;
		unblock_main_loop();
	}
	if (written <= 0)
		return -1;

	sc->partial_pos += written;
	if (sc->partial_pos == len) {
		sc->partial_pos = 0;
		return 0;
	} else {
		// Couldn't make a complete write, wait for a retransmit
		return -1;
	}

	return 0;
}

static void socketchan_write_callback(device_handle_t device_handle, uint32_t channel, int err, void *cookie)
{
	unblock_main_loop();
}

/*
 * @brief destroys socketchan_t
 */
static void destroy_socketchan(socketchan_t *sc)
{
	/* unregister read callback */
	if (sc->channel > 0) {
		novacom_set_read_callback(sc->device_handle, sc->channel, NULL, NULL);
		novacom_close_channel(sc->device_handle, sc->channel);
	}
	TRACEF("socketchan::destroy: %p, socket %d, novacom %d, device %p\n", sc, sc->socket, sc->channel, sc->device_handle);
	/* inform client */
	if (sc->socket != INVALID_SOCKET) {
		shutdown(sc->socket, SHUT_RDWR);
		close(sc->socket);
		sc->socket = INVALID_SOCKET;
	}
	novacom_release_device_handle(sc->device_handle);
	platform_free(sc);
}


void dump_device_list(SOCKET socket)
{
	char buf[256];
	struct active_device *dev;

//	sprintf(buf, "6969 AFDE123400004321DEADBEEFC001CAFE00000000 usb\n");
//	write(socket, buf, strlen(buf));

	platform_mutex_lock(&device_list_mutex);

	for (dev = device_list; dev; dev = dev->next) {
		// skip devices that are shutting down
		if (dev->closing) continue;

		if (!dev->sessionid) {
			snprintf(buf, sizeof(buf), "%d %s %s %s\n", dev->socket_port, dev->devid, dev->conntype, dev->devtype);
		} else {
			snprintf(buf, sizeof(buf), "%d %s %s %s %s\n", dev->socket_port,
					dev->devid, dev->conntype, dev->devtype, dev->sessionid);
		}
		send(socket, buf, strlen(buf), 0);
	}

	platform_mutex_unlock(&device_list_mutex);
}

/* check device list for duplicate entries */
void novacom_removedup_device(device_handle_t device_handle, novacom_device_reginfo_t *t_drinfo)
{
	struct active_device *dev = NULL;

	/* issue occurs only on tcp connection due bug in VirtualBox: LTP-624 */
	if ( t_drinfo->conntype && (0 == strncasecmp(t_drinfo->conntype, "tcp", 3)) ) {
		int len;

		platform_mutex_lock(&device_list_mutex);

		for (dev = device_list; dev; dev = dev->next) {
			len = MIN(strlen(dev->devid), NOVACOM_NDUID_CHRLEN);
			if ( t_drinfo->devid_string && (0 == strncasecmp(t_drinfo->devid_string, dev->devid, len) ) ) {
				TRACEL(LOG_ALWAYS, "duplicate: '%s', port %d\n", dev->devid, dev->socket_port);
				break;
			}
		}

		platform_mutex_unlock(&device_list_mutex);

		if(dev) {
			novacom_unregister_device(dev->device_handle);
		}
	}
}

void novacom_register_device(device_handle_t device_handle, novacom_device_reginfo_t *t_dev_reginfo)
{
	struct active_device *dev;

	/* bogus device registration info */
	if (!t_dev_reginfo)
		return;

	TRACEL(LOG_ALWAYS, "dev '%s' via %s type %s\n",
			t_dev_reginfo->devid_string,
			t_dev_reginfo->conntype,
			t_dev_reginfo->devtype);

	/*check duplicate entries(vitrual box bug:does not close sockets leaving dups) */
	novacom_removedup_device(device_handle, t_dev_reginfo);

	/* device record */
	dev = (struct active_device*)platform_calloc(sizeof(struct active_device));
	platform_assert(dev != NULL);

	dev->device_handle = device_handle;
	novacom_retain_device_handle(device_handle);

	dev->devid = platform_strdup(t_dev_reginfo->devid_string);
	dev->ref = 1;
	dev->closing = false;
	/* conntype */
	if(t_dev_reginfo->conntype)
		dev->conntype = platform_strdup(t_dev_reginfo->conntype);
	/* devtype */
	if(t_dev_reginfo->devtype)
		dev->devtype = platform_strdup(t_dev_reginfo->devtype);
#if HOST
	/* command queue */
	TAILQ_INIT(&dev->cmd_queue);
	/* session id */
	if( (t_dev_reginfo->sessionid) && ( strlen(t_dev_reginfo->sessionid)) ) {
		dev->sessionid = platform_strdup(t_dev_reginfo->sessionid);
		/* add device reference */
		add_device_ref(dev);
		/* initialization thread */
		dev->inactive = 1; /* inactive device:: should be skipped from device list */
		platform_create_thread(NULL, &novacom_deviceinit_thread, dev);
	}
#endif

	dev->socket = create_listen_socket(0, g_listen_all);
	if(dev->socket != INVALID_SOCKET) {
		dev->socket_port = get_socket_port(dev->socket);
	}
	//	TRACEF("socket %d, port %d\n", dev->socket, dev->socket_port);

	platform_mutex_lock(&device_list_mutex);

	dev->next = device_list;
	device_list = dev;

	platform_mutex_unlock(&device_list_mutex);

//	TRACEF("handle %p\n", dev->device_handle);
}

int novacom_unregister_device(device_handle_t device_handle)
{
	int err = -1;
	struct active_device *dev;
	struct active_device *last;

//	TRACEF("handle %p\n", device_handle);

	platform_mutex_lock(&device_list_mutex);

	last = NULL;
	for (dev = device_list; dev; last = dev, dev = dev->next) {
		if (dev->device_handle == device_handle) {
			TRACEL(LOG_ALWAYS, "removing id %s\n", dev->devid);
			if (last != NULL) {
				last->next = dev->next;
			} else {
				device_list = dev->next;
			}
			dev->next = NULL;
			err = 0;
			break;
		}
	}

	if (dev) {
#if HOST
		/* close command queue */
		if ( !TAILQ_EMPTY(&dev->cmd_queue) ) {
			socketcmd_t *item;
			socketcmd_t *tmp_item;

			/* mark active commands */
			item = TAILQ_FIRST(&dev->cmd_queue);
			item->close = 1;

			/* remove commands not processed yet */
			for (item = TAILQ_NEXT(item, entries); item != NULL; item = tmp_item) {
				tmp_item = TAILQ_NEXT(item, entries);
				/* Remove the item from queue. */
				TAILQ_REMOVE(&dev->cmd_queue, item, entries);
				/* release memory */
				destroy_socketcmd( item );
			}
		}

		/* close service channel */
		if (dev->cmd_chan) {
			//destroy_socketchan(dev->cmd_chan);
			//remove_device_ref(dev);
		}
#endif

		/* device closing */
		dev->closing = true;
		remove_device_ref(dev);
	}

	platform_mutex_unlock(&device_list_mutex);

	unblock_main_loop();

	return err;
}
/*
 * @brief: return remote nduid
 */
char *novacom_rnduid(device_handle_t device_handle)
{
	char *rnduid = NULL;
	struct active_device *dev;

	platform_mutex_lock(&device_list_mutex);
	for (dev = device_list; dev; dev = dev->next) {
		if (dev->device_handle == device_handle) {
			LTRACEF("found match: rnduid %s\n", dev->devid);
			rnduid = platform_strdup(dev->devid);
			break;
		}
	}
	platform_mutex_unlock(&device_list_mutex);
	return rnduid;
}

static void add_device_ref(struct active_device *dev)
{
	platform_atomic_add(&dev->ref, 1);
	//LTRACEF("dev->ref=%d(%s)\n", dev->ref, dev->devtype);
}

static void remove_device_ref(struct active_device *dev)
{
	if (platform_atomic_add(&dev->ref, -1) == 1) {
		// last ref, make sure it's not in the list
		platform_assert(dev->next == NULL);

		LTRACEF("removing last ref to dev '%s'\n", dev->devid);

		novacom_release_device_handle(dev->device_handle);

		close(dev->socket);
		platform_free(dev->devid);
		platform_free(dev->conntype);
		platform_free(dev->devtype);
		if(dev->sessionid)
			platform_free(dev->sessionid);
		platform_free(dev);
	} else {
		//LTRACEF("dev->ref=%d(%s)\n", dev->ref, dev->devtype);
	}
}

/*
 * @brief: handle accepting new client to novacomd
 */
static int novacom_register_client(active_device_t *dev, SOCKET newsocket)
{
	int rc = -1;
	socketchan_t *sc = (socketchan_t *)platform_calloc(sizeof(socketchan_t));
	if(sc) {
		sc->close = 0;
		sc->partial_pos = 0;
		sc->socket = newsocket;
		sc->tx_squelch = false;
		sc->next = socketchan_list;
		novacom_retain_device_handle(dev->device_handle);
		sc->device_handle = dev->device_handle;
		socketchan_list = sc;

		TRACEF("Opening temp channel, device %p\n", dev->device_handle);
		rc = novacom_open_temp_channel(sc->device_handle, &sc->channel, 1);
		if (rc >= 0) {
			rc = novacom_set_read_callback(sc->device_handle, sc->channel, (novacom_read_callback)&socketchan_read_callback, sc);
			if (rc < 0) {
				/* 
				 * error creating or setting the callback, which can happen as
				 * a result of a race with the device going away, abort
				 */
				sc->channel = -1;
				sc->close = 1;
				TRACEF("hit create channel/device going away race\n");
			}
			TRACEF("socketchan::created: %p, socket %d, novacom %d, device %p\n", sc, sc->socket, sc->channel, dev->device_handle);
		} else {
			TRACEF("Unable to create channel: rc(%d)\n", rc);
			sc->channel = -1;
		}
	}
	return rc;
}


static int main_loop(void)
{
	fd_set fds;
	struct socketchan *sc;
	struct socketchan *last;
	SOCKET highest_socket;
	struct active_device *dev;
	struct active_device *listen_devices;
	char sdata[8*1024];

	#define PICK_MAXSOCKET(insocket)	if(insocket > highest_socket) highest_socket = insocket;

	for (;;) {
		highest_socket = INVALID_SOCKET;
		FD_ZERO(&fds);

		if(device_list_socket != INVALID_SOCKET) {
			FD_SET(device_list_socket, &fds);
			highest_socket = device_list_socket;
		}

		if(opt_sock != INVALID_SOCKET) {
			FD_SET(opt_sock, &fds);
			PICK_MAXSOCKET(opt_sock);
		}

		if(unblock_fd != INVALID_SOCKET) {
			FD_SET(unblock_fd, &fds);
			PICK_MAXSOCKET(unblock_fd);
		}

		if(log_socket != INVALID_SOCKET) {
			FD_SET(log_socket, &fds);
			PICK_MAXSOCKET(log_socket);
		}

		if (unblock_fd_read != INVALID_SOCKET) {
			FD_SET(unblock_fd_read, &fds);
			PICK_MAXSOCKET(unblock_fd_read);
		}

		if(ctrl_socket != INVALID_SOCKET) {
			FD_SET(ctrl_socket, &fds);
			PICK_MAXSOCKET(ctrl_socket);
		}

		/* add the transfer sockets to the list */
		last = NULL;
		sc = socketchan_list;
		while (sc) {
			if (sc->close) {
				struct socketchan *temp;
				/* socket has been closed, destroy the socketchan */
				if (last) {
					last->next = sc->next;
				} else {
					socketchan_list = sc->next;
				}

				temp = sc;
				sc = sc->next;

				destroy_socketchan(temp);
			} else {
				/* see if we should start listening to a previously squelched channel */
				if (sc->tx_squelch) {
					if (novacom_tx_queue_len(sc->device_handle, sc->channel) < TX_QUEUE_LOWER) {
						sc->tx_squelch = false;
					}
				}

				/* add it to the list of sockets to listen to if it isn't squelched */
				if (!sc->tx_squelch) {
					FD_SET(sc->socket, &fds);
					PICK_MAXSOCKET(sc->socket);
//					TRACEF("queuing socket %d\n", sc->socket);
				}

				last = sc;
				sc = sc->next;
			}
		}

		/* add the listen sockets to the list */
		listen_devices = NULL;

		platform_mutex_lock(&device_list_mutex);
		for (dev = device_list; dev; dev = dev->next) {
			FD_SET(dev->socket, &fds);
			PICK_MAXSOCKET(dev->socket);

			/* 
			 * add this device to a temporary list of devices 
			 * we're listening for on this pass of select
			 */
			dev->listen_next = listen_devices;
			listen_devices = dev;
			add_device_ref(dev);
		}
		platform_mutex_unlock(&device_list_mutex);

		/* wait for input */
		if(select(highest_socket + 1, &fds, NULL, NULL, NULL) <= 0) {
			/* remove device references */
			dev = listen_devices;
			platform_mutex_lock(&device_list_mutex);
			while (dev) {
				struct active_device *temp_dev = dev;
				dev = dev->listen_next;
				remove_device_ref(temp_dev);
			}
			platform_mutex_unlock(&device_list_mutex);
			/* restart loop */
			continue;
		}

		/* see if our pipe has any data. used to unblock the select loop. */
		if (FD_ISSET(unblock_fd, &fds)) {
			unblock_fd_read = accept_socket(unblock_fd);
		}

		if( (unblock_fd_read != INVALID_SOCKET) && (FD_ISSET(unblock_fd_read, &fds)) ) {
			char c;
			if( recv(unblock_fd_read, &c, 1, 0) < 0) {
				close(unblock_fd_read);
				unblock_fd_read = INVALID_SOCKET;
			}
		}

		if (FD_ISSET(opt_sock, &fds)) {
			SOCKET newsocket = accept(opt_sock, NULL, NULL);
			if (newsocket != INVALID_SOCKET) {
				uint32_t lengths[2] = {0,0};
				char *buf;
				int rc;
				int sock_opt = 4096;
				setsockopt(newsocket, SOL_SOCKET, SO_RCVLOWAT, (char *)&sock_opt, sizeof(sock_opt));

				// only one option pair per connection
				rc = recv(newsocket, (char*)lengths, sizeof(lengths), 0);

				if(rc == sizeof(lengths)) {
					// 4k options should be enough for anyone
					if ((lengths[0] != 0) && ((lengths[0] + lengths[1]) < 4096)) {
						size_t l = lengths[0] + lengths[1] + 1;
						buf = (char*)platform_calloc(l);
						if(buf) {
							rc = recv(newsocket, buf, lengths[0] + lengths[1], 0);
							if(rc > 0) {
								buf[lengths[0] + lengths[1]] = '\0';
								handleopt(buf, &buf[lengths[0]]);
							}
							platform_free(buf);
						} else {
							TRACEF("unable to allocate memory to accept options, ignore...\n");
						}
					}
				}

				close(newsocket);
			}
		}

		/* process device list requests */
		//ychen: typo: if ( (log_socket != INVALID_SOCKET) && (FD_ISSET(device_list_socket, &fds)) ) {
		if ( (device_list_socket != INVALID_SOCKET) && (FD_ISSET(device_list_socket, &fds)) ) {
			SOCKET newsocket = accept_socket(device_list_socket);
			if(newsocket != INVALID_SOCKET) {
				dump_device_list(newsocket);
				close(newsocket);
			}
		}

		/* process logging request */
		if ( (log_socket != INVALID_SOCKET) && (FD_ISSET(log_socket, &fds)) ) {
			SOCKET newsocket = accept_socket(log_socket);
			if(newsocket != INVALID_SOCKET) {
				log_add_socket(newsocket);
			}
		}

		/* process control requests */
		if ( (ctrl_socket != INVALID_SOCKET) && (FD_ISSET(ctrl_socket, &fds)) ) {
			SOCKET newsocket = accept_socket(ctrl_socket);
			if ( newsocket != INVALID_SOCKET ) {
#if HOST
				int rc = novacom_register_command(newsocket, NULL);
				/* -1, 1: command is done */
				if (rc)
					close(newsocket);
#else
				close(newsocket);
#endif
			}
		}

		/* see if any of our device listener channels opened */
		dev = listen_devices;
		while (dev) {
			struct active_device *temp_dev;
			/* device */
			if (FD_ISSET(dev->socket, &fds) ) {
				SOCKET newsocket = accept_socket(dev->socket);
				TRACEL(LOG_TRACE, "data socket %d\n", newsocket);

				if(newsocket != INVALID_SOCKET) {

					// Set non-blocking or novacomd will drop offline if the socket fills up
					fcntl(newsocket, F_SETFL, fcntl(newsocket, F_GETFL) | O_NONBLOCK);
					(void) novacom_register_client(dev, newsocket);
				}
			}

			/* we're done with this device this time around, remove its ref */
			temp_dev = dev;
			dev = dev->listen_next;
			platform_mutex_lock(&device_list_mutex);
			remove_device_ref(temp_dev);
			platform_mutex_unlock(&device_list_mutex);
		}

		/* process any pending data on the data sockets */
		last = NULL;
		for (sc = socketchan_list; sc; last = sc, sc = sc->next) {
			if (sc->close)
				continue; // skip it
			if (FD_ISSET(sc->socket, &fds)) {
				// got some data on this socket
				int len;
				FD_CLR(sc->socket, &fds);

				len = recv_socket(sc->socket, sdata, sizeof(sdata), 0);
				if (len <= 0) {
					// error, socketchan will get cleaned up in the next cycle around the loop
					TRACEF(/*log_printf(LOG_ERROR,*/ "%s:%d: recv: errno=%d, ret=%d, sc->socket=%d\n", __FILE__, __LINE__, platform_socket_getlasterrno(), len, sc->socket);
					sc->close = 1;
				}

				if (len > 0) {
					size_t queuelen;
                             		//print cmds
                                	if (strncmp(sdata, "run",3)==0 || strncmp(sdata, "open", 4)==0 || strncmp(sdata, "get", 3)==0 || strncmp(sdata, "put", 3)==0 || strncmp(sdata, "connect", 7)==0 || strncmp(sdata, "boot", 4)==0) {
                                  		if (len < (int)sizeof(sdata)) {
                                      			sdata[len] = 0;
                                  		}
                                  		TRACEF(/*log_printf(LOG_ALWAYS, */"%s:%d: sock=%x, cmd/data recved: %s, len=%d\n",__FILE__, __LINE__, (int)sc->socket, sdata, len);
                                	}
					// it puts the data in the basket
					novacom_write_channel_async(sc->device_handle, sc->channel, sdata, len, ASYNC_FLAG_COPY, (novacom_async_callback)&socketchan_write_callback, (void *)sc);

					queuelen = novacom_tx_queue_len(sc->device_handle, sc->channel);
					if (queuelen > TX_QUEUE_UPPER) {
//						TRACEF("queue len %zd\n", novacom_tx_queue_len(sc->channel));
						sc->tx_squelch = true;
					}
				}
			}
		}
	}

	return 0;
}

// commandline parsing stuff below
static void novacomopt(int argc, char **argv)
{
	SOCKET optsock;
	struct sockaddr_in saddr;
	memset(&saddr,0,sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(NOVACOM_OPTPORT);
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* send options to existing process */
	optsock = socket(AF_INET, SOCK_STREAM, 0);
	if(optsock != INVALID_SOCKET) {
		if (connect(optsock, (struct sockaddr *)&saddr, sizeof(saddr)) == 0) {
#if 0
//we may change this potion of code in future.
			const char *opt = NULL;
			const char *val = NULL;
			uint32_t nemo[2] = {0, 0};
			TRACEL(LOG_ALWAYS, "sending options to existing novacomd process\n");
			while (getnextopt(argc, argv, &opt, &val) > 0) {
				// include nulls
				int valLen = 0;
				if (val) valLen = strlen(val) + 1;
				uint32_t lengths[2] = {strlen(opt) + 1, valLen};

				send(optsock, (const char*)lengths, sizeof(lengths), 0);
				send(optsock, opt, lengths[0], 0);
				if(valLen) {
					send(optsock, val, lengths[1], 0);
				}
				close(optsock);
				optsock = socket(AF_INET, SOCK_STREAM, 0);
				if(optsock != INVALID_SOCKET) {
					if (connect(optsock, (struct sockaddr *)&saddr, sizeof(saddr)) != 0) {
						TRACEL(LOG_ERROR, "Error connecting to existing novacomd\n");
						exit(1);
					}
				} else {
					break;
				}
			}

			if(optsock != INVALID_SOCKET) {
				send(optsock, (const char*)nemo, sizeof(nemo), 0);
				close(optsock);
			}
#endif
			
			TRACEL(LOG_ALWAYS, "Cannot start novacomd twice!\n");
			exit(0);
		} else {
			close(optsock);
		}
	} else {
		TRACEL(LOG_ERROR, "unable to create socket\n");
	}
}

int handleopt(const char *opt, const char *val)
{
	//TRACEL(LOG_ALWAYS, "Got option %s with value %s\n", opt, val?val:"(null)");
	if( val && (0 == strcmp("connect-ip", opt) ) ) {
		char *addr = platform_strdup(val);
		char *port;
		if ((port = strpbrk(addr, ": ")) != NULL) {
			*port = '\0';
			port++;
		}

		inetconnect_connect_to(addr, port);
		platform_free(addr);
	} else if (strcmp("version", opt) == 0) {
		TRACEL(LOG_ALWAYS, "novacomd version %s\n", BUILDVERSION);
		exit(1);
	} else if (strcmp("bind-all-interfaces", opt) == 0) {
		g_listen_all = 1;
	} else if (strcmp("daemonize", opt) == 0) {
		g_daemonize = 1;
	} else if (strcmp("recoverytimeout", opt) == 0) {
		g_recovery_timeout = atol(val);
		if (g_recovery_timeout < 2 || g_recovery_timeout > 5) {
			//timeout out of range
			g_recovery_timeout = TRANSPORT_RECOVERY_TIMEOUT;
			TRACEL(LOG_ERROR, "Invalid timeout out of range(2~5 seconds): %s \n", val);
			return -1;
		}
	} else if (strcmp("ioretry_timeout", opt) == 0) {
			g_usbio_retry_timeout = atol(val);
			if (g_usbio_retry_timeout > TRANSPORT_MAX_USBIO_RETRY_TIMEOUT) {
				g_usbio_retry_timeout = TRANSPORT_MAX_USBIO_RETRY_TIMEOUT;
			}
	} else if (strcmp("ioretry_delay", opt) == 0) {
			g_usbio_retry_delay = atol(val);
			if (g_usbio_retry_delay > TRANSPORT_MAX_USBIO_RETRY_TIMEOUT) {
				g_usbio_retry_delay = TRANSPORT_MAX_USBIO_RETRY_TIMEOUT;
			}
	} else if (strcmp("no-cpuaffinity", opt) == 0) {
		g_cpuaffinity = 0;
	} else if (strcmp("help", opt) == 0) {
			usage();
			exit(1);
	} else {
		/* bad option */
		return -1;
	}

	return 0;
}

struct option longopts[] = {
	{"connect-ip", required_argument, 0, 'c'},
	{"bind-all-interfaces", no_argument, 0, 'b'},
	{"daemonize", no_argument, 0, 'd'},
	{"version", no_argument, 0, 'V'},
	{0,0,0,0}
};

int getnextopt(int argc, char **argv, const char **opt, const char **val)
{
#if !defined(W32)
	int c = getopt_long(argc, argv, "ht:c:e:s:bdCV", longopts, NULL);
#else
	int c = getopt_long(argc, argv, "ht:c:e:s:bCV", longopts, NULL);
#endif
	*val = optarg;

	switch (c) {
		case 'c':
			*opt = "connect-ip";
			return 1;
		case 'V':
			*opt = "version";
			return 1;
		case 'b':
			*opt = "bind-all-interfaces";
			return 1;
		case 'd':
			*opt = "daemonize";
			return 1;
		case 't':
			*opt="recoverytimeout";
			return 1;
		case 'e':
			*opt = "ioretry_timeout";
			return 1;
		case 's':
			*opt = "ioretry_delay";
			return 1;
		case 'C':
			*opt = "no-cpuaffinity";
			return 1;
		case 'h':
			*opt = "help";
			return 1;
		/* done with args */
		case -1:
			return 0;

		/* something we don't recognize */
		default:
			return -1;
	}
}

int parse_commandline (int argc, char **argv)
{
	const char *opt, *val;
	int err;

	while ((err = getnextopt(argc, argv, &opt, &val)) > 0) {
		if (handleopt(opt, val) < 0)
			return -1;
	}
	if (g_usbio_retry_timeout < g_usbio_retry_delay) {
		g_usbio_retry_delay = g_usbio_retry_timeout;
	}
	return err;
}

int main(int argc, char **argv)
{
	int err;

	signal(SIGPIPE, SIG_IGN);

	platform_init();
#if HOST
	openlog("novacomd(" BUILDVERSION ")", 0, LOG_LOCAL7);
#endif //HOST
	log_init();

	//TRACEL(LOG_ALWAYS, "novacomd version %s starting...\n", BUILDVERSION);

	//initialize nduid
	err = novacom_init();
	if (err < 0)
		return 1;

	if (parse_commandline(argc, argv) < 0) 	{
		TRACEL(LOG_ERROR, "Invalid command line option or parameter\n");
		log_mask(LOG_OUTPUT_CONSOLE, 1);
		usage();
		exit(1);
	}

	novacomopt(argc, argv);

	if (1 == g_daemonize) {
		/* Our process ID and Session ID */
		pid_t pid, sid;

		TRACEL(LOG_ALWAYS, "starting the daemonizing process\n");

		/* Fork off the parent process */
		pid = fork();
		if (pid < 0) {
			exit(EXIT_FAILURE);
		}
		/* If we got a good PID, then
			we can exit the parent process. */
		if (pid > 0) {
			exit(EXIT_SUCCESS);
		}

		/* Change the file mode mask */
		umask(0);

		/* Create a new SID for the child process */
		sid = setsid();
		if (sid < 0) {
			/* Log the failure */
			exit(EXIT_FAILURE);
		}

		/* Change the current working directory */
		if ((chdir("/")) < 0) {
			/* Log the failure */
			exit(EXIT_FAILURE);
		}

		/* Close out the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	platform_mutex_init(&device_list_mutex);

	device_list_socket = create_listen_socket(NOVACOM_DEVLISTPORT, g_listen_all);
	if (device_list_socket == INVALID_SOCKET) {
		TRACEL(LOG_ERROR, "error creating server sockets, port %d\n", NOVACOM_DEVLISTPORT);
		return 1;
	}

	unblock_fd = create_listen_socket(NOVACOM_UNBLOCKPORT, 0);
	if (unblock_fd == INVALID_SOCKET) {
		TRACEL(LOG_ERROR, "error creating server sockets, port %d\n", NOVACOM_UNBLOCKPORT);
		return 1;
	}

	log_socket = create_listen_socket(NOVACOM_LOGPORT, g_listen_all);
	if (log_socket == INVALID_SOCKET) {
		TRACEL(LOG_ERROR, "error creating server sockets, port %d\n", NOVACOM_LOGPORT);
		return 1;
	}

	opt_sock = create_listen_socket(NOVACOM_OPTPORT, 0);
	if (opt_sock == INVALID_SOCKET) {
		TRACEL(LOG_ERROR, "error creating server sockets, port %d\n", NOVACOM_OPTPORT);
		return 1;
	}

	ctrl_socket = create_listen_socket(NOVACOM_CTRLPORT, 0);
	if(ctrl_socket == INVALID_SOCKET) {
		TRACEL(LOG_ERROR, "error creating server sockets, port %d\n", NOVACOM_CTRLPORT);
		return 1;
	}

	err = transport_init();
	if (err < 0)
		return 1;

	err = transport_start();
	if (err < 0)
		return 1;

#if DEVICE
#if 0
	// set prio on device
	// all your timeslice are belong to us
	int rc;
	struct sched_param params;
	params.sched_priority = sched_get_priority_max(SCHED_RR);
	rc = sched_setscheduler(getpid(), SCHED_RR, &params);
	if (rc) {
		fprintf(stderr, "Error calling sched_setscheduler(): %d\n", rc);
		return EXIT_FAILURE;
	}
#else
	/* run at slightly higher priority, but less so than the kernel threads */
	err = nice(-4);
	if (-4 != err) {
		TRACEL(LOG_ERROR, "nice(-4) returned an unexpected value: %d\n", err);
	}
#endif
#endif

	main_loop();

	return 0;
}

//do not submit...
#ifndef DEVICE
#define HOST 1
#endif
//end do not submit

#if HOST

/* transmission */
void *novacom_deviceinit_thread(void *arg)
{
	int rc = -1;
	active_device_t *dev = (active_device_t *) arg;

	/* arg */
	if (!arg)
		return NULL;

	/* open service control channel */
	dev->cmd_chan = (socketchan_t *)platform_calloc(sizeof(socketchan_t));
	if (dev->cmd_chan) {
		socketchan_t *sc = dev->cmd_chan;
		sc->channel = PMUX_CHANNEL_CMDSERVICE;
		LTRACEF("Opening channel(%d), device %p\n", sc->channel, dev->device_handle);
		rc = novacom_open_channel(dev->device_handle, sc->channel, 1);
		if (rc >= 0) {
			rc = novacom_set_read_callback(dev->device_handle, sc->channel, (novacom_read_callback)&socketcmd_read_callback, dev);
			if (rc < 0) {
				/* error creating or setting the callback, which can happen as
				 * a result of a race with the device going away, abort */
				sc->channel = -1;
				sc->close = 1;
				TRACEF("hit create channel/device going away race\n");
			}
			TRACEF("socketchan::created: %p, socket %d, novacom %d, device %p\n", sc, sc->socket, sc->channel, dev->device_handle);
		} else {
			TRACEF("Unable to create channel: rc(%d)\n", rc);
			platform_free(dev->cmd_chan);
			dev->cmd_chan = NULL;
		}
	}

	if(rc < 0) {
		goto out;
	}

	LTRACEF("opened device service control channel\n");

	/* tokens exchange... */
	char cmd[128];
	char hash[SHA1_HASH_STRSIZE+1];
	memset(hash, 0, sizeof(hash));
	rc = tokenstorage_readhash(dev->devid, dev->sessionid, hash, SHA1_HASH_STRSIZE);
	if(rc < 0) {
		/* host does not have installed device token */
		goto out;
	}

	snprintf(cmd, sizeof(cmd), "logint dev://%s %s", dev->devid, hash);
	rc = novacom_register_command(INVALID_SOCKET, cmd);
	/* no errors: remove dev reference since it is handled by cmd queue now */
	if (!rc) {
		remove_device_ref(dev);
	}

out:
	/* error: remove device reference, enable listing */
	if (rc < 0) {
		dev->inactive = 0;
		remove_device_ref(dev);
	}
	return NULL;
}

/*
 * @brief: handle accepting new command to device
 * @ret -1 error
 *       0 postponeddone
 *       1 done
 */
static int novacom_register_command(SOCKET cmdsocket, const char *_cmd)
{
	int rc;
	novacom_command_url_t *url = NULL;
	active_device_t *dev = NULL;
	active_device_t *devcmd = NULL;
	bool first = false;
	char cmd[128];

	/* clear */
	memset(cmd, 0, sizeof(cmd));
	/* receive command */
	if ( INVALID_SOCKET != cmdsocket ) {
		rc = recv(cmdsocket, cmd, (sizeof(cmd) - 1), 0);
		if (-1 != rc) {
			int i=0;
			/* check buffer to contain null terminated string (strnlen) */
			rc = (int)(sizeof(cmd) - 1);
			for(i = 0; i < rc; i++) {
				if(cmd[i] == 0)
					break;
			}
	
			LTRACEF("index %d/%d\n", i, rc);
			if ( rc == i ) {
				rc = -1;
			}
		}
		if(-1 == rc) {
			LTRACEF("invalid command\n");
			return -1;
		}
	} else if (_cmd) {
		strncpy(cmd, _cmd, sizeof(cmd) - 1);
	} else {
		return -1;
	}
	LTRACEF("command '%.*s'\n", sizeof(cmd) - 1, cmd);

	/* service command */
	rc = novacom_service_command(cmdsocket, cmd, &url);

	/* error or done: return error */
	if (!url) {
		LTRACEF("invalid command\n");
		return -1;
	}

	/* url returned for remote execution, lock dev list first */
	platform_mutex_lock(&device_list_mutex);

	/* see if device is registered */
	for (dev = device_list; dev; dev = dev->next) {
		if( (!url->path) || (!strlen(url->path)) ) {
			devcmd = dev;
			break;
		} else if ( 0 == strncasecmp(dev->devid, url->path, strlen(dev->devid)) ) {
			devcmd = dev;
			break;
		}
	}

	/* did not find device */
	if (!devcmd) {
		LTRACEF("unable to find corresponding device\n");
		rc = -1;
		goto out;
	}

	/* session id inactive: old device */
	if (!devcmd->sessionid) {
		LTRACEF("Session id missing: no restrictions...\n");
		rc = -1;
		goto out;
	}

	LTRACEF("nduid:%s, cmd:%s, socket %d\n", devcmd->devid, url->verb, cmdsocket);

	/* alloc mem */
	socketcmd_t *sc = (socketcmd_t *)platform_calloc(sizeof(socketcmd_t));
	if (!sc) {
		rc = -1;
		goto out;
	}

	/* fill out */
	sc->channel = PMUX_CHANNEL_CMDSERVICE;
	sc->cmd_id = dev->cmd_serviced++;
	sc->socket = cmdsocket;
	sc->url = url;
	novacom_retain_device_handle(devcmd->device_handle);
	sc->device_handle = devcmd->device_handle;

	/* add device reference on first command*/
	if ( TAILQ_EMPTY(&dev->cmd_queue) ) {
		add_device_ref(dev);
		first = true;
	}

	/* add to queue */
	TAILQ_INSERT_TAIL(&dev->cmd_queue, sc, entries);

	LTRACEF("added command to queue\n");
	LTRACEF("sc  %p, socket %d, service_num %d, device %p\n",
			sc, sc->socket, sc->cmd_id, sc->device_handle);

	/*debug queue */
#if 0
	{
		/* travel command queue */
		if ( !TAILQ_EMPTY(&dev->cmd_queue) ) {
			socketcmd_t *item;
			/* remove commands not processed yet */
			for (item = TAILQ_FIRST(&dev->cmd_queue); item != NULL; item = TAILQ_NEXT(item, entries) ) {
				LTRACEF("queue entry: url->verb(%s)\n", item->url->verb?item->url->verb:"error entry");
			}
		}
	}
#endif

out:
	/* unlock dev list */
	platform_mutex_unlock(&device_list_mutex);

	/* errors?: free resources */
	if (rc == -1) {
		/* update client */
		if (INVALID_SOCKET != cmdsocket) {
			const char *response = "invalid command\n";
			(void )send(cmdsocket, response, strlen(response) + 1, 0);
		}
		/* free urls */
		free_url(url);
	} else if (true == first) {
		/* it is first command in queue: call queue process directly */
		rc = novacom_process_cmdqueue(dev);
	}

	return rc;
}

/*
 * @brief: executes queued commands
 */
static int novacom_process_cmdqueue(active_device_t *dev)
{
	socketcmd_t *sc = NULL;
	int rc=0;

	LTRACEF("processing queue...\n");

	/* any pending command in queue until postponed command found */
	for(;;) {
		if ( !TAILQ_EMPTY(&dev->cmd_queue) ) {
			LTRACEF("pending commands, processing...\n");
			/* get first command in queue */
			sc = TAILQ_FIRST( &dev->cmd_queue);
			/* service */
			rc = novacom_service_url(dev->device_handle, dev->sessionid, sc->socket, sc->channel, sc->url);
			if (rc) {
				/* send error */
				LTRACEF("command failed...\n");
				rc = send(sc->socket, NOVACOMDMSG_REPLY_ERR, strlen(NOVACOMDMSG_REPLY_ERR)+1, 0);
				/* remove processed url from queue */
				TAILQ_REMOVE(&dev->cmd_queue, sc, entries);
				/* free command resources */
				destroy_socketcmd(sc);
			} else {
				LTRACEF("postponed command: wait completion...\n");
				break;
			}
		} else {
			LTRACEF("no more commands, remove device reference\n");
			/* queue is empty, remove device reference */
			remove_device_ref(dev);
			rc = -1;
			break;
		}

	}

	return 0;
}

/*
 * @brief: handles write callback on channel
 */
void socketcmd_write_callback(device_handle_t device_handle, uint32_t channel, int err, void *cookie)
{
	unblock_main_loop();
}

/*
 * @brief: handles read callback from channel
 */
static int socketcmd_read_callback(device_handle_t device_handle, uint32_t channel, int err, const void *buf, size_t len, void *cookie)
{
	active_device_t *dev = (active_device_t *)cookie;
	socketcmd_t *sc = NULL;
	int rc;

	if (err < 0) {
		LTRACEF("novacom channel %d closed\n", channel);
		unblock_main_loop();
		return 0;
	}

	if ( TAILQ_EMPTY(&dev->cmd_queue) ) {
		LTRACEF("queue empty\n");
		return 0;
	}

	sc = TAILQ_FIRST( &dev->cmd_queue);
	LTRACEF("socketcmd::read_cb: %p, socket %d, service_num %d, device %p\n",
			sc, sc->socket, sc->cmd_id, sc->device_handle);

	/* process reply */
	rc = novacom_service_reply(dev->devid, sc->url, buf, len);

	/* notify client if any */
	if (sc->socket != INVALID_SOCKET) {
		LTRACEF("command %s...\n", rc?"failed":"succeeded");
		if (rc) {
                        char *msg="Novacom device login failed - incorrect password provided.";
                        rc = send(sc->socket, msg, strlen(msg)+1, 0);
		} else {
			rc = send(sc->socket, NOVACOMDMSG_REPLY_OK, strlen(NOVACOMDMSG_REPLY_OK)+1, 0);
		}
	}

	/* remove processed url from queue */
	TAILQ_REMOVE(&dev->cmd_queue, sc, entries);

	/* free command resources */
	destroy_socketcmd(sc);

	/* process pending commands queue */
	novacom_process_cmdqueue(dev);

	return 0;
}

/*
 * @brief destroys socketcmd_t
 */
static void destroy_socketcmd(socketcmd_t *sc)
{
	TRACEF("socketcmd::destroy: %p, socket %d, service_num %d, device %p\n",
			sc, sc->socket, sc->cmd_id, sc->device_handle);

	/* close client socket */
	if (sc->socket != INVALID_SOCKET) {
		close(sc->socket);
		sc->socket = INVALID_SOCKET;
	}

	/* release device handle */
	if (sc->device_handle) {
		novacom_release_device_handle(sc->device_handle);
		sc->device_handle = NULL;
	}

	/* free url attributes */
	free_url(sc->url);
	sc->url = NULL;

	/* free command */
	platform_free(sc);
}

#endif

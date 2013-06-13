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

#ifndef __LIB_NOVACOM_H
#define __LIB_NOVACOM_H

#include <sys/types.h>
#include <stdint.h>

#include <buf_queue.h>


/* ports */
#define NOVACOM_DEVLISTPORT			6968
#define NOVACOM_INETPORT			6969
#define NOVACOM_LOGPORT				6970
#define NOVACOM_CTRLPORT			6971
#define NOVACOM_UNBLOCKPORT			12311
#define NOVACOM_OPTPORT				64022

/* nduid */
#define NOVACOM_NDUID_BYTELEN	(20)							///< nduid byte array representation
#define NOVACOM_NDUID_CHRLEN	(40)							///< nduid character array representation
#define NOVACOM_NDUID_STRLEN	(NOVACOM_NDUID_CHRLEN + 1)		///< nduid string representation

/* messages */
#define NOVACOMDMSG_AUTH_REQUEST	"req:auth\n"
#define NOVACOMDMSG_REPLY_OK		"ok 0\n"
#define NOVACOMDMSG_REPLY_NOK		"rep:nok\n"
#define NOVACOMDMSG_REPLY_ERR		"err -1\n"


#if 0
#ifndef container_of
#define container_of(ptr, type, member) ({          \
        const typeof(((type *)0)->member)*__mptr = (ptr);    \
                     (type *)((char *)__mptr - offsetof(type, member)); })
#endif
#endif
/* */
typedef struct mux_instance * device_handle_t;
extern int g_recovery_timeout;
extern int g_usbio_retry_timeout;
extern int g_usbio_retry_delay;
extern int g_cpuaffinity;
/* */
const char * novacom_nduid(void); /* internal nduid */
char * novacom_rnduid(device_handle_t device_handle); /* remote nduid */
int novacom_init(void); // called once per session
uint32_t novacom_get_new_sessionid();

/* device */
void novacom_retain_device_handle(device_handle_t device_handle);
void novacom_release_device_handle(device_handle_t device_handle);

/* channel read/write routines */
int novacom_queue_tx_chain(device_handle_t mux, int chan, buf_entry_t *chain);

	/* synchronous read/write */
int novacom_write_channel_sync(device_handle_t device_handle, uint32_t channel, const void *buf, size_t len);
ssize_t novacom_read_channel_sync(device_handle_t device_handle, uint32_t channel, void *buf, size_t len, size_t min);

	/* async read/write */
typedef void (*novacom_async_callback)(device_handle_t device_handle, uint32_t channel, int error, void *);

#define ASYNC_FLAG_COPY 1
int novacom_write_channel_async(device_handle_t device_handle, uint32_t channel, const void *buf, size_t len, unsigned int flags, novacom_async_callback, void *);

	/* read callback, return < 0 to nak transfer */
typedef int (*novacom_read_callback)(device_handle_t device_handle, uint32_t channel, int error, const void *buf, size_t len, void *);

	/* reads */
int novacom_set_read_callback(device_handle_t device_handle, uint32_t channel, novacom_read_callback, void *cookie);

	/* get the current tx queue length */
size_t novacom_tx_queue_len(device_handle_t device_handle, uint32_t channel);

	/* notifications */
enum novacom_notification {
	NOVACOM_NOTIFY_CHANNEL_ACTIVE,
	NOVACOM_NOTIFY_CHANNEL_INACTIVE
};

typedef void (*novacom_notify_callback)(device_handle_t device_handle, uint32_t channel, enum novacom_notification, void *cookie);

int novacom_register_for_notifications(device_handle_t device_handle, uint32_t channel, novacom_notify_callback, void *cookie);

	/* channel close callback */
typedef void (*novacom_closechan_cb)(void *cookie);
	/* set/clear cb */
int novacom_set_closechannel_callback  (device_handle_t device_handle, uint32_t channel, novacom_closechan_cb, void *cookie);
int novacom_clear_closechannel_callback(device_handle_t device_handle, uint32_t channel, novacom_closechan_cb, void *cookie);

	/* channel control */ 
int novacom_open_channel(device_handle_t device_handle, uint32_t channel, int command);
int novacom_open_temp_channel(device_handle_t device_handle, uint32_t *channel, int command); // allocate a channel
int novacom_close_channel(device_handle_t device_handle, uint32_t channel);

/* debug */
#define PMUX_RX 0
#define PMUX_TX 1
void novacom_dump_packet(const void *buf, size_t len, int txrx);

/* transport level interface */
struct novacom_tx_packet {
	size_t len;
	char *buf;
};

/* packet */
#define TX_NO_PACKET -1

int novacom_prepare_tx_packet(device_handle_t device_handle, struct novacom_tx_packet *packet);
int novacom_get_tx_packet(device_handle_t device_handle, struct novacom_tx_packet *packet, int timeout);

#define PACKET_TYPE_NULL 0
#define PACKET_TYPE_ERR 1
#define PACKET_TYPE_ACK 2
#define PACKET_TYPE_DATA 3
#define PACKET_TYPE_PROTOCOL 4
#define PACKET_TYPE_BADPACKET -1

int novacom_process_packet(device_handle_t device_handle, const char *buf, int len);

device_handle_t novacom_go_online(const char *nduid, const char *conntype, const char *devtype, char *devdata);
void novacom_go_offline(device_handle_t device_handle);


/* device registration info */
typedef struct novacom_device_reginfo {
	const char *devid_string;	/* device id */
	const char *conntype;		/* connection type */
	const char *devtype;		/* device type */
	const char *devmode;		/* device operation mode */
	const char *sessionid;		/* session id */
} novacom_device_reginfo_t;

/* register/unregister a device with the sockets layer */
/* thread safe from any context */
void novacom_register_device(device_handle_t device_handle, novacom_device_reginfo_t *t_dev_reginfo);
int novacom_unregister_device(device_handle_t device_handle);

/* output device list */
void dump_device_list(SOCKET socket);


/* command server */
typedef struct novacom_command_url {
	char *verb;
	char **verbargs;
	char *scheme;
	char *path;
	unsigned int argcount;
	char **args;

	char *string;
} novacom_command_url_t;

// <verb> <verbarg0> <verbarg1> ... <scheme>://<path> <arg0> <arg1> ...

/* command parser: commands.c */
int parse_command(const char *_string, size_t len, struct novacom_command_url **_url);
/* free url resources */
void free_url(novacom_command_url_t *url);

#endif


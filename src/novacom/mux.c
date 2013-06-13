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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>

#include <novacom.h>
#include <debug.h>

#include <platform.h>
#include "novacom_p.h"
#include "mux.h"
#include <buf_queue.h>
#include <transport.h>

#define LOCAL_TRACE 0
#define TRACE_COALESCE 0

#define RETRANSMIT_WAIT_PERIOD 50 // in ms

enum {
	CHANNEL_STATE_OPEN,
	CHANNEL_STATE_CLOSING
};

enum {
    SEND_CTRLCMD_ASYNC,
	SEND_CTRLCMD_SYNC
};

struct novacom_channel {
	struct novacom_channel *next;
	uint32_t num;
	int state;

	novacom_notify_callback notify;
	void *notify_cookie;

	// channel close callbacks
	buf_queue_t *close_callbacks;

	// tx data
	buf_queue_t *tx_queue;
	uint32_t acked_tx_sequence;
	uint32_t last_tx_sequence;
	int retransmit_len;
	platform_time_t retransmit_time;

	// rx data
	uint32_t rx_sequence;
	novacom_read_callback rx_callback;
	void *rx_callback_cookie;
	int has_pending_ack;
};

struct mux_instance {
	struct mux_instance *next;
	platform_mutex_t mux_mutex;
	volatile bool novacom_online;
	struct novacom_channel *channel_list;
	uint32_t next_temp_channel;
	platform_event_t wake_tx_event;
	volatile int refcount;
};

// local functions
static struct novacom_channel *find_channel(device_handle_t mux, uint32_t num);
static struct novacom_channel *create_channel(device_handle_t mux, uint32_t num, int command, bool bypass_online);
static int send_control_message(device_handle_t mux, int sync, uint32_t op, uint32_t channel);
static void novacom_shutdown_channel(device_handle_t mux, struct novacom_channel *c, bool send_notification);
static int control_channel_rx_callback(device_handle_t mux, uint32_t channel, int err, const void *buf, size_t len, void *cookie);
static void novacom_free_mux_instance(device_handle_t mux);


uint32_t adler(uint8_t *data, size_t len)
{
	uint32_t a = 1, b = 0;

	while (len > 0) {
		size_t tlen = len > 5550 ? 5550 : len;
		len -= tlen;
		do {
			a += *data++;
			b += a;
		} while (--tlen);

		a %= 65521;
		b %= 65521;
	}
	return (b << 16) | a;
}

void novacom_retain_device_handle(device_handle_t mux)
{
	platform_atomic_add(&mux->refcount, 1);
}

void novacom_release_device_handle(device_handle_t mux)
{
	int old = platform_atomic_add(&mux->refcount, -1);
	if (old == 1) {
		novacom_free_mux_instance(mux);
	}
}

int novacom_queue_tx_chain(device_handle_t mux, int chan, buf_entry_t *chain)
{
	struct novacom_channel *c;
	
	platform_mutex_lock(&mux->mux_mutex);
	c = find_channel(mux, chan);
	if (!c) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	bufq_append_chain(c->tx_queue, chain);

	platform_event_signal(&mux->wake_tx_event);

	platform_mutex_unlock(&mux->mux_mutex);

	return 0;
}

// This is a bit silly. Rewrite calling code to use bufq-style callbacks later.
struct tx_callback_callback_args {
	novacom_async_callback callback;
	void *cookie;
	int channel;
	device_handle_t device_handle;
};

static void tx_callback_callback(void *cookie)
{
	struct tx_callback_callback_args *tcc_args = (struct tx_callback_callback_args *)cookie;
	(tcc_args->callback)(tcc_args->device_handle, tcc_args->channel, 0, tcc_args->cookie);
	platform_free(tcc_args);
}

static int novacom_queue_tx(device_handle_t mux, int chan, const void *buf, size_t len, uint flags, novacom_async_callback callback, void *cookie)
{
	struct tx_callback_callback_args *tcc_args = NULL;
	buf_entry_t *chain = NULL;

	// XXX handle flags & ASYNC_FLAG_COPY instead of always copying
	bufc_append_data(&chain, buf, len);

	if (callback) {
		tcc_args = (struct tx_callback_callback_args*)platform_alloc(sizeof(struct tx_callback_callback_args));
		platform_assert(tcc_args);
		tcc_args->callback = callback;
		tcc_args->cookie = cookie;
		tcc_args->channel = chan;
		tcc_args->device_handle = mux;
		bufc_append_callback(&chain, &tx_callback_callback, (void *)tcc_args);
	}

	return novacom_queue_tx_chain(mux, chan, chain);
}

int novacom_write_channel_async(device_handle_t mux, uint32_t chan, const void *buf, size_t len, uint flags, novacom_async_callback callback, void *cookie)
{
	return novacom_queue_tx(mux, chan, buf, len, flags, callback, cookie);
}

size_t novacom_tx_queue_len(device_handle_t mux, uint32_t chan)
{
	platform_mutex_lock(&mux->mux_mutex);
	struct novacom_channel *c = find_channel(mux, chan);
	if (!c) {
		platform_mutex_unlock(&mux->mux_mutex);
		return 0;
	}
	
	size_t len = bufq_len(c->tx_queue);

	platform_mutex_unlock(&mux->mux_mutex);

	return len;
}

struct sync_write_data {
	platform_event_t *event;
	int error;
};

static void sync_write_callback(device_handle_t mux, uint32_t chan, int error, void *cookie)
{
	struct sync_write_data *data = (struct sync_write_data *)cookie;

	data->error = error;
	platform_event_signal(data->event);
}

int novacom_write_channel_sync(device_handle_t mux, uint32_t chan, const void *buf, size_t len)
{
	platform_event_t event;

	platform_event_create(&event);
	platform_event_unsignal(&event);

	struct sync_write_data data;
	data.event = &event;
	data.error = 0;
	int rc = novacom_write_channel_async(mux, chan, buf, len, 0, &sync_write_callback, (void *)&data);
	if (rc < 0)
		goto done;

	platform_event_wait(&event);
	#if 0   //we cannot timeout this time, because the "data" is in stack 
	if (platform_event_wait_timeout(&event, TRANSPORT_RECOVERY_TIMEOUT*1000*3 + 500)) {
		data.error = -1;
		TRACEF("%s: detected timeout, device has something wrong!!!\n", __FUNCTION__);
	}
	#endif
	rc = data.error;

done:
	platform_event_destroy(&event);

	return rc;
}

struct sync_read_data {
	platform_event_t *event;
	int error;
	char *buf;
	size_t buflen;
	size_t pos;
	size_t min;		///< minimum number of bytes to read
};

int novacom_set_read_callback(device_handle_t mux, uint32_t chan, novacom_read_callback callback, void *cookie)
{
	struct novacom_channel *c;

	if(!mux)
		return -1;

	platform_mutex_lock(&mux->mux_mutex);
	c = find_channel(mux, chan);
	if (!c) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	c->rx_callback = callback;
	c->rx_callback_cookie = cookie;

	platform_mutex_unlock(&mux->mux_mutex);

	return 0;
}

int novacom_register_for_notifications(device_handle_t mux, uint32_t chan, novacom_notify_callback callback, void *cookie)
{
	struct novacom_channel *c;

	if(!mux)
		return -1;

	platform_mutex_lock(&mux->mux_mutex);
	c = find_channel(mux, chan);
	if (!c) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	if (c->state != CHANNEL_STATE_OPEN) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	if (c->notify && callback) TRACEF("overwriting channel notification callback\n");

	c->notify = callback;
	c->notify_cookie = cookie;
	platform_mutex_unlock(&mux->mux_mutex);
	return 0;
}

static void broadcast_notification(device_handle_t mux, enum novacom_notification notification)
{
	struct novacom_channel *c;

	platform_mutex_lock(&mux->mux_mutex);
	for (c = mux->channel_list; c; c = c->next) {
		if (c->notify) {
			c->notify(mux, c->num, notification, c->notify_cookie);
		}
	}
	platform_mutex_unlock(&mux->mux_mutex);
}

/*
 * novacom_set_closechannel_callback
 * callback notification on channel close
 */
int novacom_set_closechannel_callback(device_handle_t mux, uint32_t chan, novacom_closechan_cb callback, void *cookie)
{
	struct novacom_channel *c = NULL;
	buf_entry_t *chain = NULL;

	platform_mutex_lock(&mux->mux_mutex);
	c = find_channel(mux, chan);
	if ((!c) || c->state == CHANNEL_STATE_CLOSING) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	bufc_append_callback(&chain, callback, cookie);
	bufq_append_chain(c->close_callbacks, chain);

	platform_mutex_unlock(&mux->mux_mutex);
	
	return 0;
}

/*
 * novacom_clear_closechannel_callback
 * !!! expected that cookie is dynamically allocated memory and must be freed (temp limitation)!!!
 */
int novacom_clear_closechannel_callback(device_handle_t mux, uint32_t chan, novacom_closechan_cb callback, void *cookie)
{
	struct novacom_channel *c = NULL;
	buf_queue_t *queue = NULL;

	platform_mutex_lock(&mux->mux_mutex);
	c = find_channel(mux, chan);
	if ((!c) || c->state == CHANNEL_STATE_CLOSING) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	queue = c->close_callbacks;

	if(queue) {
		platform_mutex_lock(&queue->lock);
		buf_entry_t *entry = queue->head;
		/* queue travel */
		while (entry) {
			/* clear cb, free cookie */
			if(		(entry->callback == callback)
				&&	(entry->cookie == cookie) ) {
				entry->callback = NULL;
				entry->cookie = NULL;
				platform_free(cookie);
				break;
			}
			entry = entry->next;
		}

		platform_mutex_unlock(&queue->lock);
	}


	platform_mutex_unlock(&mux->mux_mutex);

	return 0;
}

int novacom_process_packet(device_handle_t mux, const char *buf, int len)
{
	int ret;
	struct pmux_header *header = (struct pmux_header *)buf;

	// check the header
	if (header->magic != PMUX_MAGIC)
		return PACKET_TYPE_ERR;
	if (header->version != PMUX_VERSION)
		return PACKET_TYPE_ERR;
	if (header->total_len > (uint32_t)len)
		return PACKET_TYPE_ERR;
	if (header->payload_len > header->total_len)
		return PACKET_TYPE_ERR;

	// is it a null packet?
	if (header->channel == PMUX_CHANNEL_NULL)
		return PACKET_TYPE_NULL;

	ret = PACKET_TYPE_NULL;

	platform_mutex_lock(&mux->mux_mutex);
	struct novacom_channel *c = find_channel(mux, header->channel);
	if (!c) {
		// queue a CONTROL_CLOSED
		if (header->channel > PMUX_CHANNEL_MAX_FIXED) {
			//regular channels
			send_control_message(mux, SEND_CTRLCMD_ASYNC, PMUX_CONTROL_CHANNEL_CLOSED, header->channel);
		}
		else if(header->channel > PMUX_CHANNEL_CONTROL) {
			//util control channels
			send_control_message(mux, SEND_CTRLCMD_ASYNC, PMUX_CONTROL_CHANNEL_CLOSED, header->channel);
		}
		ret = PACKET_TYPE_ERR;
	} else {
		bool shutdown_channel = false;
		if (header->flags & PMUX_FLAG_ACK) {
			// it's an ack, see if it is in sequence for us
			if ((header->sequence > c->acked_tx_sequence) && (header->sequence <= c->last_tx_sequence)) {
				// in sequence, process it
				c->acked_tx_sequence = header->sequence;

				// if acked_tx_sequence is updated to last_tx_sequence, consume the bytes off the tx_queue
				// This implicitly handles queued callbacks
				bufq_consume_nonblock(c->tx_queue, c->retransmit_len);

				// probably unblocks us for more tx packets
				platform_event_signal(&mux->wake_tx_event);

				// if we have a pending channel close, and this was the last transaction, shut it down
				if ((c->state == CHANNEL_STATE_CLOSING) && (bufq_len(c->tx_queue) == 0))
					shutdown_channel = true;
			} else {
				// out of sequence, drop it
				;
#if HOST
				TRACEL(LOG_TRACE,"[%d] Out of sequence ACK: h->seq: %d, c->rx_seq: %d, h->flags: %d, h->channel: %d,c->last_tx: %d, c->acked_tx: %d\n",c->num,header->sequence,c->rx_sequence,header->flags,header->channel,c->last_tx_sequence,c->acked_tx_sequence);
#endif

			}
			ret = PACKET_TYPE_ACK;
		} else if (header->flags == 0) {
			// regular old receive packet
			bool do_ack = false;
			if (c->state == CHANNEL_STATE_CLOSING) {
				// if we're closing, ack everything. rx callbacks aren't active anymore
				c->rx_sequence = header->sequence;
				do_ack = true;
			} else if (c->rx_callback) {
				if (header->sequence == c->rx_sequence) {
					// we've already seen it, but maybe our ack was lost,
					// reack it
#if HOST
					TRACEL(LOG_TRACE,"[%d] RE-ACK: h->seq: %d, c->rx_seq: %d, h->flags: %d, h->channel: %d,c->last_tx: %d, c->acked_tx: %d\n",c->num,header->sequence,c->rx_sequence,header->flags,header->channel,c->last_tx_sequence,c->acked_tx_sequence);
#endif
					do_ack = true;
				} else if (header->sequence == (c->rx_sequence + 1)) {
					uint32_t crc;
					// next packet in the sequence, call it back
					if ((header->crc != 0) && ((crc = adler(header->data, header->payload_len)) != header->crc)) {
						TRACEF("*** CHECKSUM MISMATCH *** (that's a bad thing): header->crc(%08x), crc(%08x)\n", header->crc, crc);
						do_ack = false;
					} else if (c->rx_callback(mux, header->channel, 0, header->data, header->payload_len, c->rx_callback_cookie) >= 0) {
						// ack the sequence if the callback signals okay
						c->rx_sequence = header->sequence; // push up the sequence
						do_ack = true;
					}
				} else {
					// XXX out of sequence
					// send some sort of error to the other side?
					TRACEL(LOG_ERROR,"[%d] RX PKT OUT OF SEQUENCE (this is a very weird and bad thing): h->seq: %d, c->rx_seq: %d, h->flags: %d, h->channel: %d,c->last_tx: %d, c->acked_tx: %d\n",c->num,header->sequence,c->rx_sequence,header->flags,header->channel,c->last_tx_sequence,c->acked_tx_sequence);
				}
			} else {
				// don't ack it, just drop it on the floor and let the other side retransmit
				;
			}

			// queue an ack
			if (do_ack) {
				c->has_pending_ack = true;
				platform_event_signal(&mux->wake_tx_event);
			}

			ret = PACKET_TYPE_DATA;
		}

		if (shutdown_channel) {
			novacom_shutdown_channel(mux, c, true);
		}
	} // if (c)
	platform_mutex_unlock(&mux->mux_mutex);

	return ret;
}

static int novacom_prepare_tx_packet_ack(device_handle_t mux, struct novacom_channel *c, struct novacom_tx_packet *packet)
{
	struct pmux_header *header = (struct pmux_header *)packet->buf;

	platform_assert(c->has_pending_ack);

	header->magic = PMUX_MAGIC;
	header->version = PMUX_VERSION;
	header->flags = PMUX_FLAG_ACK;
	header->channel = c->num;
	header->sequence = c->rx_sequence; // ack up to the last rx sequence
	header->payload_len = 0;
	header->total_len = packet->len = sizeof(struct pmux_header);
	header->crc = 0;

	return 0;
}

int novacom_prepare_tx_packet(device_handle_t mux, struct novacom_tx_packet *packet)
{
	struct novacom_channel *c;
	struct novacom_channel *active_channel = NULL;
	bool retransmit = false;

	platform_mutex_lock(&mux->mux_mutex);

	// see if we have any acks
	for (c = mux->channel_list; c; c = c->next) {
		if (c->has_pending_ack) {
			if (novacom_prepare_tx_packet_ack(mux, c, packet) == 0) {
				c->has_pending_ack = false;
				platform_mutex_unlock(&mux->mux_mutex);
				return 0;
			}
		}
	}

	// try to find a channel with retransmit data
	platform_time_t now; 

	platform_get_time(&now);
	for (c = mux->channel_list; c; c = c->next) {
		if (c->last_tx_sequence != c->acked_tx_sequence) {
			if (platform_delta_time_msecs(&c->retransmit_time, &now) >= RETRANSMIT_WAIT_PERIOD) {
				LTRACEF("[%d] retransmitting %d (%d)...\n",c->num,c->last_tx_sequence,c->retransmit_len);
				retransmit = true;
				active_channel = c;
				break;
			}
		}
	}

	// try to find a channel with tx data
	if(active_channel == NULL) {
		for (c = mux->channel_list; c; c = c->next) {
			if ((c->last_tx_sequence == c->acked_tx_sequence) && bufq_len(c->tx_queue)) {
				active_channel = c;
			}
		}
	}

	if (active_channel == NULL) {
		// nothing to send

		// no data is available, next person to ask will get blocked
		platform_event_unsignal(&mux->wake_tx_event);

		platform_mutex_unlock(&mux->mux_mutex);
		return TX_NO_PACKET;
	}

	// start to put together a packet
	struct pmux_header *header = (struct pmux_header *)packet->buf;

	header->magic = PMUX_MAGIC;
	header->version = PMUX_VERSION;
	header->flags = 0;
	header->channel = active_channel->num;
	if (!retransmit) 
		active_channel->last_tx_sequence++;
	header->sequence = active_channel->last_tx_sequence;

	if (retransmit) {
		header->payload_len = active_channel->retransmit_len;
		bufq_peek_nonblock(active_channel->tx_queue, (char *)header->data, active_channel->retransmit_len);
	} else {
		if (active_channel->num > PMUX_CHANNEL_MAX_FIXED) {
			header->payload_len = active_channel->retransmit_len =
				bufq_peek_nonblock(active_channel->tx_queue, (char *)header->data, (packet->len - sizeof(struct pmux_header)));
		} else {
			// For control channels, transmit only one buf at a time
			header->payload_len = active_channel->retransmit_len =
				bufq_peek_onechunk_nonblock(active_channel->tx_queue, (char *)header->data, (packet->len - sizeof(struct pmux_header)));
		}
	}
	header->total_len = packet->len = header->payload_len + sizeof(struct pmux_header);

	// start the retransmit 'timer'
	active_channel->retransmit_time = now;

	header->crc = adler(header->data, header->payload_len);
//	header->crc = 0;

	/// LTRACEF("tx packet: payload len %d, len %d, crc %08x\n", header->payload_len, header->total_len, header->crc);
	platform_mutex_unlock(&mux->mux_mutex);
	return 0;
}

// same as above, but sleep until we get a packet to send or return error on device shutdown
int novacom_get_tx_packet(device_handle_t mux, struct novacom_tx_packet *packet, int timeout)
{
	platform_time_t start;

	if (timeout >= 0)
		platform_get_time(&start);

	platform_mutex_lock(&mux->mux_mutex);
	for (;;) {
		if (novacom_prepare_tx_packet(mux, packet) == 0) {
			platform_mutex_unlock(&mux->mux_mutex);
			return 0;
		}

		// must unlock mux so packets can be queued.
		platform_mutex_unlock(&mux->mux_mutex);
		// sleep until a packet is added, or 50ms to poll for retransmits
		platform_event_wait_timeout(&mux->wake_tx_event, RETRANSMIT_WAIT_PERIOD);
		platform_mutex_lock(&mux->mux_mutex);

		if (!mux->novacom_online)
			break;
		
		// see if we've been waiting long enough
		if (timeout >= 0) {
			platform_time_t now;

			platform_get_time(&now);

			int delta = platform_delta_time_msecs(&start, &now);
			if (delta >= timeout)
				break;
		}

		// loop back around to look for a packet or sleep again
	}

	// got nuthin
	platform_mutex_unlock(&mux->mux_mutex);
	return TX_NO_PACKET;
}

/*
 * parse device data within sync packet(look for data tokens) 
 */
static char *parse_devdata(const char *devdata, const char *datatoken_id, char *data, int len)
{
	char *ptr = NULL;

	/* check input */
	if(!devdata) {
		return NULL;
	}

	/* alloc mem for string copy */
	char *scpy = platform_strdup(devdata);
	if(!scpy) {
		return NULL;
	}

	/* search for token */
	char *str = strstr(scpy, datatoken_id);
	if( str ) {
		str += strlen(datatoken_id);
		char *substr = strtok(str, " \t\n");
		if(substr) {
			memset(data, 0, len);
			strncpy(data, substr, len - 1);
			if(strlen(data)){
				ptr = data;
				LTRACEF("%s:%s\n", datatoken_id, data);
			}
		}
	}

	platform_free((void *)scpy);

	return ptr;
}

device_handle_t novacom_go_online(const char *nduid, const char *conntype, const char *devtype, char *devdata)
{
	device_handle_t mux;
	novacom_device_reginfo_t t_dev_reginfo;
	const char *device = NULL;
	char devname[64] = {0};
	char devmode[16] = {0};
	char sessionid[16] = {0};
	// keep this separate for the return value
	// just in case the mux somehow gets deleted out from under us

	memset(&t_dev_reginfo, 0, sizeof(t_dev_reginfo));
	if (!(mux = (device_handle_t)platform_calloc(sizeof(struct mux_instance))))
		return NULL; // XXX should probably bail out or something

	platform_mutex_init(&mux->mux_mutex);
	platform_mutex_lock(&mux->mux_mutex);
	platform_event_create(&mux->wake_tx_event);

	novacom_retain_device_handle(mux);

	TRACEL(LOG_ALWAYS, "%s:%s\n", __PRETTY_FUNCTION__, nduid);

	mux->novacom_online = true;

	/* recover devtype */
	if( (devtype) && strlen(devtype) ) {
		device = devtype;
	}
	if(devdata) {
		char *ptr;
		ptr = parse_devdata(devdata, NOVACOMD_DATATOKEN_ID, devname, sizeof(devname));
		if(ptr) {
			device = devname;
			TRACEF("%s%s/(%s)\n", NOVACOMD_DATATOKEN_ID, device, devtype?devtype:"unknown");
		}
		ptr = parse_devdata(devdata, NOVACOMD_DATATOKEN_MODE, devmode, sizeof(devmode));
		if(ptr) {
			TRACEF("%s%s\n", NOVACOMD_DATATOKEN_MODE, devmode);
		}
		ptr = parse_devdata(devdata, NOVACOMD_DATATOKEN_SESSION, sessionid, sizeof(sessionid));
		if(ptr) {
			TRACEF("%s%s\n", NOVACOMD_DATATOKEN_SESSION, sessionid);
		}
	}
	/* register device */
	t_dev_reginfo.devid_string = nduid;
	t_dev_reginfo.conntype = conntype;
	t_dev_reginfo.devtype = device?device:"[unknown]";
	t_dev_reginfo.devmode = devmode;
	t_dev_reginfo.sessionid = sessionid;
	novacom_register_device(mux, &t_dev_reginfo);

	mux->channel_list = NULL;
#if HOST
	mux->next_temp_channel = PMUX_CHANNEL_HOST_BASE;
#elif DEVICE
	mux->next_temp_channel = PMUX_CHANNEL_DEVICE_BASE;
#else 
#error need to define HOST or DEVICE
#endif

	create_channel(mux, PMUX_CHANNEL_CONTROL, false, true);
	novacom_set_read_callback(mux, PMUX_CHANNEL_CONTROL, &control_channel_rx_callback, NULL);

	// notify to all the channels that we're going active
	broadcast_notification(mux, NOVACOM_NOTIFY_CHANNEL_ACTIVE);

	platform_mutex_unlock(&mux->mux_mutex);
	return mux;
}

void novacom_go_offline(device_handle_t mux)
{
	platform_mutex_lock(&mux->mux_mutex);

	TRACEF("going offline\n");

	// IMPORTANT must do this before attempting to remove the mux from the list to avoid deadlock
	mux->novacom_online = false;

	novacom_unregister_device(mux);

	// notify to all the channels that we're going offline
	broadcast_notification(mux, NOVACOM_NOTIFY_CHANNEL_INACTIVE);

	// wake any waiting tx thread
	platform_event_signal(&mux->wake_tx_event);

	// clear out the state of the channels
	struct novacom_channel *c;
	for (c = mux->channel_list; c; ) {
//		TRACEF("go_offline: handling channel %d\n", c->num);

		struct novacom_channel *saved_c = c;
		c = c->next; // this channel will get deleted, so push the pointer forward ahead of time
		TRACEL(LOG_MUXTRACE, "shutting down channel %d\n", saved_c->num);
		novacom_shutdown_channel(mux, saved_c, false);
	}

	platform_mutex_unlock(&mux->mux_mutex);
	novacom_release_device_handle(mux);
}

static void novacom_free_mux_instance(device_handle_t mux)
{
	platform_assert(mux->channel_list == NULL);
	platform_mutex_destroy(&mux->mux_mutex);
	platform_event_destroy(&mux->wake_tx_event);
	platform_free(mux);
}

static const char *control_op_to_string(uint32_t op)
{
	switch (op) {
		case PMUX_CONTROL_NONE:
			return "none";
		case PMUX_CONTROL_CHANNEL_CLOSED:
			return "closed";
		case PMUX_CONTROL_OPEN:
			return "open";
		case PMUX_CONTROL_OPEN_COMMAND:
			return "openc";
		case PMUX_CONTROL_CLOSE:
			return "close";
		default:
			return "unknown";
	}
}

void novacom_dump_packet(const void *buf, size_t len, int txrx)
{
#define TXRX ((txrx == PMUX_TX) ? "TX" : "RX")

	if (log_would_log(LOG_MUXTRACE)) {
		if (!buf || len == 0) {
	//		printf("%s NULL\n", TXRX);
			return;
		}

		struct pmux_header *header = (struct pmux_header *)buf;

		if ((header->flags & PMUX_FLAG_ACK)) {
			TRACEL(LOG_MUXTRACE, "%s ACK  c %-6d seq %-8d len %-8d tlen %-8d\n", 
					TXRX, header->channel, header->sequence, header->payload_len, header->total_len);
		} else {
			if (header->channel == PMUX_CHANNEL_CONTROL) {
				struct pmux_control_header *control = (struct pmux_control_header *)header->data;
				TRACEL(LOG_MUXTRACE, "%s DATA c %-6d seq %-8d len %-8d tlen %-8d CONTROL op %d %6s c %-6d len %-6d\n", TXRX, 
					header->channel, header->sequence, header->payload_len, header->total_len, 
					control->op, control_op_to_string(control->op), control->channel, control->len);
			} else {
				TRACEL(LOG_MUXTRACE, "%s DATA c %-6d seq %-8d len %-8d tlen %-8d crc %08x\n", TXRX, 
					header->channel, header->sequence, header->payload_len, header->total_len, header->crc);
			}
		}
	}
#undef TXRX
}

static struct novacom_channel *find_channel(struct mux_instance *mux, uint32_t num)
{
	struct novacom_channel *c;

	if (!mux) return NULL;

	for (c = mux->channel_list; c; c = c->next) {
		if (c->num == num)
			break;
	}
	
	return c;
}

static struct novacom_channel *create_channel(device_handle_t mux, uint32_t num, int command, bool bypass_online)
{
	platform_mutex_lock(&mux->mux_mutex);

	/* do online check */
	if (!bypass_online && !(mux->novacom_online)) {
		platform_mutex_unlock(&mux->mux_mutex);
		return NULL;
	}

	/* does channel exist */
	if (find_channel(mux, num) != NULL) {
		platform_mutex_unlock(&mux->mux_mutex);
		return NULL;
	}

	struct novacom_channel *c = (struct novacom_channel*)platform_calloc(sizeof(struct novacom_channel));
	platform_assert(c);

//	printf("create_channel: %d\n", num);

	c->tx_queue = bufq_create();
	c->close_callbacks = bufq_create();
	c->num = num;
	c->state = CHANNEL_STATE_OPEN;

	/* add it to the list */
	struct novacom_channel *tail = mux->channel_list;
	c->next = NULL;
	if (tail == NULL) {
		mux->channel_list = c;
	} else {
		while (tail->next != NULL)
			tail = tail->next;
		tail->next = c;
	}

	if (command) {
		if (c->num > PMUX_CHANNEL_MAX_FIXED) {
			novacom_setup_command(mux, c->num);
		} else if (c->num == PMUX_CHANNEL_CMDSERVICE) {
#if DEVICE
			/* only device should handle it, on host side such request is invalid */
			novacom_setup_service_command(mux, c->num);
#endif
		}
	}
	platform_mutex_unlock(&mux->mux_mutex);

	LTRACEF("num %d, command %d, %p\n", num, command, c);

	return c;
}

int novacom_open_channel(device_handle_t mux, uint32_t num, int command)
{
	int rc = -1;
	struct novacom_channel *c;

	LTRACEF("num %d, command %d\n", num, command);

	platform_mutex_lock(&mux->mux_mutex);
	c = create_channel(mux, num, false, false);
	platform_mutex_unlock(&mux->mux_mutex);

	if (!c) {
		return -1;
	}

	if (num > PMUX_CHANNEL_MAX_FIXED) {
		if (command)
			rc = send_control_message(mux, SEND_CTRLCMD_SYNC, PMUX_CONTROL_OPEN_COMMAND, num);
		else
			rc = send_control_message(mux, SEND_CTRLCMD_SYNC, PMUX_CONTROL_OPEN, num);
	} else if(num > PMUX_CHANNEL_CONTROL) {
		/* utility control channels */
		if (command)
			rc = send_control_message(mux, SEND_CTRLCMD_SYNC, PMUX_CONTROL_OPEN_COMMAND, num);
		else
			rc = send_control_message(mux, SEND_CTRLCMD_SYNC, PMUX_CONTROL_OPEN, num);
	}

	return rc;
}

int novacom_open_temp_channel(device_handle_t mux, uint32_t *channel, int command)
{
	platform_mutex_lock(&mux->mux_mutex);

retry:
	*channel = mux->next_temp_channel++;

	// check for wraparound
#if HOST
	if (mux->next_temp_channel == PMUX_CHANNEL_MAX_HOST)
		mux->next_temp_channel = PMUX_CHANNEL_HOST_BASE;
#elif DEVICE
	if (mux->next_temp_channel == PMUX_CHANNEL_MAX_DEVICE)
		mux->next_temp_channel = PMUX_CHANNEL_DEVICE_BASE;
#endif 

	// make sure we didn't pick an existing channel
	if (find_channel(mux, *channel) != NULL)
		goto retry;

	platform_mutex_unlock(&mux->mux_mutex);

	return novacom_open_channel(mux, *channel, command);
}

static void novacom_shutdown_channel(device_handle_t mux, struct novacom_channel *c, bool send_notification)
{
	platform_mutex_lock(&mux->mux_mutex);

	// remove it from the channel list
	if (mux->channel_list == c) {
		mux->channel_list = c->next;
	} else {
		struct novacom_channel *last;
		for (last = mux->channel_list; last; last = last->next) {
			if (last->next == c) {
				last->next = c->next;
				break;
			}
		}
	}

	// queue a close message
	if (send_notification)
		send_control_message(mux, SEND_CTRLCMD_ASYNC, PMUX_CONTROL_CLOSE, c->num);

	// clear the tx queue
	bufq_destroy(c->tx_queue);

	// tell any receivers that they're going away
	bufq_destroy(c->close_callbacks); // implicitly calls the queued callbacks
	if (c->rx_callback)
		c->rx_callback(mux, c->num, -1, NULL, 0, c->rx_callback_cookie);

	platform_free(c);
	platform_mutex_unlock(&mux->mux_mutex);
}

int novacom_close_channel(device_handle_t mux, uint32_t channel)
{
	// tear down the channel
	struct novacom_channel *c;

	if (channel <= PMUX_CHANNEL_MAX_FIXED)
		return -1; // cant close the permanent channels

	platform_mutex_lock(&mux->mux_mutex);
	// find it
	c = find_channel(mux, channel);
	if (!c) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	// is it already closing?
	if (c->state == CHANNEL_STATE_CLOSING) 
		goto done;

	c->state = CHANNEL_STATE_CLOSING;

	if (c->notify) (c->notify)(mux, channel, NOVACOM_NOTIFY_CHANNEL_INACTIVE, c->notify_cookie);

	// we now have a locked channel in the closing state, see if we can nuke it right now
	// otherwise it'll be killed when the last piece of tx data goes out
	if (bufq_len(c->tx_queue) == 0) {
		// nothing is queued up, delete it now
		novacom_shutdown_channel(mux, c, true);
	} 

done:
	platform_mutex_unlock(&mux->mux_mutex);

	return 0;
}

static int control_channel_rx_callback(device_handle_t mux, uint32_t channel, int err, const void *buf, size_t len, void *cookie)
{
	struct pmux_control_header *control = (struct pmux_control_header *)buf;
	struct novacom_channel *c = NULL;

	if (err < 0)
		return 0;

	// see if it's crap
	if (len < sizeof(struct pmux_control_header))
		return 0;

	switch (control->op) {
		case PMUX_CONTROL_NONE:
			break;
		case PMUX_CONTROL_CHANNEL_CLOSED:
			// we sent data to a channel that's closed on the other end
			TRACEL(LOG_MUXTRACE, "CONTROL_CHANNEL_CLOSED: %d\n", control->channel);
			// shutdown local channel
			platform_mutex_lock(&mux->mux_mutex);
			c = find_channel(mux, control->channel);
			if (c)
				novacom_shutdown_channel(mux, c, false);
			platform_mutex_unlock(&mux->mux_mutex);
			break;
		case PMUX_CONTROL_OPEN:
			// a request from the other side to open one of our channels
			TRACEL(LOG_MUXTRACE, "CONTROL_OPEN: %d\n", control->channel);
			platform_mutex_lock(&mux->mux_mutex);
			create_channel(mux, control->channel, 0, false); // open an ephemeral port on our side
			platform_mutex_unlock(&mux->mux_mutex);
			break;
		case PMUX_CONTROL_OPEN_COMMAND:
			// a request from the other side to open one of our channels
			TRACEL(LOG_MUXTRACE, "CONTROL_OPEN_COMMAND: %d\n", control->channel);
			platform_mutex_lock(&mux->mux_mutex);
			create_channel(mux, control->channel, 1, false); // open an ephemeral port on our side
			platform_mutex_unlock(&mux->mux_mutex);
			break;
		case PMUX_CONTROL_CLOSE: {
			// a notification from the other side that a channel is getting closed
			TRACEL(LOG_MUXTRACE, "CONTROL_CLOSE: %d\n", control->channel);
			platform_mutex_lock(&mux->mux_mutex);
			c = find_channel(mux, control->channel);
			if (c)
				novacom_shutdown_channel(mux, c, false);
			platform_mutex_unlock(&mux->mux_mutex);
			break;
		}
		default:
			// bad message
			break;
	}

	return 0;
}


/**
 * @brief  sends control message
 * @param  mux     device handle
 *         sync    execution mode: 0 - async, otherwise blocked until completed
 *         op      command/operation
 *         channel channel number
 * @ret    result
 **/
static int send_control_message(device_handle_t mux, int sync, uint32_t op, uint32_t channel)
{
	int rc;
	struct pmux_control_header header;

	header.op = op;
	header.channel = channel;
	header.len = sizeof(struct pmux_control_header);

	if(sync == SEND_CTRLCMD_SYNC) {
		rc = novacom_write_channel_sync(mux, PMUX_CHANNEL_CONTROL, &header, header.len);
	} else {
		rc = novacom_write_channel_async(mux, PMUX_CHANNEL_CONTROL, &header, header.len, ASYNC_FLAG_COPY, NULL, NULL);
	}

	return rc;
}

int novacom_mux_init(void)
{
	return 0;
}


static int sync_read_callback(device_handle_t mux, uint32_t chan, int err, const void *buf, size_t len, void *cookie)
{
	struct sync_read_data *data = (struct sync_read_data *)cookie;

//	TRACEF("chan %d, err %d, len %d, data buf %p, pos %d, buflen %d\n", chan, err, len, data->buf, data->pos, data->buflen);

	/* error, signal the caller and deliver the error */
	if (err < 0) {
		data->error = err;
		goto complete;
	}

	/* if we read this it would extend past the data, so complete the read 
	 * and nack the data. The sender should retransmit 
	 */
	if (len + data->pos > data->buflen) {
		// XXX can't accept this, nack the data
		TRACEF("bad state, buffer overruns the data\n");
		goto complete;
	}

	memcpy(data->buf + data->pos, buf, len);
	data->pos += len;

	// XXX hack to work around the above
	if (len + data->pos > data->buflen / 2) {
		goto complete;
	}

	/* exactly completes the buffer, return */
	if (data->pos == data->buflen) {
		goto complete;
	}

	/* satisfies min number of bytes requirement */
	if(data->min && ( data->pos >= data->min) ) {
		goto complete;
	}
	return 0;

complete:
	novacom_set_read_callback(mux, chan, NULL, NULL);
	platform_event_signal(data->event);

	return 0;
}

ssize_t novacom_read_channel_sync(device_handle_t mux, uint32_t channel, void *buf, size_t len, size_t min)
{
	int rc;
	platform_event_t event;
	
	platform_mutex_lock(&mux->mux_mutex);
	struct novacom_channel *c = find_channel(mux, channel);
	if (!c) {
		platform_mutex_unlock(&mux->mux_mutex);
		return -1;
	}

	platform_event_create(&event);
	platform_event_unsignal(&event);

	struct sync_read_data data;
	data.event = &event;
	data.error = 0;
	data.buf = (char*)buf;
	data.buflen = len;
	data.pos = 0;
	data.min = min;

	novacom_set_read_callback(mux, channel, &sync_read_callback, (void *)&data);

	platform_mutex_unlock(&mux->mux_mutex);

	platform_event_wait(&event);
	#if 0  //we cannot timeout this time, because the "data" is in stack
	if (platform_event_wait_timeout(&event, TRANSPORT_RECOVERY_TIMEOUT*1000*3 + 500)) {
		data.error = -1;
		TRACEF("%s: detected timeout, device has something wrong!!!\n", __FUNCTION__);
	}
	#endif 
	rc = data.error;
	if (data.pos > 0)
		rc = data.pos;

	platform_event_destroy(&event);

	return rc;
}


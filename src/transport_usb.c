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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#include <debug.h>

#include <platform.h>
#include <transport_usb.h>
#include <novacom.h>
#include "novacom/novacom_p.h"
#if DEVICE
#include "device/auth.h"
#endif

#include "transport.h"
#include "transport_usb_struct.h"
#include "novacom/mux.h"

#if HOST
#define LOCAL_TRACE 0
#ifndef TRACE_PACKETS
///#define TRACE_PACKETS 1
#endif
#ifndef LL_TRACE_PACKETS
///#define LL_TRACE_PACKETS 1
#endif
#elif DEVICE
#define LOCAL_TRACE 0
#define TRACE_PACKETS 0
#define LL_TRACE_PACKETS 0
#endif

// usb link-layer handshaking type stuff
// aka "reinventing TCP for fun and profit"


#define SYN_PACKET_INTERVAL 		500 	// interval in msecs to send a syn packet
#define HEARTBEAT_PACKET_INTERVAL	1000	// interval in msecs to send heartbeat packet
#define TIMEOUT_PACKET			5000   // old value:7200000	// packet timeout in msec

struct novacom_usbll_state {
	uint32_t uid;								///< unique device id(Linux: busid + deviceid)
	int state;
	uint32_t sessionid;
	uint32_t remoteid;
	int nextcommand;
	uint32_t reset_sessionid;
	uint32_t reset_remoteid;
	uint32_t max_mtu;
	uint32_t mtu;
	int heartbeat_interval;
	int timeout;
	device_handle_t device_handle;
	platform_time_t last_tx_time;
	platform_time_t last_syn_tx_time;
	platform_mutex_t lock;
	char remote_nduid[NOVACOM_NDUID_STRLEN];
#if DEVICE
	char *syn_datamsg;								/* combined data msg */
	char device_id[64];								/* device id */
	char session_id[10 + NOVACOM_AUTHSESSION_LEN];	/* session len + token len */
#endif
	const char *devtype;
	int synpacket_size;							/* keep syn packet size:: compatibility with old versions */
	usbll_recovery_token_t	*recovery_token;	/* recovery token:: generated after sync established */
};

enum {
	state_listen,
	state_synsent,
	state_synrecv,
	state_established
};

/* proto */
static int novacom_usbll_create_recovery_token(const void *data, int len, void **rec_token);


/*
 * novacom_usbll_check_packet_header
 * @param[buf]				packet buffer
 * @param[len]				packet length
 * @ret PACKET_TYPE_BADPACKET for invalid packet, else PACKET_TYPE_NULL
 */
int novacom_usbll_check_packet_header(const char *buf, unsigned int len)
{
	int type = PACKET_TYPE_NULL;
	struct usbll_header * header = (struct usbll_header *)buf;
#if 0
	{
		static int n= 0;

		n++;
		if (n>5) {
			log_printf(LOG_ERROR, "Got packet with old usb transport header, please upgrade the other end\n");
			n =0;
			return PACKET_TYPE_BADPACKET;
		}
		log_printf(LOG_ERROR, "n=%d\n", n);

	}
#endif
	if(len < sizeof(struct usbll_header)) {
		log_printf(LOG_ERROR, "Invalid USB packet length. Make sure your novacomd versions match.\n");
		type = PACKET_TYPE_BADPACKET;
	}
	if (header->magic != USBLL_MAGIC) {
		log_printf(LOG_ERROR, "Got bad USB packet. Make sure your novacomd versions match.\n");
		type = PACKET_TYPE_BADPACKET;
	}
	if (header->version < USBLL_VERSION) {
		log_printf(LOG_ERROR, "Got packet with old usb transport header, please upgrade the other end\n");
		type = PACKET_TYPE_BADPACKET;
	} else if (header->version > USBLL_VERSION) {
		log_printf(LOG_ERROR, "Got packet with newer usb transport header than we support, please upgrade to newer version\n");
		type = PACKET_TYPE_BADPACKET;
	}
        //more check for mux layer.
#if 0 //ychen
	if (header->command == usbll_data) {
		struct pmux_header *pmux = (struct pmux_header *)buf + sizeof(struct usbll_header);
		len -= sizeof(struct usbll_header);
		if (pmux->total_len != pmux->payload_len + sizeof(struct pmux_header) || pmux->total_len != len) {
			log_printf(LOG_ERROR, "Invalid USB packet length (PMUX). Make sure your novacomd versions match.\n");
			type = PACKET_TYPE_BADPACKET;
		}
	}
#endif 
#if 0
	// not important
	if (header->magic != PMUX_MAGIC)
		return PACKET_TYPE_ERR;
	if (header->version != PMUX_VERSION)
		return PACKET_TYPE_ERR;
#endif		
	return type;
}


#if LL_TRACE_PACKETS
static void novacom_usbll_dump_packet(novacom_usbll_handle_t usbll_handle, const char *buf, size_t len, bool tx)
{
	if (log_would_log(LOG_LLTRACE)) {
		const struct usbll_header *header = (const struct usbll_header *)buf;
		char traceheader[128];

		snprintf(traceheader, sizeof(traceheader), "%s usbll(%08x) len %5d txid 0x%08x rxid 0x%08x command 0x%x: ",
				tx ? "TX" : "RX", usbll_handle->uid, (int)len, header->txid, header->rxid, header->command);

		switch (header->command) {
			case usbll_null:
				log_printf(LOG_LLTRACE, "%s null\n", traceheader);
				break;
			case usbll_rst:
				log_printf(LOG_LLTRACE, "%s rst\n", traceheader);
				break;
			case usbll_syn: {
				const struct usbll_syn_header *syn_header = (const struct usbll_syn_header *)(header + 1);
				char nduid[NOVACOM_NDUID_STRLEN];
				memcpy(nduid, syn_header->nduid, NOVACOM_NDUID_CHRLEN);
				nduid[NOVACOM_NDUID_CHRLEN] = 0;

				if (len >= sizeof(struct usbll_header) + sizeof(struct usbll_syn_header))
					log_printf(LOG_LLTRACE, "%s syn, nduid '%s' mtu %u, heartbeat %u, timeout %u\n", 
							traceheader, nduid, syn_header->mtu, syn_header->heartbeat_interval, syn_header->timeout);
				else
					log_printf(LOG_LLTRACE, "%s syn, nduid '%s' mtu %u\n", traceheader, nduid, syn_header->mtu);

				break;
			}
			case usbll_data:
				log_printf(LOG_LLTRACE, "%s data\n", traceheader);
				break;
			default:
				log_printf(LOG_LLTRACE, "%s unknown\n", traceheader);
				break;
		}
	}
}
#endif

novacom_usbll_handle_t novacom_usbll_create(const char *devtype, uint32_t max_mtu, int heartbeat_interval, int timeout)
{
	novacom_usbll_handle_t usbll_handle = (novacom_usbll_handle_t)platform_calloc(sizeof(struct novacom_usbll_state));
	platform_assert(usbll_handle != NULL);
	if(usbll_handle) {
		platform_mutex_init(&usbll_handle->lock);
		usbll_handle->sessionid = novacom_get_new_sessionid();
		usbll_handle->nextcommand = usbll_data;
		usbll_handle->devtype = devtype;
		usbll_handle->max_mtu = max_mtu;
		usbll_handle->mtu = max_mtu;
		if(heartbeat_interval > 0) {
			usbll_handle->heartbeat_interval = heartbeat_interval;
		} else {
			usbll_handle->heartbeat_interval = HEARTBEAT_PACKET_INTERVAL; /* default */
		}
		if(timeout > 0) {
			usbll_handle->timeout = timeout;
		} else {
			usbll_handle->timeout = TIMEOUT_PACKET; /* default */
		}
		usbll_handle->synpacket_size = sizeof(struct usbll_syn_header); /* default syn packet size */

		platform_get_time(&usbll_handle->last_tx_time);
		platform_get_time(&usbll_handle->last_syn_tx_time);

#if DEVICE
		int n = 0;
#ifdef MACHINE
		/* device id */
		snprintf(usbll_handle->device_id, sizeof(usbll_handle->device_id), "%s%s-linux", NOVACOMD_DATATOKEN_ID, MACHINE);
		n = strlen(usbll_handle->device_id) + 1;
#else
		usbll_handle->device_id[0] = 0; /* clear string */
#endif
		/* session id */
		if( !auth_is_done() ) {
			int rc;
			char session[NOVACOM_AUTHSESSION_LEN + 1];
			/* query session */
			memset(session, 0, sizeof(session));
			rc = auth_get_session(session, sizeof(session) - 1);
			if(-1 != rc) {
				snprintf(usbll_handle->session_id, sizeof(usbll_handle->session_id), "%s%s", NOVACOMD_DATATOKEN_SESSION, session);
			}
			n += strlen(usbll_handle->session_id) + 1;
		} else {
			usbll_handle->session_id[0] = 0; /* clear string */
		}

		usbll_handle->syn_datamsg = platform_calloc( n );
		if(usbll_handle->syn_datamsg) {
			snprintf(usbll_handle->syn_datamsg, n, "%s %s", usbll_handle->device_id, usbll_handle->session_id);
		}
#endif
	}

	return usbll_handle;
}

void novacom_usbll_destroy(novacom_usbll_handle_t usbll_handle)
{
	platform_assert(usbll_handle != NULL);
	if (usbll_handle->device_handle != NULL) {
		novacom_go_offline(usbll_handle->device_handle);
	}
	usbll_handle->device_handle = NULL;
	platform_mutex_destroy(&usbll_handle->lock);
#if DEVICE
	platform_free(usbll_handle->syn_datamsg);
#endif
	platform_free(usbll_handle->recovery_token);
	platform_free(usbll_handle);
}

int novacom_usbll_prepare_tx_packet(novacom_usbll_handle_t usbll_handle, struct novacom_tx_packet *packet, int timeout)
{
	int ret = TX_NO_PACKET;
	size_t max_packet_len = packet->len;

	// tx packet must contain at least the header and nduid;
	platform_assert(max_packet_len >= (sizeof(struct usbll_header) + NOVACOM_NDUID_STRLEN));

	struct usbll_header * header = (struct usbll_header *)packet->buf;
	header->magic = USBLL_MAGIC;
	header->version = USBLL_VERSION;

	platform_mutex_lock(&usbll_handle->lock);

	//LTRACEF("state %d, nextcommand %d\n", usbll_handle->state, usbll_handle->nextcommand);

	// send a packet at heartbeat interval.
	if (usbll_handle->nextcommand != usbll_rst) {
		platform_time_t now;

		platform_get_time(&now);
		if (platform_delta_time_msecs(&usbll_handle->last_tx_time, &now) > usbll_handle->heartbeat_interval) {
			usbll_handle->nextcommand = usbll_null;
		}
	}

retry:
	if (usbll_handle->nextcommand == usbll_null) {
		header->txid = usbll_handle->sessionid;
		header->rxid = usbll_handle->remoteid;
		usbll_handle->nextcommand = usbll_data;

		/* only send the null packet if we're established */
		if (usbll_handle->state == state_established) {
			header->command = usbll_null;
			memcpy(&packet->buf[sizeof(struct usbll_header)], novacom_nduid(), NOVACOM_NDUID_STRLEN);
			packet->len = sizeof(struct usbll_header) + NOVACOM_NDUID_STRLEN;
			platform_get_time(&usbll_handle->last_tx_time);
			ret = 0;
		} else {
			goto retry;
		}
	} else if (usbll_handle->nextcommand == usbll_rst) {
		header->txid = usbll_handle->reset_sessionid;
		header->rxid = usbll_handle->reset_remoteid;
		header->command = usbll_rst;
		packet->len = sizeof(struct usbll_header) + NOVACOM_NDUID_STRLEN;
		usbll_handle->nextcommand = usbll_data;
		platform_get_time(&usbll_handle->last_tx_time);
		LOG_PRINTF("usbll(%08x) sending rst, txid=0x%08x, rxid=0x%08x\n", usbll_handle->uid, header->txid, header->rxid);
		ret = 0;
	} else {
		header->txid = usbll_handle->sessionid;
		header->rxid = usbll_handle->remoteid;

		switch (usbll_handle->state) {
			case state_listen:
			case state_synsent:
			case state_synrecv: {
				// send a syn
				// maybe throttle these?
				bool send_syn = true;
				
#if HOST
				/* host should not initiate a syn session */
				if (usbll_handle->state != state_synrecv)
					send_syn = false;
#else
				/* device should initiate a syn session, but dont spam the host */
				if (usbll_handle->state == state_listen || usbll_handle->state == state_synsent) {
					platform_time_t now;

					platform_get_time(&now);
					if (platform_delta_time_msecs(&usbll_handle->last_syn_tx_time, &now) < SYN_PACKET_INTERVAL) {
						send_syn = false;
						usleep(10000); /* 10 millisec, dont hog cpu */
					}
				}
#endif

				if (send_syn) {
					LTRACEF("SYNC packet\n");
					header->command = usbll_syn;
					struct usbll_syn_header *syn_header = (struct usbll_syn_header *)(header + 1);
					memcpy(syn_header->nduid, novacom_nduid(), NOVACOM_NDUID_CHRLEN);
					syn_header->mtu = usbll_handle->mtu;
					syn_header->heartbeat_interval = usbll_handle->heartbeat_interval;
					syn_header->timeout = usbll_handle->timeout;
					packet->len = sizeof(struct usbll_header) + sizeof(struct usbll_syn_header);
#if HOST
					/* did we receive old syn packet??? */
					if((usbll_handle->state == state_synrecv)
						&&  (usbll_handle->synpacket_size < ((int)(sizeof(struct usbll_syn_header))) ) ) {
						TRACEL(LOG_ERROR, "Got old syn USB packet. Adjusting packet length\n");
						packet->len = sizeof(struct usbll_header) + usbll_handle->synpacket_size;
					}
#endif
#if DEVICE
					/* data msg */
					int prod_len = strlen(usbll_handle->syn_datamsg) + 1;

					if( (prod_len > 1) && (max_packet_len >= (packet->len + prod_len)) ) {
						char *ptr = NULL;

						packet->len += prod_len;
						syn_header->data_offset = sizeof(struct usbll_syn_header);
						syn_header->data_length = prod_len;
						ptr = (char*)syn_header + syn_header->data_offset;

						memcpy(ptr, usbll_handle->syn_datamsg, prod_len);
					}

#endif
					if (usbll_handle->state == state_listen) {
						usbll_handle->state = state_synsent;
					}
					if (usbll_handle->state == state_synrecv) {
						usbll_handle->state = state_established;
					}
					platform_get_time(&usbll_handle->last_tx_time);
					platform_get_time(&usbll_handle->last_syn_tx_time);
					ret = 0;
				}
			}
			break;
			case state_established: {
				header->command = usbll_data;
				struct novacom_tx_packet subpacket;
				subpacket.buf = &packet->buf[sizeof(struct usbll_header)];
				subpacket.len = max_packet_len - sizeof(struct usbll_header);
				
				int rc;

				/* grab and retain a handle to the device while we block
				 * so that we can guarantee that it wont go out of scope if another 
				 * thread decides to destroy it.
				 */
				device_handle_t dev = usbll_handle->device_handle;
				novacom_retain_device_handle(dev);
				platform_mutex_unlock(&usbll_handle->lock);

				if (timeout > 0) 
					rc = novacom_get_tx_packet(dev, &subpacket, timeout);
				else
					rc = novacom_prepare_tx_packet(dev, &subpacket);

				/* see if the device was changed out from underneath us and trash the packet if so */
				platform_mutex_lock(&usbll_handle->lock);
				if (dev != (volatile void*)usbll_handle->device_handle) { //in case compiler doesn't think so
					TRACEF("novacom device was deleted while waiting for tx\n");
					rc = TX_NO_PACKET;
				}
				novacom_release_device_handle(dev);

				packet->len = subpacket.len + sizeof(struct usbll_header);
				if (rc != TX_NO_PACKET) {
					//printf("omg sending\n");
					platform_get_time(&usbll_handle->last_tx_time);
#if TRACE_PACKETS
					novacom_dump_packet(subpacket.buf, subpacket.len, PMUX_TX);
#endif
				}
				ret = rc;
			}
			break;
			default:
				platform_assert(false);
			break;
		}
	}

	platform_mutex_unlock(&usbll_handle->lock);

	if (ret >= 0) {
#if LL_TRACE_PACKETS
		novacom_usbll_dump_packet(usbll_handle, packet->buf, packet->len, true);
#endif

		/* tweak the len to make sure it's on an odd boundary so it looks like a complete usb transfer */
		if (packet->len != max_packet_len && ((packet->len % 64) == 0))
			packet->len++;
	}

	return ret;
}

void novacom_usbll_drop_offline(novacom_usbll_handle_t usbll_handle)
{
	platform_mutex_lock(&usbll_handle->lock);
	if (usbll_handle->device_handle != NULL) {
		device_handle_t h = usbll_handle->device_handle;
		usbll_handle->device_handle = NULL;
		novacom_go_offline(h);
		usbll_handle->sessionid = novacom_get_new_sessionid();
	}
	usbll_handle->state = state_listen;
	usbll_handle->remoteid = 0;
	usbll_handle->mtu = usbll_handle->max_mtu;
	platform_mutex_unlock(&usbll_handle->lock);
}

int novacom_usbll_process_packet(novacom_usbll_handle_t usbll_handle, const char *buf, unsigned int len)
{
	int type;

	platform_assert(len >= sizeof(struct usbll_header));
	struct usbll_header * header = (struct usbll_header *)buf;

#if 0    //has been checked in novacom_usb_read()
	/* check packet header */
	type = novacom_usbll_check_packet_header(buf, len);
	if(type == PACKET_TYPE_BADPACKET) {
		return type;
	}
#endif 

#if LL_TRACE_PACKETS
	/* dump packet */
	novacom_usbll_dump_packet(usbll_handle, buf, len, false);
#endif

	platform_mutex_lock(&usbll_handle->lock);

	if (header->command == usbll_rst) {
		log_printf(LOG_ERROR, "Got RESET packet, process it?, rxid=0x%08x, sessionid=0x%08x\n",header->rxid, usbll_handle->sessionid);
		if (header->rxid == usbll_handle->sessionid) {
			// got a rst, and it's destined for us
			log_printf(LOG_ERROR, "Got RESET packet, restart...\n");
			novacom_usbll_drop_offline(usbll_handle);
			type = PACKET_TYPE_PROTOCOL;
			goto out;
		}
	}

	/* ignore null packets */
	type = PACKET_TYPE_NULL;
	if (header->command == usbll_null && header->rxid == usbll_handle->sessionid) {
		goto out;
	}

	LTRACEF("rx packet state %d command %d, rxid 0x%x, txid 0x%x\n",
			usbll_handle->state, header->command, header->rxid, header->txid);

	switch (usbll_handle->state) {
		case state_listen:
		case state_synsent:
		case state_synrecv:
			switch (header->command) {
				case usbll_null:
				case usbll_data:
					// out of sequence, send an rst
					usbll_handle->nextcommand = usbll_rst;
					usbll_handle->reset_sessionid = header->rxid;
					usbll_handle->reset_remoteid = header->txid;
					type = PACKET_TYPE_ERR;
				break;
				case usbll_syn:
					// hoorj, a syn
					LTRACEF("SYN:: rx packet state %d command %d, rxid 0x%x\n", usbll_handle->state, header->command, header->rxid);
					if (usbll_handle->device_handle == NULL) {
						size_t syn_len = len - sizeof(struct usbll_header);
						usbll_handle->synpacket_size = syn_len; /* keep syn packet size*/
						const struct usbll_syn_header *syn_header = (const struct usbll_syn_header *)(header + 1);
						/* at least, recover nduid */
						if(syn_len >= offsetof(struct usbll_syn_header, mtu)) {
							char *syn_data = NULL;
							memcpy(usbll_handle->remote_nduid, syn_header->nduid, NOVACOM_NDUID_CHRLEN);
							usbll_handle->remote_nduid[NOVACOM_NDUID_CHRLEN] = '\0';
							/* recover mtu */
							if( (syn_len > offsetof(struct usbll_syn_header, heartbeat_interval))
									&& (syn_header->mtu < usbll_handle->mtu)) {
								usbll_handle->mtu = syn_header->mtu;
							}
							/* recover heartbeat_interval, timeout_interval */
							if(syn_len >= offsetof(struct usbll_syn_header, data_offset) ) {
								if( (int)syn_header->heartbeat_interval < usbll_handle->heartbeat_interval) {
									usbll_handle->heartbeat_interval = (int)syn_header->heartbeat_interval;
								}
								if((int)syn_header->timeout < usbll_handle->timeout) {
									usbll_handle->timeout = (int)syn_header->timeout;
								}
#if HOST
								/*nova68 workaround*/
								if(usbll_handle->timeout == 7200000)
									--usbll_handle->timeout;
								if(usbll_handle->heartbeat_interval == 1000)
									--usbll_handle->heartbeat_interval;
#endif
							} else {	/*old defaults*/
								usbll_handle->heartbeat_interval = 250;
								usbll_handle->timeout = 1000;
							}
							/* recover data */
							if( (syn_len >= (sizeof(struct usbll_syn_header) + syn_header->data_length))
									&& (syn_len >= (syn_header->data_length + syn_header->data_offset)) ) {
								syn_data = (char *)syn_header + syn_header->data_offset;
								syn_data[syn_header->data_length-1] = 0;	/*explicitly add null string termination, even if it is expected */
							} else if(syn_len > offsetof(struct usbll_syn_header, data_offset)){
								/*filter out old header definitions */
								log_printf(LOG_LLTRACE, "invalid data definition within syn packet\n");
							}
#if HOST
#if defined(__linux__)
							/* notify transport layer about new device, so recovery tokens are disposed */
							(void)novacom_usb_transport_deviceonline(usbll_handle->remote_nduid);
#endif
#endif
							/* go online */
							usbll_handle->device_handle = novacom_go_online(usbll_handle->remote_nduid, "usb", usbll_handle->devtype, syn_data);
							platform_assert(usbll_handle->device_handle);
							usbll_handle->remoteid = header->txid;
							log_printf(LOG_LLTRACE, "got syn, mtu %u, heartbeat %d, timeout %d, len(%d/%d/%d), data(%p)\n", 
								usbll_handle->mtu, usbll_handle->heartbeat_interval, usbll_handle->timeout,
								syn_len, sizeof(struct usbll_syn_header),
								syn_data?syn_header->data_length:0, syn_data);

							/* recovery token, ignore results since error indicates that we cannot resume, but we still can operate */
							if(usbll_handle->recovery_token) {
								platform_free(usbll_handle->recovery_token);
								usbll_handle->recovery_token = NULL;
							}
							(void)novacom_usbll_create_recovery_token(buf, len, (void **)&usbll_handle->recovery_token);
							if(usbll_handle->recovery_token) { /* patch recovery token!!!! */
								 /* protocol related: rxid is not known yet to device, restore from sessionid... */
								usbll_handle->recovery_token->rxid = usbll_handle->sessionid;
							}

						} else {
							/* TODO: handle this case */
						}
					} else if (usbll_handle->state != state_synrecv) {
						// printf("er, what?\n");
					}

					if (usbll_handle->state == state_listen) {
						usbll_handle->state = state_synrecv;
					} else if (usbll_handle->state == state_synsent) {
						usbll_handle->state = state_established;
					}
					type = PACKET_TYPE_PROTOCOL;
				break;
				case usbll_rst:
					// do nothing
					type = PACKET_TYPE_ERR;
				break;
				default:
					type = PACKET_TYPE_BADPACKET;
				break;
			}
		break;
		case state_established:
			type = PACKET_TYPE_ERR; // error until proven otherwise
			if ((header->rxid != usbll_handle->sessionid) && (header->rxid != 0)) {
				if (header->command != usbll_rst) {
					// Got some other spurious non-rst packet, send back an rst
					usbll_handle->nextcommand = usbll_rst;
					usbll_handle->reset_sessionid = header->rxid;
					usbll_handle->reset_remoteid = header->txid;
					goto out;
				}
			}
			if (header->command == usbll_data) {
#if TRACE_PACKETS
				novacom_dump_packet(buf+sizeof(struct usbll_header), len-sizeof(struct usbll_header), PMUX_RX);
#endif
				type = novacom_process_packet(usbll_handle->device_handle, buf+sizeof(struct usbll_header), len-sizeof(struct usbll_header));
			}
			if (header->command == usbll_syn) {
				if (header->txid != usbll_handle->remoteid) {
//					log_printf(LOG_SPEW, "*** got syn from wrong session while established\n");
//					TRACEF("*** got syn from wrong session while established (remoteid 0x%08x/txid 0x%08x\n", usbll_handle->remoteid, header->txid);
					type = PACKET_TYPE_BADPACKET;
				}
			}
		break;
		default:
			platform_assert(false);
		break;
	}

out:
	platform_mutex_unlock(&usbll_handle->lock);

	return type;
}

uint32_t novacom_usbll_get_mtu(novacom_usbll_handle_t handle)
{
	if(handle)
		return handle->mtu;
	else
		return TRANSPORT_MAX_MTU;
}

int novacom_usbll_get_timeout(novacom_usbll_handle_t handle)
{
	if(handle)
		return handle->timeout;
	else 
		return TIMEOUT_PACKET;
}
/*
 * novacom_usbll_get_nduid
 * get device nduid
 * @param[handle]	usbll handle
 * @ret[]	
 */
char *novacom_usbll_get_nduid(novacom_usbll_handle_t handle)
{
	if(handle)
		return handle->remote_nduid;
	else 
		return NULL;
}

/*
 * novacom_usbll_get_recovery_token
 * get recovery token(shall be generated when connection is established)
 * @param[handle]		usbll handle
 * @param[t_pToken]		pointer to transport recovery token structure(to save internal recovery token and handle)
 * 
 * @ret	0 - success, -1 error
  */
int novacom_usbll_get_recovery_token(novacom_usbll_handle_t handle, transport_recovery_token_t *t_token)
{
	int rc = -1;

	/* internal token is valid? */
	if( (t_token) && (handle->recovery_token) ) {
		t_token->token = handle->recovery_token;
		t_token->len = sizeof(usbll_recovery_token_t);
		t_token->user_data = handle;
		LTRACEF(" usbll_get_recovery_token data(%p)\n", t_token->token);
		rc = 0;
	}

	return rc;
}

/*
 * novacom_usbll_create_recovery_token
 * static function
 * Allocates memory for usbll_recovery_token; generates token based on provided usbll data packet
 * @param[data]			pointer to packet data
 * @param[len]			packet length
 * @param[rec_token]	pointer for return data
 * 
 * @ret 0 success(rec_token != null), -1 error
 */
static int novacom_usbll_create_recovery_token(const void *data, int len, void **rec_token)
{
	int rc = -1;

	if(rec_token) {
		usbll_recovery_token_t *t_recovery = (usbll_recovery_token_t *)platform_calloc(sizeof(usbll_recovery_token_t));
		struct usbll_header * header = (struct usbll_header *)data;

		if(t_recovery) {
			t_recovery->magic = USBLL_MAGIC;
			t_recovery->version = USBLL_VERSION;
			t_recovery->rxid = header->rxid;
			t_recovery->txid = header->txid;
			/* results */
			*rec_token = t_recovery;
			LTRACEF(" recovery_token data(%p)\n", t_recovery);

			rc = 0;
		}
	}

	return rc;
}

/*
 * novacom_usbll_generate_recovery_token
 * shall generate recovery token based on provided usbll data packet
 * @param[data]			pointer to packet data
 * @param[len]			packet length
 * @param[t_pToken]		pointer to transport recovery token structure
 * 
 * @ret 0 success, -1 error
 */
int novacom_usbll_generate_recovery_token(const void *data, int len, transport_recovery_token_t *t_token)
{
	int rc = -1;

	if(t_token) {
		rc = novacom_usbll_create_recovery_token(data, len, &t_token->token);
		t_token->len = sizeof(usbll_recovery_token_t);
		t_token->user_data = NULL;
		LTRACEF(" recovery_token data(%p)\n", t_token->token);

		rc = 0;
	}

	return rc;
}

/*
 * novacom_usbll_setuid
 * set uid:unique device id. 
 * Uid is os specific: Linux uid = busid + deviceid, MacOS uid = UID
 * It is required only for traces analysis: we can track messages per device.  
 * @param[handle]	usbll handle
 * @param[uid]		unique device id
 * @ret	none
 */
void novacom_usbll_setuid(novacom_usbll_handle_t handle, uint32_t uid)
{
	if(handle) {
		handle->uid = uid;
	}
}

/*
 * novacom_usbll_getuid
 * get uid:unique device id. 
 * Uid is os specific: Linux uid = busid + deviceid, MacOS uid = UID
 * It is required only for traces analysis: we can track messages per device.  
 * @param[handle]	usbll handle
 * @ret	uid
 */
uint32_t novacom_usbll_getuid(novacom_usbll_handle_t handle)
{
	if(handle) {
		return handle->uid;
	} else {
		return 0;
	}
}

int novacom_usbll_get_state(novacom_usbll_handle_t handle) 
{
	return handle->state;
}

void novacom_usbll_changeback_state(novacom_usbll_handle_t handle, int state) 
{
	LOG_PRINTF("current novacom state: %d, prior state=%d\n",handle->state, state);
	if (handle->state == state_established && state != state_established) {
			handle->state = state_synrecv;
			LOG_PRINTF("changed novacom state: %d\n",handle->state);
	}
}

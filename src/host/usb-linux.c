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

#include <stdio.h>
#include <usb.h>
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <string.h>

#include <transport_usb.h>
#include <platform.h>
#include <novacom.h>
#include <debug.h>
#include <log.h>
#include <sys/queue.h>

#include <linux/usbdevice_fs.h>
#include "../novacom/mux.h"
#include "device_list.h"

/* debug */
#define LOCAL_TRACE 0
#define USB_SCAN_TRACE 0
#define USB_RECOVERY 0

/* controls */
#define TRACE_ZERO_LEN_PACKETS 0
#define FAULTY_TX 0
#define MAX_MTU 16384

#define USBDEVFS_IOCTL_TIMEOUT  2000

struct myusb_dev_handle {
	int fd;

	// other stuff here
};

typedef struct {
	union {
		usb_dev_handle *handle;

		/* XXX cheezy hack to let us get to the file descriptor hidden in the libusb handle */
		struct myusb_dev_handle *myhandle;
	};

	novacom_usbll_handle_t usbll_handle;

	bool shutdown;
	platform_event_t tx_startup_event;		/* event to block tx thread until any packet received on rx side*/
	int tx_startup_wait;					/* flag to indicate that we are blocked on tx */
	platform_event_t tx_shutdown_event;		/* event to indicate tx thread shutdown */

	int rxep;
	int txep;
	int rx_timeout;
	int tx_timeout;
	const char *devtype;
	int busnum;
	int devnum;
	int iface;
} novacom_usb_handle_t;

typedef struct recovery_entry_s {
	transport_recovery_token_t	*t_token;		/* transport recovery token */
	int timeout;								/* timout value */

	TAILQ_ENTRY(recovery_entry_s) entries;		/* holds pointers to prev, next entries */
} recovery_entry_t;

/* vars */
static platform_thread_t findandattach_thread;
volatile int novacom_shutdown = 0;
		/* list of recovery tokens */
TAILQ_HEAD(recovery_queue_s, recovery_entry_s)  t_recovery_queue;
static platform_mutex_t recovery_lock;


/* find_endpoints */
static int novacom_usb_find_endpoints(usb_dev_handle *handle, int eps[2], int *iface)
{
	int i;
	int rc;
	struct usb_device *dev = usb_device(handle);

#if USB_SCAN_TRACE
	log_printf(LOG_SPEW, "find novacom endpoints: handle %p device %p\n", handle, dev);
#endif

	if(dev == NULL || dev->config == NULL) {
		return -1;
	}
	struct usb_interface *interface = dev->config->interface;

	for (i = 0; i < dev->config->bNumInterfaces; i++) {
#if USB_SCAN_TRACE
		log_printf(LOG_SPEW, "interfacenum %d\n", i);
#endif

		int a;
		for (a = 0; a < interface->num_altsetting; a++) {

#if USB_SCAN_TRACE
			log_printf(LOG_SPEW, "altsetting %d\n", a);

			log_printf(LOG_SPEW, "class %d subclass %d protocol %d endpoints %d\n",
				interface[i].altsetting[a].bInterfaceClass,
				interface[i].altsetting[a].bInterfaceSubClass,
				interface[i].altsetting[a].bInterfaceProtocol,
				interface[i].altsetting[a].bNumEndpoints);
#endif

			// see if it's a blank interface with two or three bulk endpoints, probably us
			//
			// XXX be smarter about it
			if (interface[i].altsetting[a].bInterfaceClass == USB_CLASS_VENDOR_SPEC &&
				// match against our subclass/protocol id
				(interface[i].altsetting[a].bInterfaceSubClass == 0x47 &&
				interface[i].altsetting[a].bInterfaceProtocol == 0x11) ) {

				// match the two bulk endpoints we care about
				eps[0] = eps[1] = 0;
				if (interface[i].altsetting[a].endpoint[0].bEndpointAddress & 0x80)
					eps[0] = interface[i].altsetting[a].endpoint[0].bEndpointAddress;
				if ((interface[i].altsetting[a].endpoint[1].bEndpointAddress & 0x80) == 0)
					eps[1] = interface[i].altsetting[a].endpoint[1].bEndpointAddress;

				if (eps[0] == 0 || eps[1] == 0) {
					log_printf(LOG_ERROR, "failed to find acceptable endpoints\n");
					continue;
				}

#if 0
				// set the config
				rc = usb_set_configuration(handle, dev->config->bConfigurationValue);
				if (rc) {
					log_printf(LOG_ERROR, "failed to set config %d\n", dev->config->bConfigurationValue);
					return -1;
				}
#endif

				// claim this interface
				rc = usb_claim_interface(handle, i);
				if (rc) {
					//log_printf(LOG_ERROR, "failed to claim interface %d, errno %d\n", i, errno);
					return -1;
				} else if(iface) {
					*iface = i;
				}

#if 0
				// set the alternate interface
				if (a != 0) {
					rc = usb_set_altinterface(handle, a);
					if (rc) {
						log_printf(LOG_ERROR, "failed to set altinterface %d\n", a);
						return -1;
					}
				}
#endif
			
				return 0;
			}
		}
	}

	return -1;
}

static novacom_usb_handle_t *novacom_usb_open( void )
{
	int rc;

//	usb_set_debug(100);

	rc = usb_find_busses();
	if (rc < 0)
		return NULL;

	rc = usb_find_devices();
	if (rc < 0)
		return NULL;

	struct usb_bus *bus;
	struct usb_device *dev;

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		for (dev = bus->devices; dev; dev = dev->next) {
#if USB_SCAN_TRACE
			log_printf(LOG_SPEW, "looking at dev %d (%s) %04x:%04x\n", 
					dev->devnum, dev->filename, 
					dev->descriptor.idVendor, dev->descriptor.idProduct);
#endif
			/* try to match against our list of vendor/products */
			uint i;
			for (i=0; usbid_list[i].name; i++) {
				if ((dev->descriptor.idVendor == usbid_list[i].vendor) && (dev->descriptor.idProduct == usbid_list[i].product)) {
					usb_dev_handle *handle = usb_open(dev);
					if (!handle) continue;

#if USB_SCAN_TRACE
					log_printf(LOG_SPEW, "opened usb handle: fd %d\n", ((struct myusb_dev_handle *)handle)->fd);
#endif

					int eps[2];
					int iface = -1;
					rc = novacom_usb_find_endpoints(handle, eps, &iface);
					if (rc != 0) {
						usb_close(handle);
						continue;
					}

					LTRACEF("got endpoints: %x, %x\n", eps[0], eps[1]);
					novacom_usb_handle_t *usb_handle = platform_calloc(sizeof(novacom_usb_handle_t));
					if(!usb_handle) {
						return NULL;
					}
					usb_handle->handle = handle;
					usb_handle->rxep = eps[0];
					usb_handle->txep = eps[1];
					usb_handle->devtype = usbid_list[i].name;
					usb_handle->busnum = atoi(dev->bus->dirname);
					usb_handle->devnum = dev->devnum;
					usb_handle->iface = iface;
					return usb_handle;
				}
			}
		}
	}

	return NULL;
}

static int novacom_usb_close(novacom_usb_handle_t *usb_handle)
{
	if(usb_handle && usb_handle->handle) {
		/* release iface if used */
		if(usb_handle->iface != -1) {
			usb_release_interface(usb_handle->handle, usb_handle->iface);
		}
		/* close */
		usb_close(usb_handle->handle);
		usb_handle->handle = NULL;
	}

	return 0;
}

int novacom_usb_transport_init(void)
{
	if (geteuid() != 0) {
		log_printf(LOG_ERROR, "need to run as super user to access usb\n");
		return -1;
	}

	usb_init();
	return 0;
}

/* new, native linux implementation */

static int novacom_usb_read(novacom_usb_handle_t *handle, void *buf, size_t len)
{
//	TRACEF("handle %p, buf %p, len %d, timeout %d\n", handle, buf, len, timeout);
//	TRACEF("fd %d\n", handle->myhandle->fd);

	struct usbdevfs_bulktransfer bulktransfer;

	bulktransfer.ep = handle->rxep;
	bulktransfer.len = len;
	bulktransfer.timeout = handle->rx_timeout;
	bulktransfer.data = buf;

	int rc;
	rc = ioctl(handle->myhandle->fd, USBDEVFS_BULK, &bulktransfer);
	if (rc > 0) { //now check the packet header

		if (novacom_usbll_check_packet_header(buf, rc)) { //bad packet
			log_printf(LOG_ERROR, "%s:%d -- received bad packet, set received packet size=%d\n", __FUNCTION__, __LINE__, rc);
			rc = 0;
		}
	}
	//TRACEF("rc %d\n", rc);
	return rc;
}

static int novacom_usb_write(novacom_usb_handle_t *handle, const void *buf, size_t len)
{
//	TRACEF("handle %p, buf %p, len %d, timeout %d\n", handle, buf, len, timeout);
//	TRACEF("fd %d\n", handle->myhandle->fd);

	struct usbdevfs_bulktransfer bulktransfer;

	bulktransfer.ep = handle->txep;
	bulktransfer.len = len;
	bulktransfer.timeout = handle->tx_timeout;
	bulktransfer.data = (void *)buf;

	int rc;
	rc = ioctl(handle->myhandle->fd, USBDEVFS_BULK, &bulktransfer);
//	TRACEF("rc %d\n", rc);
	return rc;
}

struct usb_thread_args {
	novacom_usb_handle_t *handle;
	novacom_usbll_handle_t usbll_handle;
};

static void *novacom_usb_tx_thread(void *arg)
{
	novacom_usb_handle_t *handle = (novacom_usb_handle_t *)arg;
	int rc;
	struct novacom_tx_packet packet;
	char *buf;

	buf = platform_calloc(MAX_MTU);
	platform_assert(buf != NULL);

	LTRACEF("start::wait for startup event: %p\n", handle);
	platform_event_wait(&handle->tx_startup_event);   //why waiting rx for starting ???
	handle->tx_startup_wait = 0;			  //change status to started
	LTRACEF("start::startup event received, continue: %p\n", handle);

	handle->tx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
	while (!novacom_shutdown && !handle->shutdown) {
		// see if we have something to send
		packet.len = novacom_usbll_get_mtu(handle->usbll_handle);
		packet.buf = buf;
		if (novacom_usbll_prepare_tx_packet(handle->usbll_handle, &packet, 100) != TX_NO_PACKET) {
			// write a block back
#if FAULTY_TX
			if (rand() < (RAND_MAX / 10)) {
				TRACEF("dropped tx packet\n");
			} else {
#endif
				rc = novacom_usb_write(handle, packet.buf, packet.len);
				if (rc < 0) {
					platform_time_t st;
					platform_time_t et;
					int time_used = 0;
					unsigned int count = 0;
					TRACEL(LOG_ALWAYS, "usbll(%08x) error writing packet, result(%d), errno %d\n", novacom_usbll_getuid(handle->usbll_handle), rc, errno);
					platform_get_time(&st);
					while (rc < 0 && !handle->shutdown) { //shutdown asap
						platform_get_time(&et);
						if (platform_delta_time_msecs(&st, &et) >= g_usbio_retry_timeout) {
							handle->shutdown = true;
							break;
						}
						if (g_usbio_retry_delay > 0) {
							if ((g_usbio_retry_timeout-time_used) >= g_usbio_retry_delay) {
								usleep(g_usbio_retry_delay * 1000);
								time_used += g_usbio_retry_delay;
							}
							else {
								usleep((g_usbio_retry_timeout - time_used) * 1000);
								time_used = g_usbio_retry_timeout;
							}
						}
						rc = novacom_usb_write(handle, packet.buf, packet.len);
						count++;

					}
		    			TRACEL(LOG_ALWAYS, "usbll(%08x) writing packet, writes(%ld), duration(%dms), result(%d), last_errno %ld\n", novacom_usbll_getuid(handle->usbll_handle), count, platform_delta_time_msecs(&st, &et), rc, errno);
					count = 0;
				}
				if (rc >=0) {
					TRACEF/*LOG_PRINTF*/("usbll(%08x) wrote tx packet len=%d\n", novacom_usbll_getuid(handle->usbll_handle), rc);
				}

#if FAULTY_TX
			}
#endif
		}
	}

	LTRACEF("shutting down handle %p\n", handle);

	platform_event_signal(&handle->tx_shutdown_event);

	platform_free(buf);

	return NULL;
}

static void *novacom_usb_rx_thread(void *arg)
{
	novacom_usb_handle_t *handle = (novacom_usb_handle_t *)arg;
	transport_recovery_token_t *rec_token = NULL;					///< recovery token
	int rc;
	int packet_type;
	char *buf;
	int sniff = 1;

	buf = platform_calloc(MAX_MTU);
	platform_assert(buf != NULL);

	LTRACEF("start, handle %p\n", handle);

	handle->rx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
	while (!novacom_shutdown && !handle->shutdown) {
		platform_time_t st;
		int time_used;
		// read a block from the pmux
		rc = novacom_usb_read(handle, buf, novacom_usbll_get_mtu(handle->usbll_handle));
		platform_get_time(&st);
		time_used = 0;
		if (rc <= 0) {
			platform_time_t et;
			unsigned int count = 0;
			TRACEL(LOG_ALWAYS, "%s:%d -- usbll(%08x) error: reading packet, result(%d), errno %d\n", __FUNCTION__, __LINE__, novacom_usbll_getuid(handle->usbll_handle), rc, errno);
			while (rc <= 0 && !handle->shutdown) { //shutdown asap
				platform_get_time(&et);
				if (platform_delta_time_msecs(&st, &et) >= g_usbio_retry_timeout) {
					handle->shutdown = true;
					break;
				}
				if (g_usbio_retry_delay > 0) {
					if ((g_usbio_retry_timeout-time_used) >= g_usbio_retry_delay) {
						usleep(g_usbio_retry_delay * 1000);
						time_used += g_usbio_retry_delay;
					}
					else {
						usleep((g_usbio_retry_timeout - time_used) * 1000);
						time_used = g_usbio_retry_timeout;
					}
				}
				rc = novacom_usb_read(handle, buf, novacom_usbll_get_mtu(handle->usbll_handle));
				count++;

			}
		    TRACEL(LOG_ALWAYS, "%s:%d -- usbll(%08x) reading packet, reads(%ld), duration(%dms), result(%d), last_errno %ld\n",  __FUNCTION__, __LINE__, novacom_usbll_getuid(handle->usbll_handle), count, platform_delta_time_msecs(&st, &et), rc, errno);
 		    count = 0;

		}

		/* sniff */
		if(sniff) {
			uint32_t uid = ((handle->busnum & 0x0FFFF) << 16) | (handle->devnum & 0x0FFFF);
			transport_recovery_token_t sniff_token;
			int ret;

			/* generate token from packet */
			ret = novacom_usbll_generate_recovery_token(buf, rc, &sniff_token);
			if(ret == -1) {
				TRACEL(LOG_ERROR, "%s:%d -- Used out system resouce, exit now !!!\n", __FUNCTION__, __LINE__);
				abort();
			}
			/* check queue for saved connections */
			ret = usbrecords_find(&sniff_token);
			/* free interface recovery token */
			platform_free(sniff_token.token);
			/* check result: create new handle, or recover */
			if(ret) {
				LTRACEF("Unable to recover(%d)\n", ret);
				handle->usbll_handle = novacom_usbll_create(handle->devtype, MAX_MTU, 0, USBDEVFS_IOCTL_TIMEOUT);
			} else {
				TRACEL(LOG_ERROR, "Recovered record...\n");
				handle->usbll_handle = sniff_token.user_data;
			}
			/* update uid */
			novacom_usbll_setuid(handle->usbll_handle, uid);
			handle->rx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
			handle->tx_timeout = novacom_usbll_get_timeout(handle->usbll_handle);
			sniff = 0;
		}
		/* process */
		packet_type = PACKET_TYPE_NULL;
		if (rc > 0) {
			// process it
			packet_type = novacom_usbll_process_packet(handle->usbll_handle, buf, rc);
			if (packet_type == PACKET_TYPE_BADPACKET) {
				platform_time_t et;
				TRACEF("received bad packet\n");
				platform_get_time(&et);
				if (platform_delta_time_msecs(&st, &et) >= g_usbio_retry_timeout) {
					handle->shutdown = true;
					break;
				}
				if (g_usbio_retry_delay > 0) {
					if ((g_usbio_retry_timeout-time_used) >= g_usbio_retry_delay) {
						usleep(g_usbio_retry_delay * 1000);
						time_used += g_usbio_retry_delay;
					}
					else {
						usleep((g_usbio_retry_timeout - time_used) * 1000);
						time_used = g_usbio_retry_timeout;
					}
				}
				///handle->shutdown = true;
				///break;
			} else if(handle->tx_startup_wait) {
				platform_event_signal(&handle->tx_startup_event);
			}
		} else {
#if TRACE_ZERO_LEN_PACKETS
			log_printf(LOG_TRACE, "RX zero len\n");
#endif
		}
	}

	LTRACEF("shutting down handle %p\n", handle);

	/* wake up tx thread (if still waits for startup) */
	if(handle->tx_startup_wait) {
		LTRACEF("wake up tx thread\n");
		platform_event_signal(&handle->tx_startup_event);
	}

	/* wait for the tx thread to exit */
	LTRACEF("waiting on tx thread\n");
	platform_event_wait(&handle->tx_shutdown_event);

	/* RX thread is responsible for cleaning up */
	LTRACEF("cleaning up handle %p\n", handle);

	/* grab recovery token if available */
	if(handle->usbll_handle) {
		rc = -1;
		rec_token = platform_calloc(sizeof(transport_recovery_token_t));
		if(rec_token) {
			snprintf(rec_token->nduid, sizeof(rec_token->nduid), "%s", novacom_usbll_get_nduid(handle->usbll_handle));
			rc = novacom_usbll_get_recovery_token(handle->usbll_handle, rec_token);
			if(rc != -1) {
				rc = usbrecords_add(rec_token);
			} else {
				LTRACEF("unable to recovery token!!!\n");
			}
		}
		/* error: free memory, destroy device */
		if(rc == -1) { //we should never go here.
			novacom_usbll_destroy(handle->usbll_handle);
			platform_free(rec_token);
		}
	}

	novacom_usb_close(handle);
	platform_event_destroy(&handle->tx_startup_event);
	platform_event_destroy(&handle->tx_shutdown_event);
	platform_free(handle);
	platform_free(buf);

	return NULL;
}

/* main worker thread */
static void *novacom_usb_findandattach_thread(void *arg)
{
	novacom_usb_handle_t *usb;

	/* init records */
	usbrecords_init();

	/* initialize records queue */
	TAILQ_INIT(&t_recovery_queue);

	/* device discovery */
	while (!novacom_shutdown) {

		usb = novacom_usb_open();
		if (usb ) {
			usb->shutdown = false;
			TRACEF("usb_handle 0x%08x, bus=%03d dev=%03d\n", usb->usbll_handle, usb->busnum, usb->devnum);
			platform_event_create(&usb->tx_startup_event);
			platform_event_unsignal(&usb->tx_startup_event);
			usb->tx_startup_wait = 1;
			platform_event_create(&usb->tx_shutdown_event);
			platform_event_unsignal(&usb->tx_shutdown_event);
	
			platform_create_thread(NULL, &novacom_usb_rx_thread, (void *)usb);
			platform_create_thread(NULL, &novacom_usb_tx_thread, (void *)usb);
		}
	
		if (!novacom_shutdown) {
			sleep(1); // dont peg the cpu waiting for usb
			/* check recovery records, shutdown interface if timeout expired */
			(void) usbrecords_update( 1 );	/* assume 1sec delay */
		}
	}

	/* update records: forcing shutdown of all records */
	usbrecords_update(TRANSPORT_RECOVERY_TIMEOUT);

	return NULL;
}

int novacom_usb_transport_start(void)
{
	novacom_shutdown = 0;
	platform_create_thread(&findandattach_thread, &novacom_usb_findandattach_thread, NULL);
	platform_mutex_init(&recovery_lock);
	return 0;
}

int novacom_usb_transport_stop(void)
{
	novacom_shutdown = 1;

	platform_waitfor_thread(findandattach_thread);
	platform_mutex_destroy(&recovery_lock);

	return 0;
}

/*
 * @brief: device_online
 */
int novacom_usb_transport_deviceonline(char *nduid)
{
	usbrecords_remove(nduid);
	return 0;
}


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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <aio.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#include <debug.h>
#include <novacom.h>
#include <platform.h>
#include <transport_usb.h>
#include "usb_gadgetfs.h"
#include "device/auth.h"
//#include "descriptors.h"

#define LOCAL_TRACE			0
#define LOCAL_TRACE_RW		0
#define LOCAL_TRACE_EVENTS	0

#define MAX_MTU 16384
#define  GADGETFS_IO_RETRY_DELAY 100    //100 ms

static int ep0_fd;
static int ep1in_fd;
static int ep2out_fd;
static char rx_buffer[MAX_MTU];
static char tx_buffer[MAX_MTU];
static struct aiocb rxaio;
static struct aiocb txaio;
static platform_event_t usb_online_event;
static volatile bool usb_online = false;		/* online status */
static volatile bool gadgetfs_online = false;	/* postpone online->offline */
novacom_usbll_handle_t usbll_handle = NULL;

static platform_event_t tx_shutdown_event;
static platform_event_t rx_shutdown_event;

/* tentative hack */
static char *ep1in_name = NULL;
static char *ep2out_name = NULL;

static int set_usb_online(bool on);

static int queue_rx(int fd, void *buf, size_t len)
{
	memset(&rxaio, 0, sizeof(rxaio));	
	rxaio.aio_fildes = fd;
	rxaio.aio_buf = buf;
	rxaio.aio_nbytes = len;
	rxaio.aio_offset = 0;
	return aio_read(&rxaio);
}

static int queue_tx(int fd, const void *buf, size_t len)
{
	memset(&txaio, 0, sizeof(txaio));	
	txaio.aio_fildes = fd;
	txaio.aio_buf = (void *)buf;
	txaio.aio_nbytes = len;
	txaio.aio_offset = 0;
	return aio_write(&txaio);
}

static int suspend(const struct aiocb * const list[], int n, struct timespec *timeout)
{
	if (timeout) {
		int t = novacom_usbll_get_timeout(usbll_handle);
		timeout->tv_sec = t / 1000;
		timeout->tv_nsec = (t % 1000) * 1000000;
	}
	return aio_suspend(list, n, timeout);
}

static void *tx_thread_entry(void *arg)
{
	device_pthread_setaffinity();

	int rc;
	int state;
	struct novacom_tx_packet packet;

	const struct aiocb * list[1];
	list[0] = &txaio;

	LOG_PRINTF("entry\n");
	while (usb_online) {
		// see if we have something to send
		packet.len = novacom_usbll_get_mtu(usbll_handle);
		packet.buf = tx_buffer;
		state = novacom_usbll_get_state(usbll_handle);		
		if (novacom_usbll_prepare_tx_packet(usbll_handle, &packet, 100) != TX_NO_PACKET) {

#if	LOCAL_TRACE_RW
			// write a block back
			LTRACEF("going to write packet\n");
#endif

#if 0
			rc = write(ep1in_fd, packet.buf, packet.len);
			LTRACEF("rc %d\n", rc);
			if (rc < 0) {
				TRACEF("error writing packet\n");
				break;
			}
#else
			rc = queue_tx(ep1in_fd, packet.buf, packet.len);
			if (rc < 0) {
				LOG_PRINTF("USB aio_write error, ret=%d, errno=%d\n", rc, errno);
				usleep(1000*GADGETFS_IO_RETRY_DELAY);
				novacom_usbll_changeback_state(usbll_handle, state);
				continue;
			}
			struct timespec timeout;
			rc = suspend(list, 1, &timeout);
			while (rc < 0 && errno == EAGAIN) {
				LOG_PRINTF("USB aio_suspend (for write) error, ret=%d, errno=%d\n", rc, errno);
				rc = suspend(list, 1, &timeout);
				if (rc >= 0) {
					LOG_PRINTF("USB aio_suspend (for write) ret=%d, errno=%d\n", rc, errno);
				}
			};
#if 0
			//do we need it ???
			if (rc < 0) {
				LTRACEF("timeout on tx\n");
				rc = aio_suspend(list, 1, NULL);
			}
#endif
			if (aio_error(&txaio) != EINPROGRESS) {
				rc = aio_return(&txaio);
				if (rc < 0) {
					/* online->offline transition */
					LOG_PRINTF("USB aio_return (for write) error, ret=%d, \n", rc);
					if( (usb_online != gadgetfs_online) && (true == usb_online) ) {
						int ret = platform_event_wait_timeout(&usb_online_event, TRANSPORT_RECOVERY_TIMEOUT * 1000*2);
						if (!ret) {
							LOG_PRINTF("platform_event_wait_timeout for usb_online_event, ret=%d\n", ret);
						}
						else {
							LOG_PRINTF("platform_event_wait_timeout for usb_online_event, ret=%d, ignored\n", ret);
						}
					}
				}
			}
			else {
				LOG_PRINTF("we should never enter here (EINPROGRESS=%d), USB aio write seems to have problem!\n", EINPROGRESS);
			}
			if (rc < 0) {
				novacom_usbll_changeback_state(usbll_handle, state);
			}
			else {
				static platform_time_t prior;
				static int init = 0;
				static unsigned int tx_bytes = 0, tx_packets = 0;
				platform_time_t curr;

				tx_bytes += packet.len;
				tx_packets++;
				if (!init) {
					platform_get_time(&prior);
					init = 1;
				}
				platform_get_time(&curr);
				if (platform_delta_time_msecs(&prior, &curr) >= 2800) { //logging for every 3sec
					platform_get_time(&prior);
					LOG_PRINTF("wrote %u bytes, %u packets\n",tx_bytes, tx_packets);
				}
			}
#endif
		}
	}

	LOG_PRINTF("shutting down\n");
	platform_event_signal(&tx_shutdown_event);

	return NULL;
}

static void *rx_thread_entry(void *arg)
{
	device_pthread_setaffinity();

	int rc;

	const struct aiocb * list[1];
	list[0] = &rxaio;

	LOG_PRINTF("entry\n");
	while (usb_online) {

#if LOCAL_TRACE_RW
		LTRACEF("going to read packet\n");
#endif

#if 0
		rc = read(ep2out_fd, rx_buffer, sizeof(rx_buffer));
		LTRACEF("read rc %d\n", rc);
		if (rc < 0) {
			TRACEF("error reading packet\n");
		}
		if (rc > 0) {
			novacom_usbll_process_packet(usbll_handle, rx_buffer, rc);
		}
#else
		rc = queue_rx(ep2out_fd, rx_buffer, novacom_usbll_get_mtu(usbll_handle));	
		if (rc < 0) {
			LOG_PRINTF("USB aio_read error, ret=%d, errno=%d\n", rc, errno);
			usleep(1000*GADGETFS_IO_RETRY_DELAY);
			continue;
		}

		struct timespec timeout;
		rc = suspend(list, 1, &timeout);
		while (rc < 0 && errno == EAGAIN) {
			LOG_PRINTF("USB aio_suspend (for read) error, ret=%d, errno=%d\n", rc, errno);
			rc = suspend(list, 1, &timeout);
			if (rc >= 0) {
				LOG_PRINTF("USB aio_suspend (for read), ret=%d, errno=%d\n", rc, errno);
			}
			//the gadget_fs event should be the source to notify usb device offline
			///novacom_usbll_drop_offline(usbll_handle);
			// suspend after usbll_drop_offline ?????
			///aio_suspend(list, 1, NULL);
		};

		if (aio_error(&rxaio) != EINPROGRESS) {
			rc = aio_return(&rxaio);
#if LOCAL_TRACE_RW
		LTRACEF("rx successful: nbytes %d\n", rc);
#endif
			if (rc > 0) {
				rc = novacom_usbll_process_packet(usbll_handle, rx_buffer, rc);
				if (rc == PACKET_TYPE_BADPACKET) {
					LOG_PRINTF("Received bad packet, ret=%d, \n", rc);
				}	
			} else {
				/* online->offline transition */
				LOG_PRINTF("USB aio_return (for read) error, ret=%d, \n", rc);
				if( (usb_online != gadgetfs_online) && (true == usb_online) ) {
					int ret = platform_event_wait_timeout(&usb_online_event, TRANSPORT_RECOVERY_TIMEOUT * 1000*2);
					if (!ret) {
						LOG_PRINTF("platform_event_wait_timeout for usb_online_event, ret=%d\n", ret);
					}
					else {
						LOG_PRINTF("platform_event_wait_timeout for usb_online_event, ret=%d, ignored\n", ret);
					}					
				}
			}
		}
		else {
			LOG_PRINTF("we should never enter here (EINPROGRESS=%d), USB aio read seems to have problem!\n", EINPROGRESS);
		}
#endif
	}

	LOG_PRINTF("shutting down\n");
	platform_event_signal(&rx_shutdown_event);

	return NULL;
}

static int set_usb_online(bool on)
{ 
	if (on) {
		if (!usb_online) {

			/*init */
			auth_init();

			/* sleep for a second to let things settle down */
			sleep(1);

			platform_event_unsignal(&tx_shutdown_event);
			platform_event_unsignal(&rx_shutdown_event);

			usbll_handle = novacom_usbll_create("host", MAX_MTU, 0, 0);

			ep1in_fd = open(ep1in_name, O_RDWR);
			LOG_PRINTF("ep1 %d\n", ep1in_fd);
			if (ep1in_fd < 0) {
				log_printf(LOG_ERROR, "error opening endpoint 1\n");
				return -1;
			}
			fcntl(ep1in_fd, F_SETFD, FD_CLOEXEC);

			ep2out_fd = open(ep2out_name, O_RDWR);
			LOG_PRINTF("ep2 %d\n", ep2out_fd);
			if (ep2out_fd < 0) {
				log_printf(LOG_ERROR, "error opening endpoint 2\n");
				close(ep1in_fd);
				return -1;
			}
			fcntl(ep2out_fd, F_SETFD, FD_CLOEXEC);
 
			usb_online = true;
			platform_event_signal(&usb_online_event);	

			/* create the worker threads */
			LOG_PRINTF("starting worker threads\n");

			platform_create_thread(NULL, &tx_thread_entry, NULL);
			platform_create_thread(NULL, &rx_thread_entry, NULL);
		} else if(false == gadgetfs_online) {
			/* postponed_offline->online */
			platform_event_signal(&usb_online_event);
		}
	} else {
		if (usb_online) {
			//change state before sending out signal!
			usb_online = false;
			platform_event_signal(&usb_online_event);

			/* wait for the existing worker threads to go away */
			LOG_PRINTF("waiting for worker threads to go away\n");
			platform_event_wait(&tx_shutdown_event);
			close(ep1in_fd);
			LOG_PRINTF("closed tx_thread\n");

			platform_event_wait(&rx_shutdown_event);
			close(ep2out_fd);
			LOG_PRINTF("closed rx_thread\n");
			novacom_usbll_destroy(usbll_handle);
			LOG_PRINTF("destroyed novacom usbll_handle\n");

			/* clear auth */
			auth_reset();
		}
	}
	return 0;
}

int novacom_usb_transport_init(void)
{
	/* init auth */
	auth_create();

	return 0;
}

// unknown _why_ we're retrying these opens, but assuming that there was a _real_
// reason I'll leave it in but with a sane number of retries
//
// It seems unnecessary to try more than once but trying 5 times because previously
// the code tried forever.

#define GADGET_RETRY_COUNT 5
static void *ep0_thread(void *arg)
{
	device_pthread_setaffinity();

	char buf[sizeof(struct usb_gadgetfs_event)*10]; /* store up to 10 events */
	fd_set fds;
	struct timeval tv;
	int rc;

	LOG_PRINTF("entry: self %ld\n", syscall(SYS_gettid));
	rc = 0; 	// re-use rc as a loop counter
retry:
	/* novacom_ep0 */
	ep0_fd = open("/dev/novacom_ep0", O_RDWR);
	if (ep0_fd >= 0) {
		ep1in_name = "/dev/novacom_ep_in";
		ep2out_name = "/dev/novacom_ep_out";
		goto opened;
	}

	/* try the omap3's usb port first */
	ep0_fd = open("/dev/gadget/musb_hdrc", O_RDWR);
	if (ep0_fd >= 0) {
		struct stat stbuf;
		if (stat("/dev/gadget/ep4in", &stbuf) == 0) {
			ep1in_name = "/dev/gadget/ep4in";
			ep2out_name = "/dev/gadget/ep3out";
		} else {
			ep1in_name = "/dev/gadget/ep2in";
			ep2out_name = "/dev/gadget/ep2out";
		}
		goto opened;
	}

	/* omap2 */
	ep0_fd = open("/dev/gadget/omap_udc", O_RDWR);
	if (ep0_fd >= 0) {
		ep1in_name = "/dev/gadget/ep7in-bulk";
		ep2out_name = "/dev/gadget/ep8out-bulk";
		goto opened;
	}

	/* msm */
	ep0_fd = open("/dev/gadget/msm_hsusb", O_RDWR);
	if (ep0_fd >= 0) {
		struct stat stbuf;
		if (stat("/dev/gadget/ep4in", &stbuf) == 0) {
			ep1in_name = "/dev/gadget/ep4in";
			ep2out_name = "/dev/gadget/ep3out";
		} else {
			ep1in_name = "/dev/gadget/ep2in";
			ep2out_name = "/dev/gadget/ep2out";
		}
		goto opened;
	}

	/* fail */
	rc++;
	if (rc >= GADGET_RETRY_COUNT) {
		log_printf(LOG_ERROR, "failed to open gadgetfs %d times - giving up on usb\n", rc);
		return (NULL);
	}

	log_printf(LOG_ERROR, "failed to open gadgetfs ep0 node - retry\n");
	sleep(1);
	goto retry;

opened:
	fcntl(ep0_fd, F_SETFD, FD_CLOEXEC);

	/* main loop */
	for (;;) {
		struct timeval *ptrtv = NULL;
		/* we use timeout only when required:: usb_online && gadgetfs disconnect event*/
		if( (gadgetfs_online == false) && usb_online) {
			ptrtv = &tv;
			tv.tv_sec = TRANSPORT_RECOVERY_TIMEOUT;
			tv.tv_usec = 0;
			/* about to trigger wait timer: clear event */
			platform_event_unsignal(&usb_online_event);
		}
		/* select */
		FD_ZERO(&fds);
		FD_SET(ep0_fd, &fds);
		rc = select(ep0_fd + 1, &fds, NULL, NULL, ptrtv);
		/* error */
		if(-1 == rc) {
			if((EAGAIN == errno) || (EINTR == errno)) {
				continue;
			} else {
				break;
			}
		}

		/* timeout */
		if(rc == 0) {
			/* gadgetfs reported disconnect */
			if( (gadgetfs_online == false) && usb_online) {
				LOG_PRINTF("Postponed going offline...\n");
				set_usb_online(false);
			}
			else {
				LOG_PRINTF("Timeout, usb is in online state, to continue...\n");
			}
			continue;
		}

		/*normal flow */
		if ( !(FD_ISSET(ep0_fd, &fds)) ) {
			continue;
		}
		int err = read(ep0_fd, buf, sizeof(buf));
		LOG_PRINTF("ep0 err %d\n", err);
		if (err < 0)
			break;

		struct usb_gadgetfs_event *event = (struct usb_gadgetfs_event *)buf;
		int nevents = err / sizeof(struct usb_gadgetfs_event);
		for (; nevents > 0; nevents--) {
			LOG_PRINTF("got usb event type %d: ", event->type);
			switch (event->type) {
				case GADGETFS_NOP:
					LOG_PRINTF("NOP\n");
					break;
				case GADGETFS_CONNECT:
					LOG_PRINTF("CONNECT\n");
					LOG_PRINTF("speed %d\n", event->u.speed);
					break;
				case GADGETFS_DISCONNECT:
					LOG_PRINTF("DISCONNECT\n");
					gadgetfs_online = false;
					break;
				case GADGETFS_SETUP:
					LOG_PRINTF("SETUP: requesttype 0x%x, request 0x%x, value 0x%x, index 0x%x, length 0x%x", event->u.setup.bRequestType, event->u.setup.bRequest, event->u.setup.wValue, event->u.setup.wIndex, event->u.setup.wLength);
					switch (event->u.setup.bRequest) {
						case USB_REQ_SET_INTERFACE:
							LOG_PRINTF("USB_REQ_SET_INTERFACE: %d\n", event->u.setup.wValue);

							// setting interface to 0 seems to be a disconnect
//								if (event->u.setup.wValue == 0) {
//									stop_io();
//								}
							break;
						case USB_REQ_SET_CONFIGURATION:
							LOG_PRINTF("USB_REQ_SET_CONFIGURATION: config %d\n", event->u.setup.wValue);
							if (event->u.setup.wValue > 0) {
								if(set_usb_online(true) < 0) {
									close(ep0_fd);
									goto retry;
								}
								gadgetfs_online = true;
							} else {
								gadgetfs_online = false;
							}
							break;
						default:
							LOG_PRINTF("unhandled request\n");
					}
					break;
				case GADGETFS_SUSPEND:
					LOG_PRINTF("SUSPEND\n");
					break;
				default:
					LOG_PRINTF("UNKNOWN\n");
					break;
			}

			event++;
		}
	}

	LOG_PRINTF("closing ep0\n");
	set_usb_online(false);
	close(ep0_fd);

	return NULL;
}

int novacom_usb_transport_start(void)
{

	/*clear auth */
	auth_reset();

	/* create an event to drive the io worker thread */
	platform_event_create(&usb_online_event);
	platform_event_unsignal(&usb_online_event);

	/* create a set of events to track the status of the io threads */
	platform_event_create(&rx_shutdown_event);
	platform_event_unsignal(&rx_shutdown_event);
	platform_event_create(&tx_shutdown_event);
	platform_event_unsignal(&tx_shutdown_event);

	/* create a thread to run the control endpoint */
	platform_create_thread(NULL, &ep0_thread, NULL);

	return 0;
}

int novacom_usb_transport_stop(void)
{
	/*clear auth */
	auth_reset();

	return 0;
}


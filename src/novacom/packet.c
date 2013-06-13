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

#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/ioctl.h>

#include <debug.h>
#include <platform.h>

#include "packet.h"
#include "packet_struct.h"

#define LOCAL_TRACE 0

#define QUEUE_MAX 65536


static void packet_sync_callback(void *cookie)
{
	platform_event_signal((platform_event_t*)cookie);
}

static int send_packet(device_handle_t device_handle, int channel, int type, void * buf, size_t size)
{
	int rc;
	struct packet_header h;
	buf_entry_t *chain = NULL;
	platform_event_t done;

	LTRACEF("channel %d, type %d, size %u\n", channel, type, size);

	/* TODO::sync call: avoid memcpy */
	bufc_prepend_data(&chain, buf, size);

	/* memset(0) not required:: all structure members are initialised */
	h.magic = PACKET_HEADER_MAGIC;
	h.version = PACKET_HEADER_VERSION;
	h.size = size;
	h.type = type;
	bufc_prepend_data(&chain, &h, sizeof(h));

	platform_event_create(&done);
	bufc_append_callback(&chain, packet_sync_callback, (void *)&done);

	rc = novacom_queue_tx_chain(device_handle, channel, chain);
	if (rc < 0) {
		/* error, clean it up */
		bufc_destroy(&chain);
		return rc;
	}

	platform_event_wait(&done);
	platform_event_destroy(&done);

	return 0;
}

int send_packet_data(device_handle_t device_handle, int channel, void * buf, size_t size)
{
	LTRACEF("channel %d, size %u\n", channel, size);
	int rc = send_packet(device_handle, channel, PACKET_HEADER_TYPE_DATA, buf, size);
	return rc;
}

int send_packet_err(device_handle_t device_handle, int channel, void * buf, size_t size)
{
	LTRACEF("channel %d, size %u\n", channel, size);
	int rc = send_packet(device_handle, channel, PACKET_HEADER_TYPE_ERR, buf, size);
	return rc;
}

int send_packet_eof(device_handle_t device_handle, int channel, int fileno)
{
	struct packet_oob_msg m;

	LTRACEF("channel %d, fileno %d\n", channel, fileno);

	memset(&m,0,sizeof(m));
	m.message = PACKET_OOB_EOF;
	m.data.fileno = fileno;

	int rc = send_packet(device_handle, channel, PACKET_HEADER_TYPE_OOB, &m, sizeof(m));
	return rc;
}

int send_packet_returncode(device_handle_t device_handle, int channel, int r)
{
	struct packet_oob_msg m;

	LTRACEF("channel %d, retcode %d\n", channel, r);

	memset(&m,0,sizeof(m));
	m.message = PACKET_OOB_RETURN;
	m.data.returncode = r;

	int rc = send_packet(device_handle, channel, PACKET_HEADER_TYPE_OOB, &m, sizeof(m));
	return rc;
}

void *packet_thread(void *arg)
{
	device_pthread_setaffinity();

	struct packet_thread_args *args = (struct packet_thread_args *)arg;

	bool outq_open = (args->out_queue != NULL);
	bool stdout_open = (args->stdoutpipe != -1);
	bool stderr_open = (args->stderrpipe != -1);
	size_t total_data = 0;

	while (true) {
		struct packet_header h;
		struct packet_oob_msg m;
		ssize_t rc;

		rc = bufq_read_sleep(args->in_queue, (char *)&h, sizeof(h));
		if ((size_t)rc < sizeof(h) ) 
			goto conn_fail;

		if (h.magic != PACKET_HEADER_MAGIC) {
			log_printf(LOG_ERROR, "Bad packet header magic\n");
			goto conn_fail;
		}
		if (h.version != PACKET_HEADER_VERSION) {
			log_printf(LOG_ERROR, "Unsupported packet version\n");
			goto conn_fail;
		}

		switch (h.type) {
			case PACKET_HEADER_TYPE_DATA:
				// main stream, splice out the data
				if (outq_open) {
					if (bufq_len(args->out_queue) > QUEUE_MAX) {
						LTRACEF("flooding the out queue, sleeping\n");
						bufq_wait_for_empty(args->out_queue);
					}
					rc = bufq_splice_sleep(args->out_queue, args->in_queue, h.size);
					total_data += h.size;
				} else {
					rc = bufq_consume_sleep(args->in_queue, h.size);
				}
				if ((size_t)rc < h.size) 
					goto conn_fail;
				break;
			case PACKET_HEADER_TYPE_OOB:
				// oob data, handle message
				rc = bufq_read_sleep(args->in_queue, (char *)&m, sizeof(m));
				if ((size_t)rc < sizeof(m) )
					goto conn_fail;

				switch (m.message) {
					case PACKET_OOB_EOF:
						switch (m.data.fileno) {
							case STDIN_FILENO:
								if (outq_open) {
									// wait for the queue to empty, then close it
									bufq_wait_for_empty(args->out_queue);
									bufq_close(args->out_queue);
									outq_open = false;
								}
							break;
							case STDOUT_FILENO:
								if (stdout_open) {
									// triggers the thread to exit
									char c = 0x01;
									if( write(args->stdoutpipe, &c, 1) < 0) {
										rc = write(args->stdoutpipe, &c, 1);
									}
									stdout_open = false;
								}
							break;
							case STDERR_FILENO:
								if (stderr_open) {
									// triggers the thread to exit
									char c = 0x02;
									if( write(args->stderrpipe, &c, 1) < 0) {
										rc = write(args->stderrpipe, &c, 1);
									}
									stderr_open = false;
								}
								break;
							default:
								TRACEF("tried to close unknown fileno %d\n", m.data.fileno);
							break;
						}
						break;
					case PACKET_OOB_SIGNAL:
						if (args->child) {
							LTRACEF("Sending signal %d to %d\n", m.data.signo, args->child);
							kill(args->child, m.data.signo);
						}
						break;
					case PACKET_OOB_RESIZE:
						if (args->child) {
							LTRACEF("got resize signal: rows %d cols %d\n", m.data.resize.rows, m.data.resize.cols);

							// XXX this seems like a race where the other thread could have already
							// closed this fd
							if (stdout_open && args->stdoutfd >= 0) {
								struct winsize ws;
								int rc;

								rc = ioctl(args->stdoutfd, TIOCGWINSZ, &ws);
								if(rc != -1) {
									ws.ws_row = m.data.resize.rows;
									ws.ws_col = m.data.resize.cols;
									LTRACEF("setting winsize to %d %d on fd %d\n", ws.ws_row, ws.ws_col, args->stdoutfd);
									rc = ioctl(args->stdoutfd, TIOCSWINSZ, &ws);
									if(rc != -1) {
										kill(args->child, SIGWINCH);
									} else {
										TRACEF("Unable to set winsize to %d %d on fd %d\n", ws.ws_row, ws.ws_col, args->stdoutfd);
									}
								}	
							}
						}
						break;
					case PACKET_OOB_RETURN:
						// what?
						TRACEF("Got a return code from the other side. no idea why.\n");
						break;
					default:
						TRACEF("bad OOB message from other side %d\n", m.message);
						break;
				} // switch (m.message)

				if (h.size > sizeof(m)) {
					rc = bufq_consume_sleep(args->in_queue, h.size - sizeof(m));
					if ((size_t)rc < (h.size - sizeof(m)) ) 
						goto conn_fail;
				}
				break;
			case PACKET_HEADER_TYPE_ERR:
				TRACEF("unexpected incoming stderr data");
			default:
				rc = bufq_consume_sleep(args->in_queue, h.size);
				if ((size_t)rc < h.size) 
					goto conn_fail;
				break;
		} // switch (h.type)
	}

conn_fail:
	if (outq_open) 
		bufq_close(args->out_queue);
	platform_event_signal(args->done);
	platform_free(arg);
	LTRACEF("exiting\n");
//	TRACEF("exiting, total data written %u\n", total_data);
	return NULL;
}


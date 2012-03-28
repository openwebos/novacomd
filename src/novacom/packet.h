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

#ifndef __PACKET_H
#define __PACKET_H

#include "buf_queue.h"
#include <novacom.h>

/* api stuff */
struct packet_thread_args {
	platform_event_t *done;
	buf_queue_t *in_queue;
	buf_queue_t *out_queue;
	pid_t child;
	int stdoutpipe;
	int stderrpipe;
	int stdoutfd;
};

int send_packet_data(device_handle_t device_handle, int channel, void * buf, size_t size);
int send_packet_err(device_handle_t device_handle, int channel, void * buf, size_t size);
int send_packet_eof(device_handle_t device_handle, int channel, int fileno);
int send_packet_returncode(device_handle_t device_handle, int channel, int r);

void *packet_thread(void *arg);

#endif


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

#ifndef __BUF_QUEUE_H
#define __BUF_QUEUE_H

#include <sys/types.h>
#include <platform.h>

typedef struct buf_entry buf_entry_t;

struct buf_entry {
	buf_entry_t *next;
	char *buf;
	size_t bufsize;
	bool immutable; // don't touch the buf
	size_t start;
	size_t len;
	void (*_free)(buf_entry_t *entry);
	void (*callback)(void *cookie);
	void *cookie; // user data for the callback func
};

typedef struct buf_queue buf_queue_t;

struct buf_queue {
	buf_entry_t *head;
	platform_mutex_t lock;
	platform_event_t wake;
	bool eof;
};

void buf_init(buf_entry_t *entry);
void buf_destroy(buf_entry_t *entry);
void bufc_destroy(buf_entry_t **chain);
void bufq_destroy(buf_queue_t *queue);
void bufq_destroy_sleep(buf_queue_t *queue);
buf_queue_t *bufq_create(void);
void bufc_prepend_chain(buf_entry_t **chain, buf_entry_t *_new);
void bufc_append_chain(buf_entry_t **chain, buf_entry_t *_new);
void bufq_append_chain(buf_queue_t *queue, buf_entry_t *chain);
void bufc_append_callback(buf_entry_t **chain, void (*callback)(void *cookie), void *cookie);
void bufq_append_callback(buf_queue_t *queue, void (*callback)(void *cookie), void *cookie);
void bufc_prepend_data(buf_entry_t **chain, const void *buf, size_t len);
void bufc_append_data(buf_entry_t **chain, const void *buf, size_t len);
void bufq_append_data(buf_queue_t *queue, const void *buf, size_t len);
size_t bufc_len(buf_entry_t **chain);
size_t bufq_len(buf_queue_t *queue);
ssize_t bufq_splice_nonblock(buf_queue_t *to, buf_queue_t *from, size_t size);
ssize_t bufq_splice_sleep(buf_queue_t *to, buf_queue_t *from, size_t size);
ssize_t bufq_read_nonblock(buf_queue_t *queue, char *buf, size_t size);
ssize_t bufq_read_sleep(buf_queue_t *queue, char *buf, size_t size);
ssize_t bufq_read_sleepempty(buf_queue_t *queue, char *buf, size_t size);
ssize_t bufc_consume(buf_entry_t **chain, size_t size);
ssize_t bufq_consume_nonblock(buf_queue_t *queue, size_t size);
ssize_t bufq_consume_sleep(buf_queue_t *queue, size_t size);
ssize_t bufc_peek(buf_entry_t **chain, char *buf, size_t size);
ssize_t bufq_peek_nonblock(buf_queue_t *queue, char *buf, size_t size);
ssize_t bufq_peek_sleep(buf_queue_t *queue, char *buf, size_t size);
ssize_t bufc_peek_onechunk(buf_entry_t **chain, char *buf, size_t size);
ssize_t bufq_peek_onechunk_nonblock(buf_queue_t *queue, char *buf, size_t size);
ssize_t bufq_peek_onechunk_sleep(buf_queue_t *queue, char *buf, size_t size);
void bufq_wait_for_empty(buf_queue_t *queue);
void bufq_close(buf_queue_t *queue);


#endif

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
#include <debug.h>
#include <string.h>
#include <stdio.h>

#include <buf_queue.h>

#define LOCAL_TRACE 0

// Buf chains are for manipulating packets
// Buf queues are pipes

void buf_init(buf_entry_t *entry)
{
	entry->next = NULL;
	entry->buf = NULL;
	entry->bufsize = 0;
	entry->immutable = false;
	entry->start = 0;
	entry->len = 0;
	entry->_free = NULL;
	entry->callback = NULL;
	entry->cookie = NULL;
}

void buf_destroy(buf_entry_t *entry)
{
	LTRACEF("%p\n", entry);

	if (entry->callback) {
		(entry->callback)(entry->cookie);
		entry->cookie = NULL;
	}
	platform_free(entry->buf);
	platform_free(entry);
}

void bufc_destroy(buf_entry_t **chain)
{
	LTRACEF("%p\n", chain);
	buf_entry_t *e = *chain;

	while (e) {
		*chain = e->next;
		e->_free(e);
		e = *chain;
	}
}

void bufq_destroy(buf_queue_t *queue)
{
	LTRACEF("%p\n", queue);
	platform_mutex_lock(&queue->lock);
	bufc_destroy(&queue->head);
	platform_mutex_unlock(&queue->lock);
	platform_mutex_destroy(&queue->lock);
	platform_event_destroy(&queue->wake);
	platform_free(queue);
}

void bufq_destroy_sleep(buf_queue_t *queue)
{
	LTRACEF("%p\n", queue);

	while (1) {
		platform_mutex_lock(&queue->lock);
		platform_event_unsignal(&queue->wake);

		if (!queue->eof) {
			bufc_destroy(&queue->head);
			platform_mutex_unlock(&queue->lock);
		} else {
			platform_mutex_unlock(&queue->lock);
			bufq_destroy(queue);
			return;
		}

		platform_event_wait(&queue->wake);
	}
}

buf_queue_t *bufq_create(void)
{
	buf_queue_t *q = (buf_queue_t *)platform_alloc(sizeof(buf_queue_t));
	LTRACEF("%p\n", q);
	platform_assert(q);

	platform_mutex_init(&q->lock);
	platform_event_create(&q->wake);
	q->head = NULL;
	q->eof = false;

	return q;
}


void bufc_prepend_chain(buf_entry_t **chain, buf_entry_t *_new)
{
	LTRACEF("%p %p\n", chain, _new);
	buf_entry_t *e = _new;

	while (e->next) 
		e = e->next;
	e->next = *chain;
	*chain = _new;
}

void bufc_append_chain(buf_entry_t **chain, buf_entry_t *_new)
{
	LTRACEF("%p %p\n", chain, _new);

	if (*chain == NULL) {
		*chain = _new;
	} else {
		buf_entry_t *e = *chain;
		while (e->next) e = e->next;
		e->next = _new;
	}
}

void bufq_append_chain(buf_queue_t *queue, buf_entry_t *chain)
{
	LTRACEF("%p %p\n", queue, chain);

	platform_mutex_lock(&queue->lock);
	bufc_append_chain(&queue->head, chain);
	platform_event_signal(&queue->wake);
	platform_mutex_unlock(&queue->lock);
}

void bufc_append_callback(buf_entry_t **chain, void (*callback)(void *cookie), void *cookie)
{
	LTRACEF("%p %p %p\n", chain, callback, cookie);

	buf_entry_t *entry = (buf_entry_t *)platform_alloc(sizeof(buf_entry_t));
	platform_assert(entry);

	buf_init(entry);
	entry->immutable = true;
	entry->_free = buf_destroy;
	entry->callback = callback;
	entry->cookie = cookie;
	bufc_append_chain(chain, entry);
}

void bufq_append_callback(buf_queue_t *queue, void (*callback)(void *cookie), void *cookie)
{
	LTRACEF("%p %p %p", queue, callback, cookie);

	platform_mutex_lock(&queue->lock);
	bufc_append_callback(&queue->head, callback, cookie);
	platform_mutex_unlock(&queue->lock);
}

// round up to closest multiple of 1024
#define ROUND_UP(x) (((x) & ~0x3FFL) + 0x400)

void bufc_prepend_data(buf_entry_t **chain, const void *buf, size_t len)
{
	LTRACEF("%p %p %d\n", chain, buf, len);
	buf_entry_t *e = *chain;

	if (e && !e->immutable && (e->start >= len)) {
		// tack the data into the existing head
		e->start -= len;
		e->len += len;
		memcpy(e->buf + e->start, buf, len);
	} else {
		// create a new entry
		buf_entry_t *entry = (buf_entry_t *)platform_alloc(sizeof(buf_entry_t));

		platform_assert(entry);
		buf_init(entry);

		entry->buf = (char*)platform_alloc(ROUND_UP(len));
		platform_assert(entry->buf);
		entry->_free = buf_destroy;
		entry->bufsize = ROUND_UP(len);
		entry->start = entry->bufsize - len;
		entry->len = len;
		memcpy(entry->buf + entry->start, buf, len);

		bufc_prepend_chain(chain, entry);
	}
}

void bufc_append_data(buf_entry_t **chain, const void *buf, size_t len)
{
	LTRACEF("%p %p %d\n", chain, buf, len);

	buf_entry_t *e = *chain;

	while (e && e->next) 
		e = e->next;

	if (e && !e->immutable && ((e->bufsize - (e->start + e->len)) >= len)) {
		// tack the data onto the end of the buffer
		memcpy(e->buf + e->start + e->len, buf, len);
		e->len += len;
	} else {
		// create a new entry
		buf_entry_t *entry = (buf_entry_t *)platform_alloc(sizeof(buf_entry_t));
		platform_assert(entry);
		buf_init(entry);
		entry->buf = (char*)platform_alloc(len);
		platform_assert(entry->buf);
		entry->_free = buf_destroy;
		entry->bufsize = len;
		entry->start = 0;
		entry->len = len;
		memcpy(entry->buf + entry->start, buf, len);

		bufc_append_chain(chain, entry);
	}
}

void bufq_append_data(buf_queue_t *queue, const void *buf, size_t len)
{
	LTRACEF("%p %p %d\n", queue, buf, len);
	platform_mutex_lock(&queue->lock);
	bufc_append_data(&queue->head, buf, len);
	platform_event_signal(&queue->wake);
	platform_mutex_unlock(&queue->lock);
}

size_t bufc_len(buf_entry_t **chain)
{
	buf_entry_t *e = *chain;
	size_t len = 0;

	while (e) {
		len += e->len;
		e = e->next;
	}
	return len;
}

size_t bufq_len(buf_queue_t *queue)
{
	platform_mutex_lock(&queue->lock);
	size_t len = bufc_len(&queue->head);
	platform_mutex_unlock(&queue->lock);

	return len;
}

ssize_t bufq_splice_nonblock(buf_queue_t *to, buf_queue_t *from, size_t size)
{
	LTRACEF("%p %p %d\n", to, from, size);
	size_t copied = 0;

	platform_mutex_lock(&from->lock);
	platform_mutex_lock(&to->lock);
	buf_entry_t *f = from->head;
	buf_entry_t *t = to->head;

	while (t && t->next) 
		t = t->next;

	if (f == NULL) 
		goto done;

	while (f && (f->len <= (size - copied))) {
		// remove from from
		from->head = f->next;
		f->next = NULL;

		// append to to
		if (t) {
			t->next = f;
		} else {
			to->head = f;
		}
		t = f;
		copied += f->len;
		f = from->head;
	}

	if (f && (size - copied)) {
		// memcpy the last chunk
		if (t) {
			bufc_append_data(&t, f->buf + f->start, (size - copied));
		} else {
			bufc_append_data(&to->head, f->buf + f->start, (size - copied));
		}
		bufc_consume(&f, (size - copied));
		copied = size;
	}

done:
	if (copied) 
		platform_event_signal(&to->wake);

	platform_mutex_unlock(&to->lock);
	platform_mutex_unlock(&from->lock);
	return copied;
}

ssize_t bufq_splice_sleep(buf_queue_t *to, buf_queue_t *from, size_t size)
{
	LTRACEF("%p %p %d\n", to, from, size);
	size_t copied = 0;

	while (size - copied) {
		// check to see if the from queue is empty and closed
		platform_mutex_lock(&from->lock);
		bool eof = from->eof;
		bool empty = (bufc_len(&from->head) == 0);
		platform_event_unsignal(&from->wake);
		platform_mutex_unlock(&from->lock);
		if (empty && eof) 
			goto done;

		// splice available data
		copied += bufq_splice_nonblock(to, from, size - copied);

		// sleep if we're not done
		if ((size - copied) && !eof) 
			platform_event_wait(&from->wake);
	}
done:
	return copied;
}

ssize_t bufq_read_nonblock(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);
	platform_assert(buf);
	size_t copied = 0;

	platform_mutex_lock(&queue->lock);
	buf_entry_t *e = queue->head;

	while (e && (e->len <= (size - copied))) {
		// consume a whole buf entry
		queue->head = e->next;
		if (e->len)
			memcpy(buf + copied, e->buf + e->start, e->len);
		copied += e->len;
		e->_free(e);
		e = queue->head;
	}

	if (e && (size - copied)) {
		// consume a partial buf entry
		memcpy(buf + copied, e->buf + e->start, (size - copied));
		e->start += size - copied;
		e->len -= size - copied;
		copied = size;
	}

	while (e && (e->len == 0)) {
		// trailing zero-length buf, consume it to trigger a callback
		queue->head = e->next;
		e->_free(e);
		e = queue->head;
	}

	platform_mutex_unlock(&queue->lock);

	return copied;
}

ssize_t bufq_read_sleep(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);
	size_t copied = 0;

	while (size - copied) {
		// check to see if the queue is empty and closed
		platform_mutex_lock(&queue->lock);
		bool eof = queue->eof;
		bool empty = (bufc_len(&queue->head) == 0);
		platform_event_unsignal(&queue->wake);
		platform_mutex_unlock(&queue->lock);

		if (empty && eof) 
			goto done;

		// copy out the available data
		copied += bufq_read_nonblock(queue, buf + copied, size - copied);

		// sleep if we're not done
		if ((size - copied) && !eof) 
			platform_event_wait(&queue->wake);
	}
done:
	return copied;
}

// Sleep until we can read at least one byte, then return whatever's there
ssize_t bufq_read_sleepempty(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);
	size_t copied = 0;

	do {
		platform_mutex_lock(&queue->lock);
		bool eof = queue->eof;
		bool empty = (bufc_len(&queue->head) == 0);
		platform_event_unsignal(&queue->wake);
		platform_mutex_unlock(&queue->lock);

		if (eof) 
			return 0;

		if (empty) 
			platform_event_wait(&queue->wake);

		copied = bufq_read_nonblock(queue, buf, size);
	} while (copied == 0);

	return copied;
}

// discard 'size' bytes off the head of a chain/queue
ssize_t bufc_consume(buf_entry_t **chain, size_t size)
{
	LTRACEF("%p %d\n", chain, size);
	size_t consumed = 0;
	buf_entry_t *e = *chain;

	while (e && (e->len <= (size - consumed))) {
		// consume whole entries
		*chain = e->next;
		consumed += e->len;
		e->_free(e);
		e = *chain;
	}

	if (e && (size - consumed)) {
		// trim entry
		e->start += (size - consumed);
		e->len -= (size - consumed);
		consumed = size;
	}

	while (e && (e->len == 0)) {
		// trailing zero-length buf, consume it to trigger a callback
		*chain = e->next;
		e->_free(e);
		e = *chain;
	}

	return consumed;
}

ssize_t bufq_consume_nonblock(buf_queue_t *queue, size_t size)
{
	LTRACEF("%p %d\n", queue, size);

	platform_mutex_lock(&queue->lock);
	size_t consumed = bufc_consume(&queue->head, size);
	platform_mutex_unlock(&queue->lock);

	return consumed;
}

ssize_t bufq_consume_sleep(buf_queue_t *queue, size_t size)
{
	LTRACEF("%p %d\n", queue, size);

	size_t consumed = 0;
	while (size - consumed) {
		size_t read = 0;
		// check to see if the queue is empty and closed
		platform_mutex_lock(&queue->lock);
		bool eof = queue->eof;
		bool empty = (bufc_len(&queue->head) == 0);
		platform_event_unsignal(&queue->wake);
		platform_mutex_unlock(&queue->lock);

		if (empty && eof) 
			goto done;

		// consume the available data
		read = bufq_consume_nonblock(queue, size - consumed);
		consumed += read;

		LTRACEF("%p, size %d, consumed %d, read %d, bufc_len %d\n", queue, size, consumed, read, bufc_len(&queue->head));

		// sleep if we're not done
		if ((size - consumed) && !eof) platform_event_wait(&queue->wake);
	}

done:
	return consumed;
}

// Read out bytes but don't consume them
ssize_t bufc_peek(buf_entry_t **chain, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", chain, buf, size);
	buf_entry_t *e = *chain;
	size_t copied = 0;

	while (e && (e->len <= (size - copied))) {
		LTRACEF("whole\n");
		// copy a whole buf entry
		if (e->len)
			memcpy(buf + copied, e->buf + e->start, e->len);
		copied += e->len;
		e = e->next;
	}

	if (e && (size - copied)) {
		LTRACEF("partial\n");
		// copy a partial buf entry
		memcpy(buf + copied, e->buf + e->start, (size - copied));
		copied = size;
	}
	return copied;
}

ssize_t bufq_peek_nonblock(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);

	platform_mutex_lock(&queue->lock);
	size_t copied = bufc_peek(&queue->head, buf, size);
	platform_mutex_unlock(&queue->lock);

	return copied;
}

ssize_t bufq_peek_sleep(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);
	size_t copied = 0;

	while (size - copied) {
		// check to see if the queue is empty and closed
		platform_mutex_lock(&queue->lock);
		bool eof = queue->eof;
		bool empty = (bufc_len(&queue->head) == 0);
		platform_event_unsignal(&queue->wake);
		platform_mutex_unlock(&queue->lock);

		if (empty && eof) 
			goto done;

		// copy out the available data
		copied += bufq_peek_nonblock(queue, buf + copied, size - copied);

		// sleep if we're not done
		if ((size - copied) && !eof) platform_event_wait(&queue->wake);
	}
done:
	return copied;
}

ssize_t bufc_peek_onechunk(buf_entry_t **chain, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", chain, buf, size);
	buf_entry_t *e = *chain;
	size_t copied = 0;

	while (e && (e->len == 0)) {
		// skip zero-byte entries
		e = e->next;
	}

	if (e) {
		copied = MIN(size, e->len);
		LTRACEF("copying %d\n", copied);
		memcpy(buf, e->buf + e->start, copied);
	}
	return copied;
}

ssize_t bufq_peek_onechunk_nonblock(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);
	size_t copied = 0;

	platform_mutex_lock(&queue->lock);
	copied = bufc_peek_onechunk(&queue->head, buf, size);
	platform_mutex_unlock(&queue->lock);

	return copied;
}

ssize_t bufq_peek_onechunk_sleep(buf_queue_t *queue, char *buf, size_t size)
{
	LTRACEF("%p %p %d\n", queue, buf, size);
	size_t copied = 0;

	while (!copied) {
		// check to see if the queue is empty and closed
		platform_mutex_lock(&queue->lock);
		bool eof = queue->eof;
		bool empty = (bufc_len(&queue->head) == 0);
		platform_event_unsignal(&queue->wake);
		platform_mutex_unlock(&queue->lock);

		if (empty && eof) 
			goto done;

		// copy out available data
		copied += bufq_peek_onechunk_nonblock(queue, buf, size);

		// sleep if we're not done
		if ((!copied) && !eof) platform_event_wait(&queue->wake);
	}
done:
	return copied;
}

void buf_event_callback(void *cookie)
{
	platform_event_t *event = (platform_event_t *)cookie;
	platform_event_signal(event);
}

void bufq_wait_for_empty(buf_queue_t *queue)
{
	LTRACEF("%p\n", queue);

	platform_mutex_lock(&queue->lock);

	if (bufc_len(&queue->head) != 0) {
		platform_event_t sleep;
		platform_event_create(&sleep);

		bufc_append_callback(&queue->head, buf_event_callback, (void *)&sleep);
		platform_mutex_unlock(&queue->lock);
		platform_event_wait(&sleep);
		platform_event_destroy(&sleep);
	} else {
		platform_mutex_unlock(&queue->lock);
	}
}

void bufq_close(buf_queue_t *queue)
{
	LTRACEF("%p\n", queue);

	platform_mutex_lock(&queue->lock);
	queue->eof = true;
	platform_event_signal(&queue->wake);
	platform_mutex_unlock(&queue->lock);
}

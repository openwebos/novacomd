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

#ifndef __PLATFORM_H
#define __PLATFORM_H

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
/* platform abstraction */

/* portable sockets */
#define SOCKET int
#define INVALID_SOCKET -1

void platform_init(void);
void platform_init_mutex(void);
void platform_init_socket(void);

	/* platform headers */
#if PLATFORM_PTHREADS
#ifndef __USE_UNIX98
#define __USE_UNIX98
#endif
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>

typedef pthread_mutex_t platform_mutex_t;
typedef pthread_rwlock_t platform_rwlock_t;

typedef struct platform_event {
	int signalled;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} platform_event_t;

typedef pthread_t platform_thread_t;

typedef int bool;
#define true 1
#define false 0

typedef struct platform_time {
	struct timeval time;
} platform_time_t;

#endif

#include <sys/time.h>

typedef void *(*thread_routine)(void *);
int platform_create_thread(platform_thread_t *thread, thread_routine routine, void *arg);
void platform_thread_yield(void);
void platform_exit_thread(void *result);
int platform_waitfor_thread(platform_thread_t thread);

int platform_mutex_init(platform_mutex_t *);
void platform_mutex_lock(platform_mutex_t *);
int platform_mutex_lock_timeout(platform_mutex_t *, long int);
int platform_mutex_trylock(platform_mutex_t *);
void platform_mutex_unlock(platform_mutex_t *);
void platform_mutex_destroy(platform_mutex_t *);

int platform_rwlock_init(platform_rwlock_t *);
void platform_rwlock_rdlock(platform_rwlock_t *);
void platform_rwlock_wrlock(platform_rwlock_t *);
void platform_rwlock_unlock(platform_rwlock_t *);
void platform_rwlock_destroy(platform_rwlock_t *);

int platform_event_create(platform_event_t *);
void platform_event_wait(platform_event_t *);
int platform_event_wait_timeout(platform_event_t *, long int); // in msecs
void platform_event_signal(platform_event_t *);
void platform_event_unsignal(platform_event_t *);
void platform_event_destroy(platform_event_t *);

int platform_atomic_add(volatile int *val, int inc);

void platform_get_time(platform_time_t *t);
int platform_get_time_string(char *str, size_t len);
int platform_delta_time_msecs(const platform_time_t *a, const platform_time_t *b);

void platform_abort(void);
int platform_socket_getlasterrno();

#define platform_assert(x) do { if (!(x)) { log_printf(LOG_ERROR, "ASSERT FAILED at (%s:%d): %s\n", __FILE__, __LINE__, #x); platform_abort(); } } while (0)
#define E_SOCKET_WOULDBLOCK EWOULDBLOCK


/* alloc api */
void *platform_alloc(size_t len);
char *platform_strdup(const char *s);
void *platform_realloc(void *p, size_t len);
void *platform_calloc(size_t len);
void platform_free(void *p);
void device_process_setaffinity();
void device_pthread_setaffinity();

/* make it hard for anyone to use the old one */
#define malloc __donotcallmalloc
#define calloc __donotcallcalloc
#define realloc __donotcallrealloc
#define free __donotcallfree

#if PLATFORM_PTHREADS
/* must acquire this before and release after forking in the parent process */
extern platform_mutex_t fork_mutex;
#endif

#endif


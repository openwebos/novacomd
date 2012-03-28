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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif 

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <sched.h>
#include <unistd.h>
#include <assert.h>

#include <novacom.h>
#include <debug.h>
#include <platform.h>

#define STACK_SIZE (64*1024)

platform_mutex_t fork_mutex;

static platform_mutex_t atomic_mutex;

void platform_init(void)
{
	srand(time(NULL));

	platform_mutex_init(&atomic_mutex);
	platform_mutex_init(&fork_mutex);
}

int platform_create_thread(platform_thread_t *_thread, thread_routine routine, void *arg)
{
	int rc;
	pthread_t thread;
	pthread_attr_t attr;

	pthread_attr_init(&attr);

	rc = pthread_attr_setstacksize(&attr, STACK_SIZE);
	platform_assert(rc == 0);

	rc = pthread_create(&thread, &attr, routine, arg);
	platform_assert(rc == 0);
	
	pthread_attr_destroy(&attr);

	pthread_detach(thread);

	if (_thread)
		*_thread = thread;

	return 0;
}

void platform_thread_yield(void)
{
	sched_yield();
}

int platform_waitfor_thread(platform_thread_t thread)
{
	// XXX currently broken, since all threads had been previously detached
	platform_assert(0);

	if (pthread_join(thread, NULL) == 0)
		return 0;
	return -1;
}

void platform_exit_thread(void *result)
{
	pthread_exit(result);
}

int platform_mutex_init(platform_mutex_t *m)
{
	pthread_mutexattr_t attr;

	if (!m) {
		log_printf(LOG_ERROR, "%s:%d -- null pointer\n", __FUNCTION__, __LINE__);
		platform_assert(m);
		return -1;
	}
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

	pthread_mutex_init(m, &attr);
	return 0;
}

void platform_mutex_lock(platform_mutex_t *m)
{
	if (!m) {
		log_printf(LOG_ERROR, "%s:%d -- null pointer\n", __FUNCTION__, __LINE__);
		platform_assert(m);
		return;
	}
	pthread_mutex_lock(m);
}

#if 0
// not present on OS X
int platform_mutex_lock_timeout(platform_mutex_t *m, long int us)
{
	struct timespec timeout;
	struct timeval currenttime;
	long long int ns_t;

	// This doesn't make sense with negative us values.
	// Neither does the rest of the funtion.
	gettimeofday(&currenttime, NULL);
	ns_t = (currenttime.tv_usec + us)*1000;
	timeout.tv_nsec = ns_t%1000000000;
	timeout.tv_sec = currenttime.tv_sec + (ns_t - timeout.tv_nsec)/1000000000;

	return pthread_mutex_timedlock(m, &timeout);
}
#endif

void platform_mutex_unlock(platform_mutex_t *m)
{
	if (!m) {
		log_printf(LOG_ERROR, "%s:%d -- null pointer\n", __FUNCTION__, __LINE__);
		platform_assert(m);
		return;
	}
	pthread_mutex_unlock(m);
}

int platform_mutex_trylock(platform_mutex_t *m)
{
	if (!m) {
		log_printf(LOG_ERROR, "%s:%d -- null pointer\n", __FUNCTION__, __LINE__);
		platform_assert(m);
		return -1;
	}
	return pthread_mutex_trylock(m);
}

void platform_mutex_destroy(platform_mutex_t *m)
{
	if (!m) {
		log_printf(LOG_ERROR, "%s:%d -- null pointer\n", __FUNCTION__, __LINE__);
		platform_assert(m);
		return ;
	}
	pthread_mutex_destroy(m);
}

int platform_rwlock_init(platform_rwlock_t *rw)
{
	return pthread_rwlock_init(rw, NULL);
}

void platform_rwlock_rdlock(platform_rwlock_t *rw)
{
	pthread_rwlock_rdlock(rw);
}

void platform_rwlock_wrlock(platform_rwlock_t *rw)
{
	pthread_rwlock_wrlock(rw);
}

void platform_rwlock_unlock(platform_rwlock_t *rw)
{
	pthread_rwlock_unlock(rw);
}

void platform_rwlock_destroy(platform_rwlock_t *rw)
{
	pthread_rwlock_destroy(rw);
}

int platform_event_create(platform_event_t *e)
{
	e->signalled = 0;

	pthread_mutex_init(&e->mutex, NULL);
	pthread_cond_init(&e->cond, NULL);

	return 0;
}

void platform_event_wait(platform_event_t *e)
{
	pthread_mutex_lock(&e->mutex);

	if (!e->signalled) {
		pthread_cond_wait(&e->cond, &e->mutex);
	}

	pthread_mutex_unlock(&e->mutex);
}

int platform_event_wait_timeout(platform_event_t *e, long int ms)
{
	struct timespec timeout;
	struct timeval currenttime;
	long long int ns_t;
	int r = 0;

	// This doesn't make sense with negative ms values.
	// Neither does the rest of the funtion.
	gettimeofday(&currenttime, NULL);
	ns_t = currenttime.tv_usec * 1000 + ms * 1000000LL;
	timeout.tv_nsec = ns_t % 1000000000LL;
	timeout.tv_sec = currenttime.tv_sec + (ns_t - timeout.tv_nsec)/1000000000LL;

	pthread_mutex_lock(&e->mutex);

	if (!e->signalled) {
		r = pthread_cond_timedwait(&e->cond, &e->mutex, &timeout);
	}

	pthread_mutex_unlock(&e->mutex);
	return r;
}

void platform_event_signal(platform_event_t *e)
{
	if (!e) { //when novacomd is die in device, this could be null.
		//TRACEL(LOG_ALWAYS, "%s: received a NULL event pointer\n", __FUNCTION__);
		return ;
	}
	pthread_mutex_lock(&e->mutex);
	e->signalled = 1;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
}

void platform_event_unsignal(platform_event_t *e)
{
	if (!e) { //in case this is null. 
		return;
	}

	pthread_mutex_lock(&e->mutex);
	e->signalled = 0;
	pthread_mutex_unlock(&e->mutex);
}

void platform_event_destroy(platform_event_t *e)
{
	if (!e) { //in case this is null. 
		return;
	}
	pthread_mutex_destroy(&e->mutex);
	pthread_cond_destroy(&e->cond);
}

int platform_atomic_add(volatile int *val, int inc)
{
	// XXX cheezy atomic add, do for reals
	platform_mutex_lock(&atomic_mutex);
	int oldval = *val;
	*val += inc;
	platform_mutex_unlock(&atomic_mutex);

	return oldval;
}

void platform_get_time(platform_time_t *t)
{
	gettimeofday(&t->time, NULL);
}

int platform_delta_time_msecs(const platform_time_t *a, const platform_time_t *b)
{
	uint64_t atime, btime;

	atime = a->time.tv_sec * 1000000 + a->time.tv_usec;
	btime = b->time.tv_sec * 1000000 + b->time.tv_usec;

	return (btime - atime) / 1000;
}

int platform_get_time_string(char *str, size_t len)
{
	time_t t = time(NULL);
	struct tm tm;
	localtime_r(&t, &tm);

	return snprintf(str, len, "[%d/%d/%d %d:%02d:%02d] ", 
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void platform_abort(void)
{
	/* dont call abort, it doesn't work */
	*((volatile unsigned int *)0) = 99;
	abort();
}

/* allocator api */
#undef malloc
#undef realloc
#undef calloc
#undef free

#if DEVICE
#define PLATFORM_HEAP_LOCK platform_mutex_lock(&fork_mutex)
#define PLATFORM_HEAP_UNLOCK platform_mutex_unlock(&fork_mutex)
#else
#define PLATFORM_HEAP_LOCK do { } while (0)
#define PLATFORM_HEAP_UNLOCK do { } while (0)
#endif

void *platform_alloc(size_t len)
{
	void *ptr;

	PLATFORM_HEAP_LOCK;
	ptr = malloc(len);
	PLATFORM_HEAP_UNLOCK;
	return ptr;
}

char *platform_strdup(const char *s)
{
	char *ptr;

	PLATFORM_HEAP_LOCK;
	ptr = strdup(s);
	PLATFORM_HEAP_UNLOCK;
	return ptr;
}

void *platform_realloc(void *p, size_t len)
{
	void *ptr;

	PLATFORM_HEAP_LOCK;
	ptr = realloc(p, len);
	PLATFORM_HEAP_UNLOCK;
	return ptr;
}

void *platform_calloc(size_t len)
{
	void *ptr;

	PLATFORM_HEAP_LOCK;
	ptr = calloc(1, len);
	PLATFORM_HEAP_UNLOCK;
	return ptr;
}

void platform_free(void *p)
{
	PLATFORM_HEAP_LOCK;
	if(p) {
		free(p);
		p = NULL;
	}
	PLATFORM_HEAP_UNLOCK;
}

int platform_socket_getlasterrno()
{
	return errno;
}

#define __SCHED_GCC_VERSION  40300
#define __COMPILER_GCC_VERSION  (__GNUC__*10000 + __GNUC_MINOR__*100)

#if __COMPILER_GCC_VERSION < __SCHED_GCC_VERSION
#pragma warning gcc version is lower than __SCHED_GCC_VERSION
#endif 

void device_process_setaffinity()
{
#if DEVICE && (__COMPILER_GCC_VERSION >= __SCHED_GCC_VERSION)
	uint32_t cpu, num_cpus, cpumask = 0;	
	int ret;

	if (!g_cpuaffinity) 
		return;

	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
	cpu = sched_getcpu();
	cpumask = 1 << cpu;
	ret = sched_setaffinity(getpid(), sizeof(cpumask), (cpu_set_t*)&cpumask);
	if (ret) {
		LOG_PRINTF("new: thread=%d, cpumask=0x%08x, num_cpus=%d, ret=%d, errno=%d\n", pthread_self(), cpumask, num_cpus, ret, errno);
	}
	sched_getaffinity(getpid(), sizeof(cpumask), (cpu_set_t*)&cpumask);
	if (cpumask > 1 || ret) {
		LOG_PRINTF("new: thread=%d, cpumask=0x%08x, num_cpus=%d, ret=%d, errno=%d\n", pthread_self(), cpumask, num_cpus, ret, errno);
	}
#endif

}

void device_pthread_setaffinity() 
{
#if DEVICE && (__COMPILER_GCC_VERSION >= __SCHED_GCC_VERSION)
	uint32_t cpu, num_cpus, cpumask;	
	int ret;

	if (!g_cpuaffinity) 
		return;

	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
	cpu = sched_getcpu();
	cpumask = 1 << cpu;
	ret = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), (cpu_set_t*)&cpumask);
	if (ret) {
		LOG_PRINTF("set: thread=%d, cpumask=0x%08x, num_cpus=%d, ret=%d,errno=%d\n", pthread_self(), cpumask, num_cpus, ret, errno);
	}
	ret = pthread_getaffinity_np(pthread_self(), sizeof(cpumask), (cpu_set_t*)&cpumask);
	if (cpumask > 1 || ret ) {
		LOG_PRINTF("new: thread=%d, cpumask=0x%08x, num_cpus=%d, ret=%d,errno=%d\n", pthread_self(), cpumask, num_cpus, ret, errno);
	}
	
#endif

}


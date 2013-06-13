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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <syslog.h>
#endif
#include <errno.h>

#include <debug.h>
#include <log.h>

static unsigned int console_logmask = LOG_ALWAYS | LOG_ERROR;
static unsigned int syslog_logmask = LOG_ALWAYS | LOG_ERROR | LOG_TRACE;

static unsigned int socket_logmask = LOG_ALWAYS | LOG_ERROR | LOG_TRACE | LOG_SPEW | LOG_MUXTRACE | LOG_LLTRACE;
static unsigned int file_logmask = LOG_ALWAYS | LOG_ERROR | LOG_TRACE | LOG_SPEW | LOG_MUXTRACE | LOG_LLTRACE;

#define MASTER_MASK (console_logmask | syslog_logmask | ((log_socket != (INVALID_SOCKET)) ? socket_logmask : 0) | ((log_file) ? file_logmask : 0) )

// XXX hack
SOCKET log_socket = INVALID_SOCKET;
FILE* log_file = NULL;

static int is_ubuntu_mac = 0;

void log_init()
{
        is_ubuntu_mac = 1;
}

void log_mask(unsigned int output, unsigned int mask)
{
	switch (output) {
		case LOG_OUTPUT_CONSOLE:
			console_logmask |= mask;
			break;
		case LOG_OUTPUT_SYSLOG:
			syslog_logmask |= mask;
			break;
		case LOG_OUTPUT_SOCKET:
			socket_logmask |= mask;
			break;
	}
}

void log_unmask(unsigned int output, unsigned int mask)
{
	switch (output) {
		case LOG_OUTPUT_CONSOLE:
			console_logmask &= ~mask;
			break;
		case LOG_OUTPUT_SYSLOG:
			syslog_logmask &= ~mask;
			break;
		case LOG_OUTPUT_SOCKET:
			socket_logmask &= ~mask;
			break;
	}
}

int get_log_mask(unsigned int output)
{
	switch (output) {
		case LOG_OUTPUT_CONSOLE:
			return console_logmask;
		case LOG_OUTPUT_SYSLOG:
			return syslog_logmask;
		case LOG_OUTPUT_SOCKET:
			return socket_logmask;
		default:
			return 0;
	}
}

	
int log_would_log(unsigned int mask)
{
	if ((mask & MASTER_MASK) == 0)
		return 0;
	else
		return 1;
}

void log_printf(unsigned int mask, const char *fmt, ...)
{
	int  timestrlen = 0;
	char msg[256];
	int  len = 0;

	if ((mask & MASTER_MASK) == 0)
		return;

	/* clear strings */
	msg[0] = 0;

	/* timestamp */
	if ((mask & LOG_NOTIMESTAMP) == 0) {
		timestrlen = platform_get_time_string(msg, 64);
		if(timestrlen < 0) {
			return;
		}
	}

	/* message */
	va_list ap;
	va_start(ap, fmt);
	len = vsnprintf(msg + timestrlen, sizeof(msg) - timestrlen - 2, fmt, ap);
	va_end(ap);
	if (-1 == len) {
		return;
	}

	/* track len */
	len += timestrlen; /* add timestring */
	msg[sizeof(msg)-1] = 0;

#undef fprintf
	if (mask & console_logmask) {
		FILE *outfp;

		if (mask & LOG_ERROR)
			outfp = stderr;
		else
			outfp = stdout;
		fprintf(outfp, "%s", msg);
	}
	if (mask & syslog_logmask) {
#if DEVICE 
		syslog(LOG_INFO, "{%s}: (%s) %s", "novacomd", BUILDVERSION, msg + timestrlen);  //skip to print timestamp in msg string.

#elif defined(__linux__)
		if (is_ubuntu_mac) {
                        syslog(LOG_ALWAYS, "%s", msg + timestrlen); //skip to print timestamp
                }
#endif
	}
	if (mask & socket_logmask) {
		// dump to any connected log socket listeners
		if (log_socket != INVALID_SOCKET) {
			int rc = send(log_socket, msg, len, MSG_DONTWAIT);
			if (rc < 0 && errno != EAGAIN) {
				shutdown(log_socket, SHUT_RDWR);
				close(log_socket);
				log_socket = INVALID_SOCKET;
			}
		}
	}
		
#if defined(TONS_OF_LOGGING) && TONS_OF_LOGGING
	if(mask & file_logmask) {
		if(log_file == NULL) {
			log_file = fopen(LOG_PATH"novacomd.log","w+");
		}
		fprintf(log_file, "%s", msg);
	}
#endif
}

void log_add_socket(SOCKET s)
{
	if (log_socket != INVALID_SOCKET) {
		SOCKET temp = log_socket;
		log_socket = INVALID_SOCKET;
		shutdown(temp, SHUT_RDWR);
		close(temp);
	}
	log_socket = s;
}

/*
 * hexdump8
 * @param[ptr]	pointer to data
 * @param[len]	data length
 * @ret none
 */
void hexdump8(const void *ptr, size_t len)
{
	unsigned long address = (unsigned long)ptr;
	size_t count;
	size_t i;
#undef fprintf
	for (count = 0 ; count < len; count += 16) {
		fprintf(stderr, "0x%08lx: ", address);
		for (i=0; i < MIN(16, len - count); i++) {
			fprintf(stderr, "0x%02hhx ", (*(const unsigned char *)(address + i)));
		}
		fprintf(stderr, "\n");
		address += 16;
	}
	fflush(stderr);
}


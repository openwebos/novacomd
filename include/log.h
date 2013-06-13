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

#ifndef __LOG_H
#define __LOG_H

#define LOG_ALWAYS   (1<<0)
#define LOG_ERROR    (1<<1)
#define LOG_TRACE    (1<<2)
#define LOG_SPEW     (1<<3)
#define LOG_LLTRACE  (1<<4)
#define LOG_MUXTRACE (1<<5)
#define LOG_NOTIMESTAMP (1<<31)

enum {
	LOG_OUTPUT_CONSOLE = 1,
	LOG_OUTPUT_SYSLOG,
	LOG_OUTPUT_SOCKET,
};

void log_init();
void log_printf(unsigned int mask, const char *fmt, ...);

int log_would_log(unsigned int mask);

void log_mask(unsigned int output, unsigned int mask);
void log_unmask(unsigned int output, unsigned int mask);
int get_log_mask(unsigned int output);

void log_add_socket(SOCKET s);

void hexdump8(const void *ptr, size_t len);

/* make printf and fprintf fail to compile */
#define printf __donotcallprintf
#define fprintf __donotcallfprintf

#endif


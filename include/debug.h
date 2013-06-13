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

#ifndef __DEBUG_H
#define __DEBUG_H

#include <assert.h>
#include <platform.h>
#include <stdio.h>
#include <log.h>


/* trace routines */
#define TRACE_ENTRY         log_printf(LOG_TRACE, "%s: entry\n", __PRETTY_FUNCTION__)
#define TRACE_EXIT          log_printf(LOG_TRACE, "%s: exit\n", __PRETTY_FUNCTION__)
#define TRACE_ENTRY_OBJ     log_printf(LOG_TRACE, "%s: entry obj %p\n", __PRETTY_FUNCTION__, this)
#define TRACE_EXIT_OBJ      log_printf(LOG_TRACE, "%s: exit obj %p\n", __PRETTY_FUNCTION__, this)
#define TRACE               log_printf(LOG_TRACE, "%s:%d\n", __PRETTY_FUNCTION__, __LINE__)
#define TRACEF(format, ...) log_printf(LOG_TRACE, "%s:%d: "format, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#define TRACEL(LEVEL,...)   log_printf(LEVEL, __VA_ARGS__)

/* trace routines with private/local settings (LOCAL_TRACE subset of private routnes)*/
#define PTRACE_ENTRY(PRIVATE_TRACE)      do { if (PRIVATE_TRACE) { TRACE_ENTRY; } } while (0)
#define PTRACE_EXIT(PRIVATE_TRACE)       do { if (PRIVATE_TRACE) { TRACE_EXIT;  } } while (0)
#define PTRACE(PRIVATE_TRACE)            do { if (PRIVATE_TRACE) { TRACE;       } } while (0)
#define PTRACEF(PRIVATE_TRACE,...)       do { if (PRIVATE_TRACE) {\
                                            log_printf(LOG_TRACE, "%s:%d: ", __PRETTY_FUNCTION__, __LINE__);\
                                            log_printf(LOG_TRACE | LOG_NOTIMESTAMP, __VA_ARGS__);   } } while (0)
#define PTRACEL(PRIVATE_TRACE,LEVEL,...) do { if (PRIVATE_TRACE) { log_printf(LEVEL,##__VA_ARGS__); } } while (0)

/* trace routines that work if LOCAL_TRACE is set */
#define LTRACE_ENTRY       PTRACE_ENTRY(LOCAL_TRACE)
#define LTRACE_EXIT        PTRACE_EXIT(LOCAL_TRACE)
#define LTRACE             PTRACE(LOCAL_TRACE)
#define LTRACEF(...)       PTRACEF(LOCAL_TRACE,__VA_ARGS__)
#define LTRACEL(LEVEL,...) PTRACEL(LOCAL_TRACE,LEVEL,__VA_ARGS__)

#if DEVICE
#define LOG_PRINTF(format, ...) log_printf(LOG_TRACE, "%s:%d: "format, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#else 
#define LOG_PRINTF(format, ...) log_printf(LOG_ALWAYS, "%s:%d: "format, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#endif

#define ASSERT(x) do { if (!(x)) { log_printf(LOG_ERROR, "ASSERT FAILED at (%s:%d): %s\n", __FILE__, __LINE__, #x); platform_abort(); } } while (0)

#endif


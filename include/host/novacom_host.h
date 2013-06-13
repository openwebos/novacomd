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

#ifndef __LIB_NOVACOM_HOST_H
#define __LIB_NOVACOM_HOST_H

#include <sys/types.h>
#include <stdint.h>

#include "platform.h"
#include <buf_queue.h>

/* process command and provides command url */
int novacom_service_command(SOCKET cmdsocket, const char *cmd, novacom_command_url_t **_url);

/* process command url */
int novacom_service_url(device_handle_t dev, const char *ssid, SOCKET cmdsocket, uint32_t channel, novacom_command_url_t *url);

/* process reply */
int novacom_service_reply(const char *devid, novacom_command_url_t *url, const void *buf, size_t len);

/* store token */
int tokenstorage_store(const char *file, void *buf, size_t len);

/* remove token */
int tokenstorage_remove(const char *file);

/* read token */
int tokenstorage_read(const char *file, void *buf, size_t len);

/* read token + calc hash based on ssid */
int tokenstorage_readhash(const char *file, const char *ssid, void *hash, size_t len);

#endif

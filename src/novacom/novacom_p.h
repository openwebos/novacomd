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

#ifndef __NOVACOM_P_H
#define __NOVACOM_P_H

#include <novacom.h>

#define NOVACOMD_DATATOKEN_ID		"id:"
#define NOVACOMD_DATATOKEN_MTU		"mtu:"
#define NOVACOMD_DATATOKEN_MODE		"mode:"
#define NOVACOMD_DATATOKEN_SESSION	"sn:"

/* multiplexing engine */
int novacom_mux_init(void);

/* parse command */
int parse_command(const char *_string, size_t len, struct novacom_command_url **_url);

/* standard device commands */
int novacom_setup_command(device_handle_t device_handle, uint32_t chan);

/* service control device commands */
int novacom_setup_service_command(device_handle_t device_handle, uint32_t chan);

#endif



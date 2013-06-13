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

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#define TRANSPORT_RECOVERY_TIMEOUT	(5)
#define TRANSPORT_MAX_MTU		(16384)
#define TRANSPORT_MAX_USBIO_RETRY_TIMEOUT	(500)
#define TRANSPORT_USBIO_RETRY_TIMEOUT	(100)

/*
 * recovery token
 */
typedef struct transport_recovery_token {
	void *token;		/* recovery token */
	int len;			/* recovery token length */
	void *user_data;	/* transport private data */
	char nduid[41];		/* device nduid */
} transport_recovery_token_t;


/* abstraction of the novacom transport mechanism */

int transport_init(void);
int transport_start(void);
int transport_stop(void);

#endif


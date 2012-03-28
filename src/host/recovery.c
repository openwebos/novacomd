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
#include <stdio.h>
#include <string.h>
#include <debug.h>
#include <unistd.h>
#include <stdint.h>
#include <platform.h>
#include <novacom.h>
#include <transport_usb.h>
#include <errno.h>
#include <log.h>

#include <sys/queue.h>

/* debug */
#define LOCAL_TRACE  0
#define USB_RECOVERY 0

typedef struct recovery_entry_s {
	transport_recovery_token_t	*t_token;		/* transport recovery token */
	int timeout;								/* timout value */

	TAILQ_ENTRY(recovery_entry_s) entries;		/* holds pointers to prev, next entries */
} recovery_entry_t;

/* list of recovery tokens */
TAILQ_HEAD(recovery_queue_s, recovery_entry_s)  t_recovery_queue;
static platform_mutex_t recovery_lock;


/*
 * usbrecords_init
 * init records
 * @ret 0 - success, -1 error
 */
int usbrecords_init( void )
{
	TAILQ_INIT(&t_recovery_queue);	/* initialize records queue */
	platform_mutex_init(&recovery_lock); /* initialize mutex */
	return 0;
}

/*
 * usbrecords_add
 * save recovery records in array
 * @param[t_token]	recovery token
 * @ret 0 - success, -1 error
 */
int usbrecords_add(transport_recovery_token_t *t_token)
{
	int rc = -1;
	recovery_entry_t *item = (recovery_entry_t *)platform_calloc(sizeof(recovery_entry_t));

	if(item) {
		LTRACEF("* add token data(%p)\n", t_token->token);
		item->t_token = t_token;
		item->timeout = g_recovery_timeout;
		platform_mutex_lock(&recovery_lock);
		TAILQ_INSERT_TAIL(&t_recovery_queue, item, entries);
		platform_mutex_unlock(&recovery_lock);
		rc = 0;
	}

	return rc;
}

/*
 * usbrecords_find
 * check if we can recover device based on recovery queue
 * @param[t_token] recovery token to compare against
 * @ret -1 unable to recover, 0 success (token->user_data has handle) 
 */
int usbrecords_find(transport_recovery_token_t *t_token)
{
	int rc = -1;
	recovery_entry_t *item;
	recovery_entry_t *tmp_item;

	platform_mutex_lock(&recovery_lock);
	/* check all entries */
	for (item = TAILQ_FIRST(&t_recovery_queue); item != NULL; item = tmp_item) {
		transport_recovery_token_t *token = item->t_token;
		tmp_item = TAILQ_NEXT(item, entries);
		if (token->len == t_token->len) {

			if( 0 == memcmp(token->token, t_token->token, token->len) ) {
				TRACEF("Matches, nduid(%s)\n", token->nduid);
				/* Remove the item from queue. */
				TAILQ_REMOVE(&t_recovery_queue, item, entries);
				/* restore handle */
				t_token->user_data = token->user_data;
				/* Free the item as we don't need it anymore. */
				platform_free(item->t_token);
				platform_free(item);
				/* success */
				rc = 0;
				break;
			}
		}
	}
	platform_mutex_unlock(&recovery_lock);

	return rc;
}


/*
 * usbrecords_update
 * @param[elapsed]	elapsed time
 * @ret 0 - success, -1 error
 */
int usbrecords_update(int elapsed)
{
	recovery_entry_t *item;
	recovery_entry_t *tmp_item;

	LTRACEF("Update records\n");

	platform_mutex_lock(&recovery_lock);
	/* check all entries */
	for (item = TAILQ_FIRST(&t_recovery_queue); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		/* update remaining recovery time */
		item->timeout -= elapsed;
		PTRACEF(USB_RECOVERY, "Check entry(%p): timeout %d\n", item, item->timeout);
		/* expired? */
		if(item->timeout < 0) {
			TRACEF("expired timeout::destroy record\n");
			/* destroy handle */
			novacom_usbll_destroy((novacom_usbll_handle_t)item->t_token->user_data);
			/* Remove the item from queue. */
			TAILQ_REMOVE(&t_recovery_queue, item, entries);
			/* Free the item as we don't need it anymore. */
			platform_free(item->t_token);
			platform_free(item);
		}
	}

	platform_mutex_unlock(&recovery_lock);

	return 0;
}

/*
 * usbrecords_remove
 * @param[nduid] device nduid
 * @ret 0 - success, -1 error
 */
int usbrecords_remove(char *nduid)
{
	recovery_entry_t *item;
	recovery_entry_t *tmp_item;

	LTRACEF("Update records\n");

	platform_mutex_lock(&recovery_lock);
	/* check all entries */
	for (item = TAILQ_FIRST(&t_recovery_queue); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		if(0 == strncmp(item->t_token->nduid, nduid, sizeof(item->t_token->nduid)) ) {
TRACEF("explicit remove::nduid(%s)\n", nduid);
			/* destroy handle */
			novacom_usbll_destroy((novacom_usbll_handle_t)item->t_token->user_data);
			/* Remove the item from queue. */
			TAILQ_REMOVE(&t_recovery_queue, item, entries);
			/* Free the item as we don't need it anymore. */
			platform_free(item->t_token);
			platform_free(item);
		}
	}

	platform_mutex_unlock(&recovery_lock);

	return 0;
}


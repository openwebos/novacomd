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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "debug.h"
#include "platform.h"
#include "novacom.h"
#include "buffer.h"
#include "lib/cksum.h"
#include "device/auth.h"
#include "host/novacom_host.h"

//
#define LOCAL_TRACE    0
#define TRACE_COMMANDS 0

extern void socketcmd_write_callback(device_handle_t device_handle, uint32_t channel, int err, void *cookie);

/*
 * @brief reports device list
 * @param sc socket
 * @param channel
 * @param url command url
 * @param dev device handle
 * @param ssid session id
 * @ret -1 error, 0 success
 */
int novacom_hostcmd_list(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *dev, const char *ssid)
{
	dump_device_list(sc);
	return 1;
}


/*
 * @brief handles device login
 * @param sc socket
 * @param channel
 * @param url command url
 * @param dev device handle
 * @param ssid session id
 * @param method 0 - password, 1 token
 * @ret -1 error, 0 success
 */
static int novacom_hostcmd_login(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *_dev, const char *ssid, int method)
{
	int rc=-1;
	buffer_t *b = buffer_new(100);
	device_handle_t dev = (device_handle_t)_dev;

	/* buffer */
	if (!b)
		goto done;

	/* expecting at least one parameter */
	if (url->argcount < 1) {
		goto done;
	}

	/* message type(auth.h) */
	rc = buffer_putbyte(b, SSH_MSG_USERAUTH_REQUEST);
	if (rc)
		goto done;

	/* version info */
	rc = buffer_putbyte(b, 0);
	if (rc)
		goto done;

	/* method info: 0 password, 1 token */
	if (method)
		rc = buffer_putstring(b, (const unsigned char *)AUTH_METHOD_TOKEN, AUTH_METHOD_TOKEN_LEN);
	else
		rc = buffer_putstring(b, (const unsigned char *)AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN);
	if (rc)
		goto done;

	/* hash info */
	rc = buffer_putstring(b, (const unsigned char *)url->args[0], strlen(url->args[0]));
	if (rc)
		goto done;

	LTRACEF("channel %d, hash %s\n", channel, url->args[0]);
	rc = novacom_write_channel_async(dev, channel, b->data, b->pos, ASYNC_FLAG_COPY, (novacom_async_callback)&socketcmd_write_callback, (void *)url);

done:
	buffer_free(b);
	return rc;
}

/*
 * @brief handles device login, password based
 */
static int novacom_hostcmd_devlogin(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *_dev, const char *ssid)
{
	return novacom_hostcmd_login(sc, channel, url, _dev, ssid, 0);
}

/*
 * @brief handles device login, token based
 */
static int novacom_hostcmd_devlogint(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *_dev, const char *ssid)
{
	return novacom_hostcmd_login(sc, channel, url, _dev, ssid, 1);
}

/*
 * @brief reports device list
 * @param sc socket
 * @param channel
 * @param url command url
 * @param dev device handle
 * @param ssid session id
 * @ret -1 error, 0 success
 */
static int novacom_hostcmd_devlogout(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *_dev, const char *ssid)
{
	int rc=-1;
	buffer_t *b = buffer_new(100);
	device_handle_t dev = (device_handle_t)_dev;

	/* buffer */
	if (!b)
		goto done;

	/* message type(auth.h) */
	rc = buffer_putbyte(b, SSH_MSG_DISCONNECT);
	if (rc)
		goto done;

	/* version info */
	rc = buffer_putbyte(b, 0);
	if (rc)
		goto done;

	rc = novacom_write_channel_async(dev, channel, b->data, b->pos, ASYNC_FLAG_COPY, (novacom_async_callback)&socketcmd_write_callback, (void *)url);

done:
	buffer_free(b);
	return rc;
}

/*
 * @brief reports device list
 * @param sc socket
 * @param channel
 * @param url command url
 * @param dev device handle
 * @param ssid session id
 * @ret -1 error, 0 success
 */
static int novacom_hostcmd_devadd(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *_dev, const char *ssid)
{
	int rc=-1;
	buffer_t *b = buffer_new(100);
	device_handle_t dev = (device_handle_t)_dev;

	/* buffer */
	if (!b)
		goto done;

	/* expecting at least one parameter */
	if (url->argcount < 1) {
		goto done;
	}

	/* message type(auth.h) */
	rc = buffer_putbyte(b, SSH_MSG_USERAUTH_TOKENREQUEST_ADD);
	if (rc)
		goto done;

	/* version info */
	rc = buffer_putbyte(b, 0);
	if (rc)
		goto done;

	/* password info */
	rc = buffer_putstring(b, (const unsigned char *)url->args[0], strlen(url->args[0]));
	if (rc)
		goto done;

	rc = novacom_write_channel_async(dev, channel, b->data, b->pos, ASYNC_FLAG_COPY, (novacom_async_callback)&socketcmd_write_callback, (void *)url);

done:
	buffer_free(b);
	return rc;
}

/*
 * @brief reports device list
 * @param sc socket
 * @param channel
 * @param url command url
 * @param dev device handle
 * @param ssid session id
 * @ret -1 error, 0 success
 */
int novacom_hostcmd_devremove(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *_dev, const char *ssid)
{
	int rc=-1;
	buffer_t *b = buffer_new(100); /* 44 + 44 + 2 */
	device_handle_t dev = (device_handle_t)_dev;
	char *file = NULL;
	char hash[SHA1_HASH_STRSIZE];

	if ( strlen(ssid) != NOVACOM_AUTHSESSION_LEN) {
		LTRACEF("invalid ssid length(%d)\n", strlen(ssid));
		goto done;
	}
	/* buffer */
	if (!b)
		goto done;

	/* expecting at least one parameter */
	if (url->argcount < 1) {
		goto done;
	}

	/* message type(auth.h) */
	rc = buffer_putbyte(b, SSH_MSG_USERAUTH_TOKENREQUEST_RM);
	if (rc)
		goto done;

	/* version info */
	rc = buffer_putbyte(b, 0);
	if (rc)
		goto done;

	/* password info */
	rc = buffer_putstring(b, (const unsigned char *)url->args[0], strlen(url->args[0]));
	if (rc)
		goto done;

	/* token hash info */
	file = novacom_rnduid(dev);
	if (!file)
		goto done;
	rc = tokenstorage_readhash(file, ssid, hash, sizeof(hash));
	if (-1 == rc) {
		LTRACEF("unable to get hashed token\n");
		goto done;
	}

	/* pack it */
	rc = buffer_putstring(b, (unsigned char *)hash, sizeof(hash));
	if (rc)
		goto done;

	rc = novacom_write_channel_async(dev, channel, b->data, b->pos, ASYNC_FLAG_COPY, (novacom_async_callback)&socketcmd_write_callback, (void *)url);

done:
	LTRACEF("rc(%d)\n", rc);
	platform_free(file);
	buffer_free(b);
	return rc;
}

// === Command stuff here ===
static struct {
	char* verb;
	char* scheme;
	int remote; /* requires communication to device */
	int (*spawn)(SOCKET sc, uint32_t channel, novacom_command_url_t *url, void *dev, const char *ssid);
} iohandlers[] =
{
	{ "list",   "host", 0, novacom_hostcmd_list      },
	{ "login",   "dev", 1, novacom_hostcmd_devlogin  },
	{ "logout",  "dev", 1, novacom_hostcmd_devlogout },
	{ "logint",  "dev", 1, novacom_hostcmd_devlogint },
	{ "add",     "dev", 1, novacom_hostcmd_devadd    },
	{ "remove",  "dev", 1, novacom_hostcmd_devremove },
	{ NULL, NULL, 0, NULL }
};

/*
 * @brief: service command to novacomd
 * @ret
 * -1 invalid command
 *  0 placed in queue
 *  1 command complete
 *  url parsed command (when ret==0)
 */
int novacom_service_command(SOCKET cmdsocket, const char *cmd, novacom_command_url_t **_url)
{
	int i=0;
	int rc=-1; /* error by default */
	bool handled = false;
	struct novacom_command_url *url = NULL;

	/* check */
	if (!_url) {
		goto done; /* return error */
	}

	// parse the command
	if (parse_command(cmd, strlen(cmd), &url) < 0) {
		rc = -1;
		goto done;
	}
	PTRACEF(TRACE_COMMANDS, "command verb '%s', scheme '%s'\n", url->verb, url->scheme);

	// check command handlers
	i = 0;
	while (iohandlers[i].verb != NULL) {
		if ((strcasecmp(url->verb, iohandlers[i].verb) == 0) &&
				strcasecmp(url->scheme, iohandlers[i].scheme) == 0) {
			handled = true;
			break;
		}
		i++;
	}

	if(!handled) {
		goto done;
	}

	/* some processing involved? */
	if(!iohandlers[i].remote) {
		rc = iohandlers[i].spawn(cmdsocket, 0, url, NULL, NULL);
		if (!rc)
			rc = 1; /*done with command */
		PTRACEF(TRACE_COMMANDS, "host command: done...\n");
	} else {
		/* register command with device commands queue */
		rc = 0;
		*_url = url;
		PTRACEF(TRACE_COMMANDS, "device specific command: postponed...\n");
	}

done:
	/* free _url only when we have error/completed cmd */
	if (rc && url) {
		free_url(url);
	}

	PTRACEF(TRACE_COMMANDS, "return rc(%d)\n", rc);
	return rc;
}

/*
 * @brief: service url
 * @ret
 * -1 invalid command
 *  0 placed in queue
 *  1 command complete
 */
int novacom_service_url(device_handle_t dev, const char *ssid, SOCKET cmdsocket, uint32_t channel, novacom_command_url_t *url)
{
	bool handled=false;
	int i=0;
	int rc=-1;
	while (iohandlers[i].verb != NULL) {
		if ((strcasecmp(url->verb, iohandlers[i].verb) == 0) &&
			strcasecmp(url->scheme, iohandlers[i].scheme) == 0) {
			handled = true;
			break;
		}
		i++;
	}
	if (handled) {
		PTRACEF(TRACE_COMMANDS, "command %s\n", url->verb);
		rc = iohandlers[i].spawn(cmdsocket, channel, url, dev, ssid);
	}
	return rc;
}

/*
 * @brief: service reply
 * @ret
 * -1 error
 *  0 ok
 */
int novacom_service_reply(const char *devid, struct novacom_command_url *url, const void *buf, size_t len)
{
	int rc=-1;
	unsigned char type; /* reply cmd type */
	unsigned char version; /* reply cmd version */
	unsigned char cmd; /* reply cmd */
	buffer_t *b = buffer_new(0);

	LTRACEF("len %d\n", len);
	/* buffer wrapper */
	rc = buffer_setdata(b, (unsigned char *)buf, len);
	if (rc)
		goto done;

	/* recover message type, version, cmd */
	rc = buffer_getbyte(b, &type);
	if (rc)
		goto done;
	rc = buffer_getbyte(b, &version);
	if (rc)
		goto done;
	rc = buffer_getbyte(b, &cmd);
	if (rc)
		goto done;

	LTRACEF("msg type: %d, cmd %d\n", type, cmd);
	switch(cmd) {
		case SSH_MSG_DISCONNECT:
		case SSH_MSG_USERAUTH_REQUEST:
			rc = (SSH_MSG_USERAUTH_FAILURE == type)? -1:0;
		break;
		case SSH_MSG_USERAUTH_TOKENREQUEST_RM:
			rc = (SSH_MSG_USERAUTH_FAILURE == type)? -1:0;
			/* delete local store */
			if (SSH_MSG_USERAUTH_SUCCESS == type) {
				tokenstorage_remove(devid);
			}
		break;
		case SSH_MSG_USERAUTH_TOKENREQUEST_ADD:
			if (SSH_MSG_USERAUTH_TOKEN_REPLY == type) {
				unsigned char *token = NULL;
				rc = buffer_getblob(b, &token);
				LTRACEF("rc %d\n", rc);

				if (rc > 0) {
					LTRACEF("save token reply to local store\n");
					rc = tokenstorage_store(devid, token, rc);
					if (rc < 0) {
						TRACEF("Unable to save token in local store\n");
					}
					platform_free(token);
				}
			} else {
				rc = -1;
			}
		break;
		default: {
			rc = -1;
		}
		break;
	}

done:
	buffer_free(b);

	return rc;
}

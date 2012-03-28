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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "debug.h"
#include "platform.h"
#include "novacom.h"
#include "buffer.h"
#include "device/auth.h"

//
#define LOCAL_TRACE    0
#define TRACE_COMMANDS 0

/*
* @brief handle "logout" request
 */
static int novacom_handle_authlogout(device_handle_t dev, uint32_t chan, buffer_t *b, buffer_t *r, unsigned char cmd)
{
	bool res;
	LTRACEF("disconnect session command\n");
	res = auth_reset_state();
	if (false == res)
		buffer_putbyte(r, SSH_MSG_USERAUTH_FAILURE);
	else 
		buffer_putbyte(r, SSH_MSG_USERAUTH_SUCCESS);
	buffer_putbyte(r, 0);
	buffer_putbyte(r, cmd);
	return (true == res)?0:-1;
}

/*
 * @brief handle authrequest
 */
static int novacom_handle_authrequest(device_handle_t dev, uint32_t chan, buffer_t *b, buffer_t *r, unsigned char cmd)
{
	int rc=-1;
	bool res = false;
	char *mode = NULL;
	char *str = NULL;

	/* skip version */
	if ( 0 != buffer_getbyte(b, NULL) ) {
		goto done;
	}

	/* get mode */
	if (0 != buffer_getstring(b, (unsigned char **)&mode) ) {
		goto done;
	}

	/* get hash */
	if ( 0 != buffer_getstring(b, (unsigned char **)&str) ) {
		goto done;
	}

	LTRACEF("mode %s, hash %s\n", mode, str);
	rc = strlen(mode);
	if ( (AUTH_METHOD_PASSWORD_LEN == rc)
		&& ( 0 == strncmp(mode, AUTH_METHOD_PASSWORD, rc)) ) {
		/*password request */
		res = auth_process_passw(str, strlen(str), 0);
	} else if ( (AUTH_METHOD_TOKEN_LEN == rc)
				&& ( 0 == strncmp(mode, AUTH_METHOD_TOKEN, rc)) ) {
		/*token request*/
		res = auth_process_token(str, strlen(str));
	}
	rc = (true == res)?0:-1;

done:
	/* pickup res */
	LTRACEF("result(%d)\n", rc);
	if (rc)
		buffer_putbyte(r, SSH_MSG_USERAUTH_FAILURE);
	else 
		buffer_putbyte(r, SSH_MSG_USERAUTH_SUCCESS);
	buffer_putbyte(r, 0);
	buffer_putbyte(r, cmd);

	/*resources */
	platform_free(mode);
	platform_free(str);
	return rc;
}

/*
 * @brief handle token request
 * mode=0:add token request
 * mode=1:remove token request
 */
static int novacom_handle_tokenrequest(device_handle_t dev, uint32_t chan, buffer_t *b, buffer_t *r, unsigned char cmd)
{
	int rc=-1;
	char *hash = NULL;
	char *token = NULL;
	char *blob = NULL;

	/* skip version */
	if ( 0 != buffer_getbyte(b, NULL) ) {
		LTRACEF("missing version\n");
		goto out;
	}

	/* get hash */
	if ( 0 != buffer_getstring(b, (unsigned char **)&hash) ) {
		LTRACEF("missing password hash\n");
		goto out;
	}

	/* get hashed token for "remove" */
	if ( (SSH_MSG_USERAUTH_TOKENREQUEST_RM == cmd)
			&& ( 0 != buffer_getstring(b, (unsigned char **)&token) ) ) {
		LTRACEF("missing token hash\n");
		goto out;
	}

	/* verify that password hash is good */
	if ( true != auth_process_passw(hash, strlen(hash), 1) ) {
		LTRACEF("invalid password hash\n");
		goto out;
	}

	/* process tokens */
	if (SSH_MSG_USERAUTH_TOKENREQUEST_RM == cmd) {
		rc = auth_tokenfile_delete(token, strlen(token));
		/* pickup res */
		if (!rc) {
			buffer_putbyte(r, SSH_MSG_USERAUTH_SUCCESS);
			buffer_putbyte(r, 0);   /* version */
			buffer_putbyte(r, cmd); /* command */
		}
	} else {
		blob = platform_calloc(NOVACOM_AUTHTOKEN_LEN);
		if (!blob) {
			LTRACEF("unable to allocate token\n");
			goto out;
		}
		/* fill with random data */
		LTRACEF("generate token\n");
		rc = auth_tokenfile_buffergenerate(blob, NOVACOM_AUTHTOKEN_LEN);
		if (rc) {
			LTRACEF("unable to generate token\n");
			goto out;
		}
		/* save token: creating file with name:<rnduid> */
		LTRACEF("save token\n");
		char *file = novacom_rnduid(dev);
		if (!file) {
			LTRACEF("unable to retrieve rnduid\n");
			goto out;
		}
		rc = auth_tokenfile_create(file, blob, NOVACOM_AUTHTOKEN_LEN);
		platform_free(file);
		if (rc) {
			LTRACEF("unable to store token\n");
			goto out;
		}
		LTRACEF("token generated && saved\n");
		/* pickup res */
		buffer_putbyte(r, SSH_MSG_USERAUTH_TOKEN_REPLY);
		buffer_putbyte(r, 0);   /* version */
		buffer_putbyte(r, cmd); /* command */
		/* resize output buffer to fit token data */
		rc = buffer_resize(r, 16 + NOVACOM_AUTHTOKEN_LEN);
		if (rc)
			goto out;

		rc = buffer_putblob(r, (unsigned char *)blob, NOVACOM_AUTHTOKEN_LEN);
		LTRACEF("token placed\n");
	}

out:
	/* error result */
	if (rc) {
		buffer_setpos(r, 0);
		buffer_putbyte(r, SSH_MSG_USERAUTH_FAILURE);
		buffer_putbyte(r, 0);   /* version */
		buffer_putbyte(r, cmd); /* command */
	}
	LTRACEF("result(%d), r->pos %d, r->size %d\n", rc, r->pos, r->len);
	/* free resources */
	platform_free(hash);
	platform_free(token);
	platform_free(blob);
	return rc;
}

int novacom_handle_command_fromclient(device_handle_t dev, uint32_t chan, int err, const void *buf, size_t len, void *cookie)
{
	int rc=0;
	unsigned char type;
	buffer_t *b = buffer_new(0);
	buffer_t *r = buffer_new(4); /* reply buffer, can be resized in handler */

	TRACEF("chan %d, len %d\n", chan, len);

	/* error, ignore */
	if (err < 0)
		goto out;

	/* buffer wrapper */
	buffer_setdata(b, (unsigned char *)buf, len);

	/* recover message type */
	buffer_getbyte(b, &type);
	TRACEF("msg type: %d\n", type);
	switch(type) {
		case SSH_MSG_DISCONNECT:
			rc = novacom_handle_authlogout(dev, chan, b, r, type);
		break;
		case SSH_MSG_USERAUTH_REQUEST:
			rc = novacom_handle_authrequest(dev, chan, b, r, type);
		break;
		case SSH_MSG_USERAUTH_TOKENREQUEST_ADD:
		case SSH_MSG_USERAUTH_TOKENREQUEST_RM:
			rc = novacom_handle_tokenrequest(dev, chan, b, r, type);
		break;
		default: {
			type = SSH_MSG_UNIMPLEMENTED;
			buffer_putbyte(r, type);
		}
		break;
	}

	/* async write, so reply data is copied...*/
	rc = novacom_write_channel_async(dev, chan, r->data, r->pos, 0, NULL, NULL);

out:
	/* free buffers */
	buffer_free(b);
	buffer_free(r);

	return rc;
}

int novacom_setup_service_command(device_handle_t device_handle, uint32_t chan)
{
	novacom_set_read_callback(device_handle, chan, &novacom_handle_command_fromclient, NULL);

	return 0;
}


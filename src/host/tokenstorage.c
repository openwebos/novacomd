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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include "novacom.h"
#include "lib/cksum.h"
#include "device/auth.h"
#include "host/novacom_host.h"
#include "debug.h"

#define LOCAL_TRACE 0
/*
 * @brief handles save/read/delete token files on host side
 * Linux OS
 *   /root/.nova
 */

/*
 * @brief: tokenstorage path
 * @ret -1 error
 *       0 success
 */
static int tokenstorage_path(char *path, size_t len)
{
	int rc = 0;
	uid_t uid;
	struct passwd *pw = NULL;

	/* environment (inherited from current user) */
	uid = getuid();
	pw = getpwuid(uid);

	if (!pw || !pw->pw_dir) {
		TRACEF("unable to recover home directory\n");
		return -1;
	}

	/* create directory */
	snprintf(path, len, "%s/.nova/", pw->pw_dir);
	LTRACEF("path %s\n", path);

	rc = mkdir(path, S_IRWXU);
	if (rc && errno != EEXIST) {
		TRACEF("unable to create .nova directory\n");
		return -1;
	}

	return 0;
}


/*
 * @brief stores token data as /root/.nova/<nduid>
 */
int tokenstorage_store(const char *file, void *buf, size_t len)
{
	char path[128];
	size_t  rc=0;
	FILE *fd = NULL;

	/* check storage path */
	if ( -1 == tokenstorage_path(path, sizeof(path)) ) {
		return -1;
	}
	/* token file */
	strncat(path, file, sizeof(path) - strlen(path) - 1);

	/* create it */
	fd = fopen(path, "wb");
	if ( NULL == fd) {
		TRACEF("unable to create '%s' file\n", path);
		return -1;
	}
	LTRACEF("write: %d bytes to '%s' file\n", len, path);
	rc = fwrite(buf, 1, len, fd);
	fclose(fd);
	if (len != rc) {
		TRACEF("unable to write to '%s' file: remove...\n", path);
		remove(path);
		return -1;
	}

	return 0;
}

/*
 * @brief stores token data as /root/.nova/<nduid>
 */
int tokenstorage_remove(const char *file)
{
	int rc;
	char path[128];
	/* check storage path */
	rc = tokenstorage_path(path, sizeof(path));
	if (-1 == rc) {
		return rc;
	}
	/* token file */
	strncat(path, file, sizeof(path) - strlen(path));
	/* remove it */
	rc = remove(path);

	return rc;
}

/*
 * @brief reads token data as /root/.nova/<nduid>
 * @ret -1  error
 *      > 0 number of bytes read
 */
int tokenstorage_read(const char *file, void *buf, size_t len)
{
	char path[128];
	size_t rc;
	FILE *fd;

	/* check storage path */
	if ( -1 == tokenstorage_path(path, sizeof(path)) ) {
		return -1;
	}
	/* token file */
	strncat(path, file, sizeof(path) - strlen(path));
	LTRACEF("path %s\n", path);

	/* read */
	fd = fopen(path, "rb");
	if ( NULL == fd) {
		TRACEF("unable to open '%s' file\n", path);
		return -1;
	}
	rc = fread(buf, 1, len, fd);
	fclose(fd);
	if (len != rc) {
		TRACEF("unable to read data: '%s' file...\n", path);
		return -1;
	}

	return rc;
}

/*
 * @brief reads token data as /root/.nova/<nduid> and calculates hash
 * @ret -1  error
 *      > 0 hash length
 */
int tokenstorage_readhash(const char *file, const char *ssid, void *hash, size_t len)
{
	int rc=-1;
	char *buf = NULL;

	/* check hash buffer size */
	if ( len < SHA1_HASH_STRSIZE) {
		LTRACEF("invalid buffer length (%d/%d)\n", len, SHA1_HASH_STRSIZE);
		return rc;
	}

	/* check session size */
	if ( NOVACOM_AUTHSESSION_LEN != strlen(ssid) ) {
		LTRACEF("invalid session length (%d/%d)\n", strlen(ssid), NOVACOM_AUTHSESSION_LEN);
		return rc;
	}

	/* allocate memory to fit tokendata + session id */
	buf = (char *)platform_calloc(NOVACOM_AUTHTOKEN_LEN + NOVACOM_AUTHSESSION_LEN);
	if (!buf) {
		LTRACEF("Unable to allocate memory\n");
		return rc;
	}

	/* calc hash */
	SHA1Context ctx;
	rc = tokenstorage_read(file, buf, NOVACOM_AUTHTOKEN_LEN);
	if (-1 == rc) {
		goto done;
	}
	memcpy(buf + NOVACOM_AUTHTOKEN_LEN, ssid, NOVACOM_AUTHSESSION_LEN);
	SHA1Reset(&ctx);
	SHA1Input(&ctx, (const unsigned char *)buf, NOVACOM_AUTHTOKEN_LEN + NOVACOM_AUTHSESSION_LEN);
	rc = SHA1Result(&ctx);
	memcpy(hash, ctx.Message_Digest_Str, sizeof(ctx.Message_Digest_Str));
	rc = (int) sizeof(ctx.Message_Digest_Str);

done:
	/* free resources */
	platform_free(buf);

	return rc;
}


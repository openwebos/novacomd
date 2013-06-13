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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <inttypes.h>
#include <fcntl.h>
#include <dirent.h>

#include "novacom.h"
#include "debug.h"
#include "platform.h"
#include "device/auth.h"
#include "lib/cksum.h"

//#define DEBUG_AUTH
//debug
#define LOCAL_TRACE		0
#define TRACE_CHECKPASS		1
#define TRACE_SETSESSION	1
#define TRACE_CHECKREAD		0

#define DEVICE_PASS_FILE		"/var/novacom/passwd"
#define DEVICE_BLOB_DIR			"/var/novacom/tokens"
#define DEVICE_BLOB_MAXCOUNT	(100)

#define DEVICE_HASH_SIZE		(SHA1_HASH_SIZE)	/* sha1 hash 160bit */
#define DEVICE_HASH_STRSIZE		(SHA1_HASH_STRSIZE)	/* sha1 string hash */

/* */
typedef struct auth_token_record_s {
	char *filename;
	char token_data[NOVACOM_AUTHTOKEN_LEN];		/* device token */
	char token_hash[DEVICE_HASH_STRSIZE];		/* string hashed token */
	int  token_len;
	TAILQ_ENTRY(auth_token_record_s) entries;	/* holds pointers to prev, next entries */
} auth_token_record_t;

/* */
typedef struct novacom_auth_state {
#ifdef DEBUG_AUTH
	unsigned int	unlockcnt;               /* debug unlock cnt(auto unlocks after 10 attempts */
#endif
	unsigned int	tokenfailcount;          /* number of failed token authentication attempts */
	unsigned int	failcount;               /* Number of (failed) authentication attempts.*/
	bool			protected;               /* Is protection enabled */
	bool			authdone;                /* 0 if we haven't authed, 1 if we have */

	TAILQ_HEAD(token_queue_s, auth_token_record_s)  t_token_queue; /* queue of tokens */

	bool session_set;                        /* session is set */
	char session[NOVACOM_AUTHSESSION_LEN];   /* session data */
} novacom_auth_state_t;

//locals
static novacom_auth_state_t	auth_state;

//proto
static int read_data(const char *file_name, char *buf, int inlen);
static int auth_tokenfile_read(const char *file, char *buf, int buflen);
static int auth_new_session(char *session, int len);
static void auth_set_session(char session[NOVACOM_AUTHSESSION_LEN]);
static int auth_tokenfile_scan( void );
/*
 * @brief auth_create create auth
 */
void auth_create( void )
{
	/* */
	memset(&auth_state, 0, sizeof(auth_state));
	auth_state.authdone = true; /* no password, by default */
	TAILQ_INIT(&auth_state.t_token_queue);
}


/*
 * @brief auth_init initialize auth
 * @ret none
 */
void auth_init( void )
{
	int rc;
	struct stat fstat;

	if (!TAILQ_EMPTY(&auth_state.t_token_queue)) {
		(void) auth_reset();
		TRACEF("clear tokens...\n");
	}
	//defaults
#ifdef DEBUG_AUTH
	auth_state.unlockcnt = 0;
#endif
	auth_state.tokenfailcount = 0; 
	auth_state.failcount = 0;
	auth_state.protected = false;
	auth_state.authdone = true; /* no password, by default */
	memset(&auth_state.session, 0, sizeof(auth_state.session));

	//check if exists
	memset(&fstat, 0, sizeof(fstat));
	rc = stat(DEVICE_PASS_FILE, &fstat);
	LTRACEF("passenabled flag(%d), file(%s)\n", rc, DEVICE_PASS_FILE);

	if (!rc && fstat.st_size) {

		auth_state.protected = true;
		auth_state.authdone = false; /* password enabled */

	}

	if(!rc) {
		char session[NOVACOM_AUTHSESSION_LEN];
		rc = auth_new_session(session, sizeof(session));
		auth_set_session(session);
	}

	return;
}

/*
 * auth_reset_state
 * reset auth state
 */
bool auth_reset_state()
{
	/* clear only if password protected */
	if (true == auth_state.protected) {
		/* reset fail count only if previously authenticated */
		if (auth_state.authdone) {
			auth_state.failcount = 0;
		}
		/* reset authentication state */
		auth_state.authdone = false;
	} else {
		auth_state.authdone = true;
	}
	LTRACEF("authdone(%d)\n", auth_state.authdone);
#ifdef DEBUG_AUTH
	auth_state.unlockcnt = 0;
#endif
	return true;
}

/*
 * auth_reset
 * reset auth state, clear all memory, etc...
 */
bool auth_reset()
{
	auth_token_record_t *item;

#ifdef DEBUG_AUTH
	auth_state.unlockcnt = 0;
#endif
	auth_state.authdone = true; /* password disabled */

	/* clear queue */
	while( (item = TAILQ_FIRST(&auth_state.t_token_queue)) ){
		TAILQ_REMOVE(&auth_state.t_token_queue, item, entries);
		platform_free(item->filename);
		platform_free(item);
	}

	return true;
}

/*
 * @brief auth_is_done returns authentication state
 */
bool auth_is_done( void )
{
	LTRACEF("authdone(%d)\n", auth_state.authdone);

#ifdef DEBUG_AUTH
	LTRACEF("auto_unlockcnt(%d)\n", auth_state.unlockcnt);
	if(auth_state.unlockcnt > 10) {
		auth_state.authdone = true;
	} else {
		++auth_state.unlockcnt;
	}
#endif

	return auth_state.authdone;
}

/*
 * @brief checks provided password
 * @param input user data
 * @param inlen user data length
 * @param forced forced run(ignore authdone state)
 * @ret true success, false error
 *  success also sets auth_done to unlocked state
 */
bool auth_process_passw(const char *input, int inlen, int forced)
{
	SHA1Context ctx;
	int rc = -1;
	char *hash = NULL;

	/* forced run? */
	if (!forced) {
		/* check: ignore if permission granted */
		if (true == auth_state.authdone) {
			return true;
		}
	
		/* check: re */
		if (auth_state.failcount > NOVACOM_AUTH_PASSWD_RETRY_MAX) {
			TRACEL(LOG_ERROR, "Exceeded number of retries\n");
			return false;
		}
	}

	/* check: length */
	if (inlen != (DEVICE_HASH_STRSIZE) ) {
		TRACEL(LOG_ERROR, "Invalid hash size (%d/%d)\n", inlen, DEVICE_HASH_STRSIZE);
		return false;
	}

	/* check */
	if (false == auth_state.session_set) {
		TRACEF("Session must be generated and active\n");
		return false;
	}

	/* check */
	hash = platform_calloc(DEVICE_HASH_STRSIZE + NOVACOM_AUTHSESSION_LEN);
	if (NULL == hash) {
		TRACEF("Unable to allocate memory\n");
		return false;
	}

	/*open file*/
	rc = read_data(DEVICE_PASS_FILE, hash, DEVICE_HASH_STRSIZE);
	if ( (rc != -1) && (rc == DEVICE_HASH_STRSIZE) ) {

		PTRACEF(TRACE_CHECKPASS, "passwd(%.*s)\n", DEVICE_HASH_STRSIZE, hash);

		/* calc SHA1(nduid, password, session)*/
		memcpy(hash + rc, auth_state.session, NOVACOM_AUTHSESSION_LEN);
		SHA1Reset(&ctx);
		SHA1Input(&ctx, (const unsigned char *)hash, rc + NOVACOM_AUTHSESSION_LEN);
		rc = SHA1Result(&ctx);

		/* compare */
		rc = memcmp(input, ctx.Message_Digest_Str, inlen);
		PTRACEF(TRACE_CHECKPASS, "compared hashes(%d)\n", rc);
		PTRACEF(TRACE_CHECKPASS, "     input hash(%.*s)\n", inlen, input);
		PTRACEF(TRACE_CHECKPASS, "      calc hash(%.*s)\n", inlen, ctx.Message_Digest_Str);
		/* skip updates for forced mode */
		if (!forced) {
			if(0 == rc) {
				auth_state.authdone = true;
			} else {
				++auth_state.failcount;
				usleep(200000);
			}
		}
	} else {
		TRACEL(LOG_ERROR, "Read password error(%d)\n", rc);
	}

	platform_free(hash);

	return rc?false:true;
}

/* 
 * @brief verify token
 * @param input user input
 * @param inlen user input length
 * @ret true success, false failure
 */
bool auth_process_token(const char *input, int inlen)
{
	auth_token_record_t *item;
	int rc;

	/* check: length */
	if (inlen != (DEVICE_HASH_STRSIZE) ) {
		TRACEL(LOG_ERROR, "Invalid hash size\n");
		return false;
	}

	/* check: ignore if permission granted */
	if (true == auth_state.authdone) {
		return true;
	}

	/* check: attempts */
	if (auth_state.tokenfailcount > NOVACOM_AUTH_TOKEN_RETRY_MAX) {
		TRACEL(LOG_ERROR, "Exceeded number of retries\n");
		return false;
	}

	/*hashes are generated in advance */
	for (item = TAILQ_FIRST(&auth_state.t_token_queue); item != NULL; item = TAILQ_NEXT(item, entries)) {

		PTRACEF(TRACE_CHECKPASS, "item: \n");
		rc = memcmp(item->token_hash, input, inlen);
		PTRACEF(TRACE_CHECKPASS, "compared rc(%d)\n", rc);

		if (0 == rc) {
			auth_state.authdone = true;
			break;
		} else {
			++auth_state.tokenfailcount;
		}
	}

	return auth_state.authdone;
}

/* 
 * @brief auth_set_session
 * @param session session data(random data)
 * @ret none
 */
static void auth_set_session(char session[NOVACOM_AUTHSESSION_LEN])
{
	/* copy data */
	memcpy(auth_state.session, session, NOVACOM_AUTHSESSION_LEN);
	auth_state.session_set = true;

	auth_tokenfile_scan();

}

/* 
 * @brief auth_get_session
 * @param session session data(random data)
 * @ret -1 session not set or buffer too small
 *      number of bytes in session
 */
int auth_get_session(char *session, int len)
{
	/* */
	if(len < NOVACOM_AUTHSESSION_LEN) {
		TRACEF("Buffer too small\n");
		return -1;
	}

	/* */
	if(true != auth_state.session_set) {
		TRACEF("session is not set yet\n");
		return -1;
	}

	memcpy(session, auth_state.session, NOVACOM_AUTHSESSION_LEN);

	return NOVACOM_AUTHSESSION_LEN;
}

/* 
 * @brief auth_new_session generates new session data
 * @param session session data(random data)
 * @ret -1 session not set or buffer too small
 *      number of bytes in session
 */
static int auth_new_session(char *session, int len)
{
	int i;
	/* check length */
	if(len < NOVACOM_AUTHSESSION_LEN) {
		TRACEF("Buffer too small\n");
		return -1;
	}

	/* random generated data */
	for (i=0; i < NOVACOM_AUTHSESSION_LEN; i++) {
		session[i] = "0123456789abcdef"[rand() & 0xf];
	}
	LTRACEF("session[%.*s]\n", NOVACOM_AUTHSESSION_LEN, session);

	return NOVACOM_AUTHSESSION_LEN;
}

/*
 * @brief read token file contents
 * @param file
 * @param buf
 * @param buflen
 * @ret 0 success, -1 error
 */
static int auth_tokenfile_read(const char *file, char *buf, int buflen)
{
	int rc;
	char fpath[128];	/* full path */
	struct stat st;

	snprintf(fpath, sizeof(fpath), "%s/%s", DEVICE_BLOB_DIR, file);

	rc = stat(fpath, &st); /* check if we have regular file */
	if( (0 == rc) &&(S_ISREG(st.st_mode)) ) {
		rc = read_data(fpath, buf, buflen); /* read contents into buffer */
	} else {
		rc = -1;
	}
	return rc;
}

/*
 * @brief generate token file contents
 * @param buf
 * @param buflen
 * @ret 0 success, -1 error
 */
int auth_tokenfile_buffergenerate(char *buf, int buflen)
{
	int rc=0;
	int i;
	for(i=0; i< buflen; i++) {
		buf[i] = (char)(rand() & 0xff);
	}

	return rc;
}
/*
 * @brief create token file contents
 * @param path
 * @param file
 * @param buf
 * @param buflen
 * @ret 0 success, -1 error
 */
int auth_tokenfile_create(char *file, char *buf, int buflen)
{
	int rc = -1;
	int fd;
	char fpath[128];	/* full path */

	/* create directory */
	snprintf(fpath, sizeof(fpath), "%s", DEVICE_BLOB_DIR);
	rc = mkdir(fpath, S_IRWXU);
	if (rc && errno != EEXIST) {
		TRACEF("unable to create directory\n");
		return -1;
	}

	/*  */
	snprintf(fpath, sizeof(fpath), "%s/%s", DEVICE_BLOB_DIR, file);
	fd = open(fpath, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);

	if(-1 != fd) {
		rc = write(fd, buf, buflen);	/* write to file */
		(void) close(fd);
		if(rc != buflen) {
			remove(fpath);	/* remove partial file */
			TRACEF("Unable to write to file(%d/%d)\n", rc, buflen);
			rc = -1;
		} else {
			rc = 0;

			/* force scan */
			auth_tokenfile_scan();
		}
	}

	return rc;
}

/*
 * @brief remove token file
 * @param input  hash dataf
 * @param inlen  hash length
 * @ret 0 success, -1 error
 */
int auth_tokenfile_delete(char *input, int inlen)
{
	int rc = -1;
	auth_token_record_t *item = NULL;;

	/* skip invalid data*/
	if (!input) {
		LTRACEF("invalid data...\n");
		return -1;
	}

	/* skip invalid length */
	if (inlen != DEVICE_HASH_STRSIZE) {
		LTRACEF("invalid hash size...\n");
		return -1;
	}

	/* walk through hash table */
	for (item = TAILQ_FIRST(&auth_state.t_token_queue); item != NULL; item = TAILQ_NEXT(item, entries)) {
		int res = memcmp(item->token_hash, input, inlen);
		LTRACEF("compared res(%d) against file '%s'\n", res, item->filename);
		if(0 == res) {
			char fpath[128];

			snprintf(fpath, sizeof(fpath), "%s/%s", DEVICE_BLOB_DIR, item->filename);
			rc = remove(fpath);
			LTRACEF("file remove: rc(%d)\n", rc);

			/* force scan */
			auth_tokenfile_scan();

			break;
		}
	}

	return rc;
}


/*
 * reads data from file and returns length
 * @param file_name
 * @param buf        buffer
 * @param inlen      buffer length
 * @ret -1 error, otherwise: number of bytes read
 */
static int read_data(const char *file_name, char *data, int inlen)
{
	int rc;
	long i, toread;
	int fd = -1;

	PTRACEF(TRACE_CHECKREAD, "open file\n");
	fd = open(file_name, O_RDONLY);
	if(-1 == fd) {
		PTRACEF(TRACE_CHECKREAD, "unable to open file\n");
		rc = -1;
		goto exit;
	}

	/* fill buffer */
	PTRACEF(TRACE_CHECKREAD, "read file\n");
	for (i = 0, toread = inlen; i < inlen;) {
		rc = read(fd, &data[i], toread);
		if (rc <= 0)
			break;
		toread -= rc;
		i += rc;
	}

	/* did we read any */
	PTRACEF(TRACE_CHECKREAD, "read(%d) bytes\n", i);
	if(i == 0) {
		rc = -1;
		goto exit;
	} else if(data[i-1] == '\n') {
		data[i-1] = 0;
		--i;
	}

exit:
	if(fd != -1) {
		close(fd);
	}

	return rc;
}

/*
 * @brief clears tokens, scans token files, calcs hashes
 * @ret 0 success, -1 error
 */
static int auth_tokenfile_scan( void )
{
	int rc=-1;
	char *hash = NULL;
	DIR *dfd = NULL;
	struct dirent *dp = NULL;
	int count = 0;
	auth_token_record_t *item;

	/* clear queue */
	while( (item = TAILQ_FIRST(&auth_state.t_token_queue)) ){
		TAILQ_REMOVE(&auth_state.t_token_queue, item, entries);
		LTRACEF("clear token: file(%s)\n", item->filename);
		platform_free(item->filename);
		platform_free(item);
	}

	/* hash blob */
	hash = platform_calloc(NOVACOM_AUTHTOKEN_LEN + NOVACOM_AUTHSESSION_LEN);
	if (!hash)
		return -1;

	dfd = opendir(DEVICE_BLOB_DIR);
	if (dfd)  {

		/* read dir */
		while((dp = readdir(dfd)) != NULL) {
			if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
				int read;
				auth_token_record_t t_buf;

				LTRACEF("read token from (%s/%s)\n", DEVICE_BLOB_DIR, dp->d_name);

				read = auth_tokenfile_read(dp->d_name, t_buf.token_data, sizeof(t_buf.token_data));
				if (-1 != read) {
					item = (auth_token_record_t *)platform_calloc(sizeof(auth_token_record_t));

					if (item) {
						/* token itself */
						memcpy(item->token_data, t_buf.token_data, read);
						/* filename */
						item->filename = platform_strdup(dp->d_name);
						if (!item->filename) {
							LTRACEF("Unable to allocate memory...\n");
							platform_free(item);
							break;
						}
						/* token length */
						item->token_len = read;

						/* token hash */
						SHA1Context ctx;

						/* calc SHA1(token, session)*/
						memset(hash, 0, sizeof(*hash));
						memcpy(hash, item->token_data, item->token_len);
						memcpy(hash + item->token_len, auth_state.session, NOVACOM_AUTHSESSION_LEN);
						SHA1Reset(&ctx);
						SHA1Input(&ctx, (const unsigned char *)hash, item->token_len + NOVACOM_AUTHSESSION_LEN);
						rc = SHA1Result(&ctx);
						memcpy(item->token_hash, ctx.Message_Digest_Str, sizeof(item->token_hash));

						LTRACEF("item: calc rc(%d), hash(%.*s)\n",
									rc, DEVICE_HASH_STRSIZE, item->token_hash);

						/* attach to queue */
						TAILQ_INSERT_TAIL(&auth_state.t_token_queue, item, entries);
						++count;

						/* check */
						if(DEVICE_BLOB_MAXCOUNT < count) {
							TRACEL(LOG_ERROR, "too many tokens defined(%d), abort...\n", count);
							break;
						}
					} else {
						TRACEL(LOG_ERROR, "Unable to allocate memory...\n");
						break;
					}
				}
			}
		}
		closedir(dfd);
	} else {
		LTRACEF("unable to open directory\n");
	}

	platform_free(hash);

	return rc;
}


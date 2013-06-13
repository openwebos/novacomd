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

/*
 * @brief auth.h
 */
#ifndef __NOVACOM_AUTH_P_H
#define __NOVACOM_AUTH_P_H


#include <novacom.h>

/* message numbers */
#define SSH_MSG_DISCONNECT                   1
#define SSH_MSG_IGNORE                       2
#define SSH_MSG_UNIMPLEMENTED                3
#define SSH_MSG_DEBUG                        4
#define SSH_MSG_SERVICE_REQUEST              5
#define SSH_MSG_SERVICE_ACCEPT               6
#define SSH_MSG_KEXINIT                     20
#define SSH_MSG_NEWKEYS                     21
#define SSH_MSG_KEXDH_INIT                  30
#define SSH_MSG_KEXDH_REPLY                 31

/* userauth message numbers */
#define SSH_MSG_USERAUTH_REQUEST            50
#define SSH_MSG_USERAUTH_FAILURE            51
#define SSH_MSG_USERAUTH_SUCCESS            52
#define SSH_MSG_USERAUTH_BANNER             53
/* packets 60-79 are method-specific, aren't one-one mapping */
#define SSH_MSG_USERAUTH_TOKENREQUEST_ADD   70 /* add token */
#define SSH_MSG_USERAUTH_TOKENREQUEST_RM    71 /* delete token */
#define SSH_MSG_USERAUTH_TOKEN_REPLY        75 /* response */

#define AUTH_METHOD_PASSWORD "password"
#define AUTH_METHOD_PASSWORD_LEN 8
#define AUTH_METHOD_TOKEN "token"
#define AUTH_METHOD_TOKEN_LEN 5

/* 
 * authentication message format (similar to ssh):
 * REQUESTS
 *
 * => [logout] disconnect current session
 *  byte(SSH_MSG_DISCONNECT)
 *  byte(VERSION)
 *
 * => [login]password_authentication_request
 *  byte(SSH_MSG_USERAUTH_REQUEST)
 *  string(AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN);
 *  byte(VERSION)
 *  string(hash, 40);
 *
 * => token_authentication_request
 *  byte(SSH_MSG_USERAUTH_REQUEST)
 *  string(AUTH_METHOD_TOKEN, AUTH_METHOD_TOKEN_LEN);
 *  byte(VERSION)
 *  string(hash, 40);
 *
 * => token_add
 *  byte(SSH_MSG_USERAUTH_TOKENREQUEST_ADD) 
 *  byte(VERSION)
 *  string(hash, 40); :hashed password
 *
 * => token_remove
 *  byte(SSH_MSG_USERAUTH_TOKENREQUEST_RM) 
 *  byte(VERSION)
 *  string(hash, 40); ::hashed password
 *  string(hash, 40); ::hash for token: we can operate on hash
 *
 * REPLY
 * <= invalid password
 *  byte(SSH_MSG_USERAUTH_FAILURE);
 *  byte(VERSION)
 *  byte(REQUEST_TYPE)
 *
 * <= invalid token
 *  byte(SSH_MSG_USERAUTH_FAILURE);
 *  byte(VERSION)
 *  byte(REQUEST_TYPE)
 *
 * <= success
 *  byte(SSH_MSG_USERAUTH_SUCCESS);
 *  byte(VERSION)
 *  byte(REQUEST_TYPE)
 *
 * <= token data
 *  byte(SSH_MSG_USERAUTH_TOKEN_REPLY)
 *  byte(VERSION)
 *  byte(REQUEST_TYPE)
 *  string(AUTH_METHOD_TOKEN, AUTH_METHOD_TOKEN_LEN);
 *  string(token, token_length); :current length 256
 */

#define NOVACOM_AUTH_PASSWD_RETRY_MAX	(10) /* number of failed password attempts allowed per connection */
#define NOVACOM_AUTH_TOKEN_RETRY_MAX	(1) /* number of failed token attempts allowed per connection */
#define NOVACOM_AUTHSESSION_LEN 		(10)
#define NOVACOM_AUTHTOKEN_LEN			(256)

/* create */
void auth_create(void);

/* init */
void auth_init(void);

/* reset */
bool auth_reset();

/* reset state */
bool auth_reset_state();

/* get session */
int auth_get_session(char *session, int len);

/* authentication done */
bool auth_is_done( void );

/* check password */
bool auth_process_passw(const char *input, int inlen, int forced);

/* check token */
bool auth_process_token(const char *input, int inlen);

/* token file create */
int auth_tokenfile_create(char *file, char *buf, int buflen);

/* token file delete */
int auth_tokenfile_delete(char *buf, int len);

/* helper: fill out buffer with random data */
int auth_tokenfile_buffergenerate(char *buf, int buflen);


#endif


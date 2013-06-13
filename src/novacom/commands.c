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
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <debug.h>
#include <platform.h>
#include <novacom.h>

#include "novacom_p.h"

//
#define LOCAL_TRACE    0
#define TRACE_COMMANDS 0

//
#define	DEVICE_COMMAND_ARGS_INC		32		/* allocate memory in steps, instead realloc on each token */
#define DEVICE_COMMAND_ARGS_LIMIT	4096	/* limit number of allowed arguments. Usually, it is OS specific value */
typedef struct device_command_args {
	int count;					/* number of discovered tokens */
	char **tokens;				/* array of tokens  */
	int array_size;				/* array size, reflects preallocated array size */
} device_command_args_t;


static char *trim(char *string)
{
	/* consume leading space */
	for (; isspace(*string); string++)
		;

	/* consume trailing space and newlines */
	int len = strlen(string);
	int pos;

	for (pos = len - 1; pos >= 0 && (isspace(string[pos]) || iscntrl(string[pos])); pos--) {
		string[pos] = 0;
	}

	return string;
}
/*
 * allocate, reallocate device commands array of tokens
 *  Memory allocation is done in blocks to limit number of realloc calls
 */
static int tokens_realloc(device_command_args_t *dev_args)
{
	int res = -1;	/* error by default */
	if(dev_args)  {
//		TRACEF("%s: count %d, tokens %p, array_size %d, dev_args %p\n", __FUNCTION__, dev_args->count, dev_args->tokens, dev_args->array_size, dev_args);
		/* check if we did not exceed limits */
		if(dev_args->array_size < DEVICE_COMMAND_ARGS_LIMIT) {
			dev_args->tokens = (char **)platform_realloc(dev_args->tokens,
									(sizeof(char *))*(dev_args->array_size + DEVICE_COMMAND_ARGS_INC));
			if(!dev_args->tokens) {
				dev_args->count = 0;	/* reset number of arguments */
				return -1;
			}
			dev_args->array_size += DEVICE_COMMAND_ARGS_INC;
			res = 0;
		}
	}
	return res;
}

static int tokenize(char *string, device_command_args_t *dev_args)
{
	int pos = 0;
	int currtok = 0;
	int skips = 0;
	enum {
		INITIAL,
		TOK,
		IN_TOK,
		IN_SPACE,
		IN_SKIP
	} state = INITIAL;

//	TRACEF("tokenize '%s'\n", string);

	while (string[pos] != 0) {
		int res;
//		TRACEF("state %d, pos %d: c '%c'\n", state, pos, string[pos]);
		if(currtok >= dev_args->array_size) {
			res = tokens_realloc(dev_args);
			if(res == -1) {
				return dev_args->count;	/*error during realloc, return known number of tokens*/
			}
		}
		switch (state) {
			case INITIAL:
				if (isspace(string[pos]))
					state = IN_SPACE;
				else
					state = TOK;
				break;
			case TOK:
				dev_args->tokens[currtok] = &string[pos];
				currtok++;
				++dev_args->count;
				skips = 0;
				state = IN_TOK;
				pos++;
				break;
			case IN_TOK:
				if (isspace(string[pos])) {
					state = IN_SPACE;
					break;
				} else if (string[pos]=='\\') {
					state = IN_SKIP;
					pos++;
					break;
				}
				if (skips) {
					string[pos-skips] = string[pos];
					string[pos] = 0;
				}
				pos++;
				break;
			case IN_SPACE:
				if (!isspace(string[pos])) {
					state = TOK;
					break;
				}
				string[pos] = 0;
				pos++;
				break;
			case IN_SKIP:
				state = IN_TOK;
				++skips;
				string[pos-skips] = string[pos];
				string[pos] = 0;
				pos++;
				break;
		}
	}

	return currtok;
}

/*
 * free url resources
 */
void free_url(novacom_command_url_t *url)
{
	if(url) {
		platform_free(url->args);
		platform_free(url->verbargs);
		platform_free(url->string);
	}
	platform_free(url);
}

/*
 * parse command
 */
int parse_command(const char *_string, size_t len, struct novacom_command_url **_url)
{
	int i;
	int num_tokens;
	char *string = NULL;
	struct novacom_command_url *url = NULL;
	device_command_args_t *dev_args = NULL;

	url = (novacom_command_url_t *)platform_calloc(sizeof(struct novacom_command_url));
	if(!url)
		goto error;
 
	/* make a copy */
	string = (char *)platform_alloc(len + 1);
	if(!string)
		goto error;
	memcpy(string, _string, len);
	string[len] = 0;

	url->string = string;

	/* trim it */
	string = trim(string);

	PTRACEF(TRACE_COMMANDS, "string '%s'\n", string);

	/* tokenize it */
	dev_args = (device_command_args_t *)platform_calloc(sizeof(device_command_args_t));
	if(!dev_args)
		goto error;

	num_tokens = tokenize(string, dev_args);
	if (num_tokens <= 0)
		goto error;

	PTRACEF(TRACE_COMMANDS, "num tokens %d\n", num_tokens);
	for (i =0; i < num_tokens; i++) {
		PTRACEF(TRACE_COMMANDS, "token %d: '%s'\n", i, dev_args->tokens[i]);
	}


	/* start grabbing the tokens */
	int currtok = 0;

	/* break out the verb */
	url->verb = dev_args->tokens[0];
	currtok++;

	PTRACEF(TRACE_COMMANDS, "verb '%s'\n", url->verb);

	/* find the verb arguments */
	int verbargstart = currtok;
	for (; currtok < num_tokens; currtok++) {
		if (strstr(dev_args->tokens[currtok], "://") != NULL)
			break;
	}
	PTRACEF(TRACE_COMMANDS, "currtok %d, num_tokens %d\n", currtok, num_tokens);
	if (currtok >= num_tokens)
		goto error;

	/* arguments */
	PTRACEF(TRACE_COMMANDS, "currtok %d, verbargstart %d\n", currtok, verbargstart);
	if (currtok > verbargstart) {
		/* we have some arguments to the verb */
		int argcount = currtok - verbargstart;
		url->verbargs = (char **)platform_alloc(sizeof(char *) * (argcount + 1));
		if(!url->verbargs)
			goto error;
		for (i = 0; i < argcount; i++) {
			url->verbargs[i] = dev_args->tokens[verbargstart + i];
			PTRACEF(TRACE_COMMANDS, "verb arg %d: '%s'\n", i, url->verbargs[i]);
		}
		url->verbargs[argcount] = 0;
	}

	/* find the scheme */
	url->scheme = dev_args->tokens[currtok];

	/* find the :// and remove it */
	char *schemepathsep = strstr(dev_args->tokens[currtok], "://");
	if (schemepathsep == NULL)
		goto error;

	/* zero it out, this creates the scheme string */
	*schemepathsep = 0;

	PTRACEF(TRACE_COMMANDS, "scheme '%s'\n", url->scheme);

	/* path should be the char after :// */
	schemepathsep += 3;

	/* extract the path */
	url->path = schemepathsep;

	PTRACEF(TRACE_COMMANDS, "path '%s'\n", url->path);

	currtok++;

	/* find the regular arguments */
//	TRACEF("args: currtok %d, num_tokens %d\n", currtok, num_tokens);

	if (num_tokens > currtok) {
		/* we have some arguments */
		int argcount = num_tokens - currtok;
		url->args = (char **)platform_alloc(sizeof(char *) * (argcount + 1));
		if(!url->args)
			goto error;
		for (i = 0; i < argcount; i++) {
			url->args[i] = dev_args->tokens[currtok + i];
			PTRACEF(TRACE_COMMANDS, "arg %d: '%s'\n", i, url->args[i]);
		}
		url->argcount = argcount;
		url->args[argcount] = 0;
	}

	PTRACEF(TRACE_COMMANDS, "successful: url %p\n", url);

	*_url = url;

	if(dev_args) {
		platform_free(dev_args->tokens);
		platform_free(dev_args);
	}

	return 0;

error:
	PTRACEF(TRACE_COMMANDS, "failed to parse string\n");
	if(dev_args) {
		platform_free(dev_args->tokens);
		platform_free(dev_args);
	}

	free_url(url);

	return -1;
}

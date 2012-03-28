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
/*
 * Dropbear SSH
 *
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */
#include <string.h>
#include "buffer.h"
#include "debug.h"

#define LOCAL_TRACE 0
/*
 * @brief: create new buffer
 */
buffer_t *buffer_new(size_t size)
{
	buffer_t *buf = NULL;
	buf = (buffer_t *)platform_calloc(sizeof(buffer_t));
	if (buf && size) {
		buf->data = (unsigned char *)platform_calloc(size);
		buf->len = size;
		if (!buf->data) {
			platform_free(buf);
			buf = NULL;
		}
	}
	return buf;
}

/*
 * @brief: free buffer
 */
int buffer_free(buffer_t *b)
{
	/* check */
	if (!b)
		return -1;

	/* free data if exist */
	if(b->data)
		platform_free(b->data);

	platform_free(b);
	return 0;
}

/*
 * @brief: set buffer data
 */
int buffer_resize(buffer_t *b, size_t size)
{
	/* check */
	if (!b)
		return -1;

	/* realloc */
	b->data = (unsigned char *)platform_realloc(b->data, size);
	if (!b->data)
		return -1;

	/* adjust pos if required */
	if(b->pos > size)
		b->pos = size;
	/* update position */
	b->len = size;

	return 0;
}

/*
 * @brief: set buffer data
 */
int buffer_setdata(buffer_t *b, unsigned char *data, size_t size)
{
	if (b->data) {
		platform_free(b->data);
	}

	b->data = (unsigned char *)platform_calloc(size);
	if (!b->data) {
		return -1;
	}
	memcpy(b->data, data, size);
#if LOCAL_TRACE
	hexdump8(b->data, MIN(size, 64));
#endif
	b->pos = 0;
	b->len = size;
	return 0;
}

/*
 * @brief: set pos
 */
int buffer_setpos(buffer_t *b, size_t pos)
{
	if (pos <= b->len) {
		b->pos = pos;
	} else {
		return -1;
	}
	return 0;
}

/*
 * @brief: checks if our buffer fits input of size.
 */
int buffer_checksize(buffer_t *b, unsigned int size)
{
	/* check buffer */
	if(!b)
		return -1;

	LTRACEF("pos %d/%d, +size %d\n", b->pos, b->len, size);
	/*check position */
	if( (b->pos + size) <= b->len) {
		return 0;
	} else {
		return -1;
	}
}
/*
 * @brief: stores 1 byte in buffer
 */
int buffer_putbyte(buffer_t *b, const unsigned char in)
{
	int rc = buffer_checksize(b, sizeof(in) );
	if (!rc) {
		b->data[b->pos++] = in;
	}
	return rc;
}

/*
 * @brief: retrieves 1 byte from buffer
 */
int buffer_getbyte(buffer_t *b, unsigned char *out)
{
	int rc = buffer_checksize(b, sizeof(*out));
	if (!rc) {
		if (out) {
			*out = b->data[b->pos];
		}
		++b->pos;
	}
	return rc;
}

/*
 * @brief: stores byte[len] in buffer
 */
int buffer_putbytes(buffer_t *b, const unsigned char *in, uint32_t len)
{
	int rc = buffer_checksize(b, len);
	if (!rc) {
		memcpy(&b->data[b->pos], in, len);
		b->pos += len;
	}
	return rc;
}

/*
 * @brief: stores int32 in buffer
 */
int buffer_putint32(buffer_t *b, const uint32_t in)
{
	int rc = buffer_checksize(b, sizeof(in) );
	if (!rc) {
		b->data[b->pos++] = (unsigned char)((in >> 24) & 0xff);
		b->data[b->pos++] = (unsigned char)((in >> 16) & 0xff);
		b->data[b->pos++] = (unsigned char)((in >>  8) & 0xff);
		b->data[b->pos++] = (unsigned char)((in      ) & 0xff);
	}
	return rc;
}

/*
 * @brief: retrieves int32 from buffer
 */
int buffer_getint32(buffer_t *b, uint32_t *out)
{
	int rc = buffer_checksize(b, sizeof(uint32_t) );
	if (!rc) {
		if (out) {
			*out = ( (((uint32_t)b->data[b->pos  ]) << 24)
					|(((uint32_t)b->data[b->pos+1]) << 16)
					|(((uint32_t)b->data[b->pos+2]) <<  8)
					|(((uint32_t)b->data[b->pos+3])      ) );
			LTRACEF("out %d, pos %d\n", *out, b->pos);
		}
		b->pos += 4;
	}
	return rc;
}

/*
 * @brief: stores string in buffer (len,string)
 */
int buffer_putstring(buffer_t *b, const unsigned char *in, uint32_t len)
{
	int rc = buffer_checksize(b, sizeof(len) + len);
	if (!rc) {
		rc = buffer_putint32(b, len);
		rc = buffer_putbytes(b, in, len);
		LTRACEF("rc %d, in %s, len %d\n", rc, in, len);
	}
	return rc;
}

/*
 * @brief: retrieves string from buffer (string should be freed by user)
 */
int buffer_getstring(buffer_t *b, unsigned char **out)
{
	uint32_t len;
	unsigned char *str;
	int rc = buffer_checksize(b, sizeof(len));
	/* return error */
	if (rc) {
		return rc;
	}

	buffer_getint32( b, &len);
	rc = buffer_checksize(b, len);
	if (rc) {
		/*revert position */
		buffer_setpos(b, b->pos - sizeof(len));
		/* error */
		return rc;
	}
	LTRACEF("rc %d, len %d\n", rc, len);

	/* allocate memory */
	str = (unsigned char *)platform_calloc(len + 1);
	if (!str) {
		/*revert position */
		buffer_setpos(b, b->pos - sizeof(len));
		/* error */
		return -1;
	}

	/* copy string */
	memcpy(str, &b->data[b->pos], len);
	b->pos += len;
	*out = str;
	LTRACEF("rc %d, str %s\n", rc, str);

	/* */
	return rc;
}

/*
 * @brief: stores bytes array in buffer (len,string)
 */
int buffer_putblob(buffer_t *b, const unsigned char *in, uint32_t len)
{
	int rc = buffer_checksize(b, sizeof(len) + len);
	if(!rc) {
		rc = buffer_putint32(b, len);
		rc = buffer_putbytes(b, in, len);
		LTRACEF("rc %d, len %d\n", rc, len);
	}
	return rc;
}

/*
 * @brief: retrieves bytes array from buffer (should be freed by user)
 * @ret : -1 error, > 0 blob size
 */
uint32_t buffer_getblob(buffer_t *b, unsigned char **out)
{
	uint32_t len;
	unsigned char *blob;
	int rc = buffer_checksize(b, sizeof(len));
	/* return error */
	if (rc) {
		return rc;
	}

	buffer_getint32( b, &len);
	rc = buffer_checksize(b, len);
	if (rc) {
		/*revert position */
		buffer_setpos(b, b->pos - sizeof(len));
		/* error */
		return rc;
	}
	LTRACEF("rc %d, len %d\n", rc, len);

	/* allocate memory */
	blob = (unsigned char *)platform_calloc(len);
	if (!blob) {
		/*revert position */
		buffer_setpos(b, b->pos - sizeof(len));
		/* error */
		return -1;
	}

	/* copy array */
	memcpy(blob, &b->data[b->pos], len);
	b->pos += len;
	*out = blob;

	/* */
	return len;
}

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
 * Dropbear - a SSH2 server
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
#ifndef __BUFFER_H
#define __BUFFER_H

#include <sys/types.h>
#include <inttypes.h>
#include "platform.h"

typedef struct buffer_s {
	unsigned char *data;
	size_t pos;
	size_t len;
} buffer_t;

buffer_t *buffer_new(size_t size);
int buffer_free(buffer_t *b);
int buffer_resize(buffer_t *b, size_t size);
int buffer_setdata(buffer_t *b, unsigned char *data, size_t size);
int buffer_setpos(buffer_t *b, size_t pos);
int buffer_checksize(buffer_t *b, unsigned int size);
int buffer_putbyte(buffer_t *b, const unsigned char in);
int buffer_getbyte(buffer_t *b, unsigned char *out);
int buffer_putbytes(buffer_t *b, const unsigned char *in, uint32_t len);
int buffer_putint32(buffer_t *b, const uint32_t in);
int buffer_getint32(buffer_t *b, uint32_t *out);
int buffer_putstring(buffer_t *b, const unsigned char *in, uint32_t len);
int buffer_getstring(buffer_t *b, unsigned char **out);
int buffer_putblob(buffer_t *b, const unsigned char *in, uint32_t len);
uint32_t buffer_getblob(buffer_t *b, unsigned char **out);
#endif

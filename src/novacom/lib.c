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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <platform.h>
#include <novacom.h>
#include "novacom_p.h"

static char nduid[NOVACOM_NDUID_STRLEN];

void novacom_nduid_init(void)
{
	int i;

	for (i=0; i < NOVACOM_NDUID_CHRLEN; i++) {
		nduid[i] = "0123456789abcdef"[rand() & 0xf];
	}

	int fd;
	// if /proc/nduid doesn't exist, this will just fail through and leave the random nduid
	fd = open("/proc/nduid", O_RDONLY);
	if (fd >= 0) {
		i = read(fd, nduid, NOVACOM_NDUID_CHRLEN);	/*ignore return, fail through with random id*/
		close(fd);
	}
	nduid[NOVACOM_NDUID_CHRLEN] = 0;
}

char * novacom_nduid(void)
{
	return nduid;
}

int novacom_init(void)
{
	novacom_nduid_init();
	return novacom_mux_init();
}

uint32_t novacom_get_new_sessionid()
{
	uint32_t sid =rand();
	return sid;
}

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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <platform.h>
#include <novacom.h>
#ifndef WEBOS_TARGET_MACHINE_IMPL_HOST
#include <nyx/nyx_client.h>
#endif
#include "novacom_p.h"

static char nduid[NOVACOM_NDUID_STRLEN];

void novacom_nduid_init(void)
{
	int i;

	//initialize nduid for cases nyx-lib is not usable
	for (i=0; i < NOVACOM_NDUID_CHRLEN; i++) {
		nduid[i] = "0123456789abcdef"[rand() & 0xf];
	}
	nduid[NOVACOM_NDUID_CHRLEN] = '\0';

#ifndef WEBOS_TARGET_MACHINE_IMPL_HOST
	nyx_device_handle_t device = NULL;
	nyx_error_t error = NYX_ERROR_NONE;

	error = nyx_init();

	if(NYX_ERROR_NONE == error)
	{
		error = nyx_device_open(NYX_DEVICE_DEVICE_INFO, "Main", &device);

		if(NULL != device && NYX_ERROR_NONE == error)
		{
			// Error value left unchecked on purpose. If NDUID reading fails for
			// some reason, initialized value is used.
			(void) nyx_device_info_get_info(device, NYX_DEVICE_INFO_NDUID, nduid,
			                                NOVACOM_NDUID_STRLEN);

			nyx_device_close(device);
		}

		nyx_deinit();
	}

#endif // !WEBOS_TARGET_MACHINE_IMPL_HOST
}

const char * novacom_nduid(void)
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

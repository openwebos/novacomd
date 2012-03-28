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
#include <platform.h>
#include <fcntl.h>
#include <unistd.h>

void platform_init(void) 
{
	srand(time(NULL));
	platform_init_mutex();
	platform_init_socket();
}

void platform_init_socket(void)
{
}
int platform_checksuperuser(void) 
{
	return geteuid();
}

void platform_closeonexec(SOCKET fp)
{
	fcntl(fp, F_SETFD, FD_CLOEXEC);
}


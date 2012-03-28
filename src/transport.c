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

#include <transport.h>
#include <transport_usb.h>
#include <transport_inet.h>

// basic wrapper functions to init/start/stop each transport

int transport_init(void)
{
	if (novacom_usb_transport_init() < 0) 
		return -1;
	inetconnect_transport_init();
	inetlisten_transport_init();
	return 0;
}

int transport_start(void)
{
	novacom_usb_transport_start();
	inetconnect_transport_start();
	inetlisten_transport_start();
	return 0;
}

int transport_stop(void)
{
	novacom_usb_transport_stop();
	inetconnect_transport_stop();
	inetlisten_transport_stop();
	return 0;
}


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

#ifndef __TRANSPORT_USB_H
#define __TRANSPORT_USB_H

#include <novacom.h>
#include "transport.h"

int novacom_usb_transport_init(void);
int novacom_usb_transport_start(void);
int novacom_usb_transport_stop(void);
int novacom_usb_transport_deviceonline(char *nduid);
/* usb recovery */
int usbrecords_init( void );
int usbrecords_add(transport_recovery_token_t *t_token);
int usbrecords_find(transport_recovery_token_t *t_token);
int usbrecords_update(int elapsed);
int usbrecords_remove(char *nduid);

typedef struct novacom_usbll_state * novacom_usbll_handle_t;

novacom_usbll_handle_t novacom_usbll_create(const char *devtype, uint32_t max_mtu, int heartbeat_interval, int timeout);
void novacom_usbll_destroy(novacom_usbll_handle_t usbll_handle);
int novacom_usbll_prepare_tx_packet(novacom_usbll_handle_t usbll_handle, struct novacom_tx_packet *packet, int timeout);
void novacom_usbll_drop_offline(novacom_usbll_handle_t handle);
int novacom_usbll_process_packet(novacom_usbll_handle_t usbll_handle, const char *buf, unsigned int len);
uint32_t novacom_usbll_get_mtu(novacom_usbll_handle_t);
int novacom_usbll_get_timeout(novacom_usbll_handle_t);
char *novacom_usbll_get_nduid(novacom_usbll_handle_t);
int novacom_usbll_check_packet_header(const char *buf, unsigned int len);
int novacom_usbll_get_recovery_token(novacom_usbll_handle_t handle, transport_recovery_token_t *t_pToken);
int novacom_usbll_generate_recovery_token(const void *data, int len, transport_recovery_token_t *t_pToken);
void novacom_usbll_setuid(novacom_usbll_handle_t handle, uint32_t uid);
uint32_t novacom_usbll_getuid(novacom_usbll_handle_t handle);

int novacom_usbll_get_state(novacom_usbll_handle_t handle);
void novacom_usbll_changeback_state(novacom_usbll_handle_t handle, int state);


#endif


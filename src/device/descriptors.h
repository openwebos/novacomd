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

#ifndef __USB_DESCRIPTORS_H
#define __USB_DESCRIPTORS_H

#include <inttypes.h>

#define W(w) (w & 0xff), (w >> 8)

static const uint8_t dev_descr[] = {
    0x12,           /* descriptor length */
    0x01,           /* Device Descriptor type */
    W(0x0200),      /* USB Version */
    0x00,           /* class */
    0x00,           /* subclass */
    0x00,           /* protocol */
    0x40,           /* max packet size, ept0 */
    W(0x0830),      /* vendor */
    W(0x1000),      /* product */
    W(0x1000),      /* release */
    0x01,           /* manufacturer string */
    0x02,           /* product string */
    0x00,           /* serialno string */
    0x01,           /* num configs */
};

static const uint8_t devqual_descr[] = {
	0x0a,			/* len */
	0x06,			/* Device Qualifier type */
	W(0x0200),		/* USB version */
    0x00,           /* class */
    0x00,           /* subclass */
    0x00,           /* protocol */
    0x40,           /* max packet size, ept0 */
    0x01,           /* num configs */
	0x00			/* reserved */
};

static const uint8_t cfg_descr_lowspeed[] = {
    0x09,           /* Length of Cfg Descr */
    0x02,           /* Type of Cfg Descr */
    W(0x0020),      /* Total Length (incl ifc, ept) */
    0x01,           /* # Interfaces */
    0x01,           /* Cfg Value */
    0x00,           /* Cfg String */
    0xc0,           /* Attributes -- self powered */
    0,              /* Power Consumption - none */

    0x09,           /* Length of Ifc Descr */
    0x04,           /* Type of Ifc Descr */
    0x00,           /* Ifc Number */
    0x00,           /* Alt Number */
    0x02,           /* Ept Count */
    0xff,           /* Ifc Class - Vendor Specific */
    0x00,           /* Ifc Subclass */
    0x00,           /* Ifc Protocol */
    0x00,           /* Ifc String Index */
};


static const uint8_t ep1_descr_lowspeed[] = {
/* endpoint 1(in): data read endpoint */
    0x07,           /* Length of Ept Descr */
    0x05,           /* Type of Ept Descr */
    0x81,           /* Address 1:IN */
    0x02,           /* Type = BULK*/
    W(64),			/* MaxPkt = 64 */
    0x00,           /* Interval */
};

static const uint8_t ep2_descr_lowspeed[] = {
/* endpoint 2(out): data write endpoint */
    0x07,           /* Length of Ept Descr */
    0x05,           /* Type of Ept Descr */
    0x02,           /* Address 2:OUT */
    0x02,           /* Type = BULK */
    W(64),			/* MaxPkt = 64 */
    0x00,           /* Interval */
};

static const uint8_t cfg_descr_highspeed[] = {
    0x09,           /* Length of Cfg Descr */
    0x02,           /* Type of Cfg Descr */
    W(0x0020),      /* Total Length (incl ifc, ept) */
    0x01,           /* # Interfaces */
    0x01,           /* Cfg Value */
    0x00,           /* Cfg String */
    0xc0,           /* Attributes -- self powered */
    0,              /* Power Consumption - none */

    0x09,           /* Length of Ifc Descr */
    0x04,           /* Type of Ifc Descr */
    0x00,           /* Ifc Number */
    0x00,           /* Alt Number */
    0x02,           /* Ept Count */
    0xff,           /* Ifc Class - Vendor Specific */
    0x00,           /* Ifc Subclass */
    0x00,           /* Ifc Protocol */
    0x00,           /* Ifc String Index */
};

static const uint8_t ep1_descr_highspeed[] = {
/* endpoint 1(in): data read endpoint */
    0x07,           /* Length of Ept Descr */
    0x05,           /* Type of Ept Descr */
    0x81,           /* Address 1:IN */
    0x02,           /* Type = BULK*/
    W(512),			/* MaxPkt = 512 */
    0x00,           /* Interval */
};

static const uint8_t ep2_descr_highspeed[] = {
/* endpoint 2(out): data write endpoint */
    0x07,           /* Length of Ept Descr */
    0x05,           /* Type of Ept Descr */
    0x02,           /* Address 2:OUT */
    0x02,           /* Type = BULK */
    W(512),			/* MaxPkt = 512 */
    0x00,           /* Interval */
};

static const uint16_t dstring[] = {
    0x030e, /* numchars * 2 + 2 */
    'b', 'o', 'o', 't', 'i', 'e'
};

static const uint16_t mstring[] = {
    0x030a, /* numchars * 2 + 2 */
    'P', 'a', 'l', 'm'
};

static const uint16_t langid[] __attribute__((aligned((2)))) = { 0x04, 0x03, 0x09, 0x04 };

#endif


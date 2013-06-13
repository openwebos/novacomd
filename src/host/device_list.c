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
#include <stdint.h>
#include "device_list.h"

/* as devices get added, add to this list */
struct usb_device_table usbid_list[] = {
	{0x0830, 0x1000, "unknown-bootie"},  // legacy bootie usb interface
	/* castle */
	{0x0830, 0x0101, "castle-linux"},    // castle transition ethernet + disk mode + novacom
	{0x0830, 0x8001, "castle-bootie"},   // emu2/castle bootie
	{0x0830, 0x8002, "castle-linux"},    // emu2/castle linux mass storage + novacom
	{0x05AC, 0x0101, "castle-linux"},    // emu2/castle linux mass storage + novacom
	{0x05AC, 0x1209, "castle-linux"},    // emu2/pixie/castle media sync + novacom
	{0x05AC, 0x8002, "castle-linux"},    // emu2/castle linux mass storage + novacom
	{0x05AC, 0x8003, "castle-linux"},    // emu2/castle linux mass storage + novacom
	{0x05AC, 0x8004, "castle-linux"},    // emu2/castle linux mass storage + novacom
	{0x05AC, 0x8012, "castle-linux"},    // emu2/castle linux mass storage + novacom
	{0x0830, 0x8003, "castle-linux"},    // emu2/castle linux mass storage + serial + novacom
	{0x0830, 0x8004, "castle-linux"},    // emu2/castle linux mass storage + serial + novacom
	{0x0830, 0x8006, "castle-linux"},    // castle transition ethernet + disk mode + novacom
	{0x0830, 0x8007, "castle-linux"},    // emu2/castle linux USB passthru + novacom
	/* pixie */
	{0x0830, 0x8011, "pixie-bootie"},    // pixie bootie
	{0x0830, 0x8012, "pixie-linux"},     // pixie linux mass storage + novacom
	{0x0830, 0x8016, "pixie-linux"},     // pixie ethernet + mass storage + novacom
	{0x0830, 0x8017, "pixie-linux"},     // pixie USB passthru + novacom

	{0x0830, 0x0103, "pixie-linux"},     // pixie transition ethernet + disk mode + novacom		(to be removed)
	/* zepfloyd */
	{0x0830, 0xc001, "zepfloyd-bootie"}, // zepfloyd bootie
	{0x0830, 0xc002, "zepfloyd-linux"},  // zepfloyd linux mass storage + novacom

	/* product_id base 0x20 */
	{0x0830, 0x8021, ""},                // windsor bootie
	{0x0830, 0x8022, ""},                // windsor linux mass storage + novacom
	{0x0830, 0x8026, ""},                // windsor ethernet + mass storage + novacom
	{0x0830, 0x8027, ""},                // windsor USB Passthru + novacom

	{0x0830, 0x0105, ""},                // windsor transition ethernet + disk mode + novacom	(to be removed)

	/* product_id base 0x30 */
	{0x0830, 0x8031, ""},                // broadway bootie
	{0x0830, 0x8032, ""},                // broadway linux mass storage + novacom
	{0x0830, 0x8036, ""},                // broadway ethernet + mass storage + novacom
	{0x0830, 0x8037, ""},                // broadway USB Passthru + novacom

	{0x0830, 0x0107, ""},                // broadway transition ethernet + disk mode + novacom	(to be removed)

	/* product_id base 0x40 */
	{0x0830, 0x8041, ""},                // roadrunner bootie
	{0x0830, 0x8042, ""},                // roadrunner linux mass storage + novacom
	{0x0830, 0x8046, ""},                // roadrunner ethernet + mass storage + novacom
	{0x0830, 0x8047, ""},                // roadrunner USB Passthru + novacom

	/* product_id base 0x50 */           // Manta Ray
	{0x0830, 0x8051, ""},                // bootie
	{0x0830, 0x8052, ""},                // linux mass storage + novacom
	{0x0830, 0x8056, ""},                // ethernet + mass storage + novacom
	{0x0830, 0x8057, ""},                // USB Passthru + novacom

	/* product_id base 0x60 */           // Sting Ray
	{0x0830, 0x8061, ""},                // bootie
	{0x0830, 0x8062, ""},                // linux mass storage + novacom
	{0x0830, 0x8066, ""},                // ethernet + mass storage + novacom
	{0x0830, 0x8067, ""},                // USB Passthru + novacom

	/* product_id base 0x70 */           // Topaz
	{0x0830, 0x8071, ""},                // bootie
	{0x0830, 0x8072, ""},                // linux mass storage + novacom
	{0x0830, 0x8076, ""},                // ethernet + mass storage + novacom
	{0x0830, 0x8077, ""},                // USB Passthru + novacom

	/* product_id base 0x80 */           // WindsorNot
	{0x0830, 0x8081, ""},                // bootie
	{0x0830, 0x8082, ""},                // linux mass storage + novacom
	{0x0830, 0x8086, ""},                // ethernet + mass storage + novacom
	{0x0830, 0x8087, ""},                // USB Passthru + novacom

	/* product_id base 0x90 */           // ...
	{0x0830, 0x8091, ""},                // bootie
	{0x0830, 0x8092, ""},                // linux mass storage + novacom
	{0x0830, 0x8096, ""},                // ethernet + mass storage + novacom
	{0x0830, 0x8097, ""},                // USB Passthru + novacom

	/* HP product_id base 1x28 */        // HP ...
	{0x03F0, 0x1128, ""},                // bootie
	{0x03F0, 0x1228, ""},                // linux mass storage + novacom
	{0x03F0, 0x1628, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x1728, ""},                // USB Passthru + novacom

	{0x03F0, 0x1928, ""},                // bootie
	{0x03F0, 0x1a28, ""},                // linux mass storage + novacom
	{0x03F0, 0x1e28, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x1f28, ""},                // USB Passthru + novacom

	/* HP product_id base 2x28 */        // HP ...
	{0x03F0, 0x2128, ""},                // bootie
	{0x03F0, 0x2228, ""},                // linux mass storage + novacom
	{0x03F0, 0x2628, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x2728, ""},                // USB Passthru + novacom

	{0x03F0, 0x2928, ""},                // bootie
	{0x03F0, 0x2a28, ""},                // linux mass storage + novacom
	{0x03F0, 0x2e28, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x2f28, ""},                // USB Passthru + novacom

	/* HP product_id base 3x28 */        // HP ...
	{0x03F0, 0x3128, ""},                // bootie
	{0x03F0, 0x3228, ""},                // linux mass storage + novacom
	{0x03F0, 0x3628, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x3728, ""},                // USB Passthru + novacom

	{0x03F0, 0x3928, ""},                // bootie
	{0x03F0, 0x3a28, ""},                // linux mass storage + novacom
	{0x03F0, 0x3e28, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x3f28, ""},                // USB Passthru + novacom

	/* HP product_id base 4x28 */        // HP ...
	{0x03F0, 0x4128, ""},                // bootie
	{0x03F0, 0x4228, ""},                // linux mass storage + novacom
	{0x03F0, 0x4628, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x4728, ""},                // USB Passthru + novacom

	{0x03F0, 0x4928, ""},                // bootie
	{0x03F0, 0x4a28, ""},                // linux mass storage + novacom
	{0x03F0, 0x4e28, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x4f28, ""},                // USB Passthru + novacom

	/* HP product_id base 4x28 */        // HP ...
	{0x03F0, 0x5128, ""},                // bootie
	{0x03F0, 0x5228, ""},                // linux mass storage + novacom
	{0x03F0, 0x5628, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x5728, ""},                // USB Passthru + novacom

	{0x03F0, 0x5928, ""},                // bootie
	{0x03F0, 0x5a28, ""},                // linux mass storage + novacom
	{0x03F0, 0x5e28, ""},                // ethernet + mass storage + novacom
	{0x03F0, 0x5f28, ""},                // USB Passthru + novacom

	/* new device */

	/* end of list */
	{0, 0, NULL}
};


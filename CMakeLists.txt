# @@@LICENSE
#
#      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

#
# novacomd/CMakeLists.txt
#

cmake_minimum_required(VERSION 2.8.7)
project(novacomd C)

include(webOS/webOS)
include(FindPkgConfig)

webos_modules_init(1 0 0 QUALIFIER RC4)
webos_component(2 0 0)
webos_machine_impl_dep()

add_definitions(-DBUILDVERSION="${WEBOS_COMPONENT_VERSION}")
webos_add_compiler_flags(ALL -DPLATFORM_PTHREADS=1)
webos_add_compiler_flags(ALL -Wall -g -O2)

include_directories(include)

file(GLOB lib_files src/lib/*.c)
file(GLOB cksum_files src/lib/cksum/*.c)
file(GLOB novacom_files src/novacom/*.c)

# Device and host have different sources
if(${WEBOS_TARGET_MACHINE_IMPL} STREQUAL host)
	file(GLOB target_files src/host/*.c)
	webos_add_compiler_flags(ALL -DHOST=1)
	set(upstartfile files/launch/host/novacomd)
else()
	webos_machine_dep()
	file(GLOB target_files src/device/*.c)
	list(APPEND target_files src/platform_pthreads.c)
	webos_add_compiler_flags(ALL -DDEVICE=1)
	add_definitions(-DMACHINE="${WEBOS_TARGET_MACHINE}")
	set(upstartfile files/launch/device/novacomd)
endif()

# device build gets ${device_files} and src/platform_pthreads.c
# host build gets src/host files (see makefile)
add_executable(novacomd ${lib_files}
                        ${cksum_files}
                        ${novacom_files}
                        ${target_files}
                        src/platform_pthreads.c
                        src/main.c src/log.c src/socket.c
                        src/transport.c
                        src/transport_inet.c
                        src/transport_usb.c)


# Link against the libusb of host system when building standalone
if(${WEBOS_TARGET_MACHINE_IMPL} STREQUAL host)
	pkg_check_modules(LIBUSB REQUIRED libusb)
	include_directories(${LIBUSB_INCLUDE_DIRS})
	webos_add_compiler_flags(ALL ${LIBUSB_CFLAGS_OTHER})
	target_link_libraries(novacomd ${LIBUSB_LIBRARIES})
endif()

target_link_libraries(novacomd pthread)
target_link_libraries(novacomd rt)

webos_build_daemon(NAME novacomd LAUNCH ${upstartfile} ROOTFS RESTRICTED_PERMISSIONS)

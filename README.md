novacomd
========

Summary
-------
Utility to communicate with a target device over USB or TCP/IP

Description
-----------
_novacom_ and _novacomd_ provide a generic toolset to allow communication
between a host and an embedded device using sockets over USB. If there is a
TCP/IP network connection between the two, it can be used instead.

How to build
===========

## Dependencies

Below are the tools and libraries (and their minimum versions) required to
build _novacomd_:

- cmake (version required by openwebos/cmake-modules-webos)
- gcc 4.6.3
- glib-2.0 2.32.1
- libusb 1.0.0 (needed only for the host build)
- openwebos/cmake-modules-webos 1.0.0 RC4
- openwebos/nyx-lib 3.0.0 RC1 (needed only for non-host builds)
- pkg-config 0.26

## Building

Once you have downloaded the source, enter the following to build it (after
changing into the directory under which it was downloaded):

    $ mkdir BUILD
    $ cd BUILD
    $ cmake ..
    $ make
    $ sudo make install

The directory under which the files are installed defaults to `/usr/local/webos`.
You can install them elsewhere by supplying a value for `WEBOS_INSTALL_ROOT`
when invoking `cmake`. For example:

    $ cmake -D WEBOS_INSTALL_ROOT:PATH=$HOME/projects/openwebos ..
    $ make
    $ make install

will install the files in subdirectories of `$HOME/projects/openwebos`.

Specifying `WEBOS_INSTALL_ROOT` also causes `pkg-config` to look in that tree
first before searching the standard locations. You can specify additional
directories to be searched prior to this one by setting the `PKG_CONFIG_PATH`
environment variable.

If not specified, `WEBOS_INSTALL_ROOT` defaults to `/usr/local/webos`.

To build the version of _novacomd_ suitable for running on the host system (for
use in communicating with a device), define `WEBOS_TARGET_MACHINE_IMPL` as `host`:
    $ cmake -D WEBOS_TARGET_MACHINE_IMPL:STRING=host ..

Note that this generates a Makefile that installs the files in the same
locations as the non-host build.

To configure for a debug build, enter:

    $ cmake -D CMAKE_BUILD_TYPE:STRING=Debug ..

To see a list of the make targets that `cmake` has generated, enter:

    $ make help

## Uninstalling

From the directory where you originally ran `make install`, enter:

    $ [sudo] make uninstall

You will need to use `sudo` if you did not specify `WEBOS_INSTALL_ROOT`.

# Copyright and License Information

Unless otherwise specified, all content, including all source code files and
documentation files in this repository are:

Copyright (c) 2008-2013 LG Electronics, Inc.

Unless otherwise specified or set forth in the NOTICE file, all content,
including all source code files and documentation files in this repository are:
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

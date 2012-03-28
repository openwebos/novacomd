#/* @@@LICENSE
#*
#*      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
#*
#* Licensed under the Apache License, Version 2.0 (the "License");
#* you may not use this file except in compliance with the License.
#* You may obtain a copy of the License at
#*
#* http://www.apache.org/licenses/LICENSE-2.0
#*
#* Unless required by applicable law or agreed to in writing, software
#* distributed under the License is distributed on an "AS IS" BASIS,
#* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#* See the License for the specific language governing permissions and
#* limitations under the License.
#*
#* LICENSE@@@ */
TARGET := novacomd
BUILDDIR = build-$(TARGET)


# pull in the build version from OE if it's set
ifneq ($(BUILDVERSION),)
BUILDVERSION := \"$(TARGET)-$(BUILDVERSION)\"
else
BUILDVERSION ?= \"..local..$(shell whoami)@$(shell hostname)..$(shell date +%Y%m%d..%H:%M:%S)\"
endif

# overriding build version if it is building off of phoenix
ifneq ($(NC_SUBMISSION_NUMBER),)
BUILDVERSION := \"novacomd-$(NC_SUBMISSION_NUMBER)\"
endif


# compiler flags, default libs to link against
MYCFLAGS := -Wall -W -Wno-multichar -Wno-unused-parameter -Wno-unused-function -g -O2 -Iinclude -DBUILDVERSION=$(BUILDVERSION) 
# pull in the machine build name version from OE if it's set
ifneq ($(MACHINE),)
MYCFLAGS += -DMACHINE=\"$(MACHINE)\"
endif
HOSTCFLAGS := $(MYCFLAGS) -Isrc
DEVICECFLAGS := $(MYCFLAGS) $(OECFLAGS) $(TARGET_CC_ARCH) -DPLATFORM_PTHREADS=1
CPPFLAGS := -g
ASMFLAGS :=
LDFLAGS := 
ENVP:=

HOSTLDLIBS :=
DEVICELDLIBS := -lpthread -lrt

UNAME := $(shell uname -s)
ARCH := $(shell uname -m)

# this may be overridden by OE, though it's likely to be the same
ifneq ($(TARGET_PREFIX),)
DEVICECC := $(TARGET_PREFIX)gcc
DEVICELD := $(TARGET_PREFIX)ld
else
DEVICECC := arm-none-linux-gnueabi-gcc
DEVICELD := arm-none-linux-gnueabi-ld
endif


ifeq ($(UNAME),Linux)
LDFLAGS += -Wl,-rpath,. # add the local path to the program's search path
HOSTLDLIBS += -lpthread -lusb
HOSTPLATFORM := pthreads
HOSTOS := linux
endif

COMMONOBJS := \
	src/main.o \
	src/log.o \
	src/socket.o \
	src/transport.o \
	src/transport_inet.o \
	src/transport_usb.o \
\
	src/novacom/lib.o \
	src/novacom/mux.o \
	src/novacom/packet.o \
	src/novacom/buf_queue.o \
	src/novacom/commands.o \
	src/novacom/commands_device.o \
\
	src/lib/cksum/adler32.o \
	src/lib/cksum/sha1.o \
	src/lib/buffer.o

DEVICEOBJS := \
	$(COMMONOBJS) \
	src/platform_pthreads.o \
	src/device/usb-gadget.o \
	src/device/auth.o \
	src/device/commands_service.o

HOSTOBJS := \
	$(COMMONOBJS) \
	src/host/device_list.o \
	src/host/usb-$(HOSTOS).o \
	src/host/tokenstorage.o \
	src/host/commands_service.o \
	src/host/recovery.o

# do some work based on the host platform
ifeq ($(HOSTPLATFORM), pthreads)
HOSTOBJS += \
	src/platform_pthreads.o
HOSTCFLAGS += -DPLATFORM_PTHREADS=1
endif

HOSTOBJS := $(addprefix $(BUILDDIR)-host/,$(HOSTOBJS))
DEVICEOBJS := $(addprefix $(BUILDDIR)-device/,$(DEVICEOBJS))

DEPS := $(OBJS:.o=.d) $(HOSTOBJS:.o=.d) $(DEVICEOBJS:.o=.d)

.PHONY: device host all

all: host device

device: $(BUILDDIR)-device/$(TARGET)

host: $(BUILDDIR)-host/$(TARGET)

$(BUILDDIR)-host/$(TARGET): $(HOSTOBJS)
	@echo HOST linking $@
	@${ENVP} $(CC) $(LDFLAGS) $(HOSTOBJS) -o $@ $(HOSTLDLIBS)

$(BUILDDIR)-device/$(TARGET): $(DEVICEOBJS)
	@echo DEV linking $@
	@$(DEVICECC) $(LDFLAGS) $(DEVICEOBJS) -o $@ $(DEVICELDLIBS)

.PHONY: clean
clean:
	rm -f $(HOSTOBJS) $(DEVICEOBJS) $(DEPS) $(BUILDDIR)-host/$(TARGET) $(BUILDDIR)-device/$(TARGET)

.PHONY: spotless
spotless:
	rm -rf build-*

# makes sure the target dir exists
MKDIR = if [ ! -d $(dir $@) ]; then mkdir -p $(dir $@); fi

$(BUILDDIR)-host/%.o: %.c
	@$(MKDIR)
	@echo HOST compiling $<
	@${ENVP} $(CC) -DHOST=1 $(HOSTCFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

$(BUILDDIR)-host/%.o: %.cpp
	@$(MKDIR)
	@echo HOST compiling $<
	@${ENVP} $(CC) -DHOST=1 $(HOSTCPPFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

$(BUILDDIR)-host/%.o: %.S
	@$(MKDIR)
	@echo HOST compiling $<
	@${ENVP} $(CC) -DHOST=1 $(HOSTASMFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

$(BUILDDIR)-device/%.o: %.c
	@$(MKDIR)
	@echo DEV compiling $<
	@$(DEVICECC) -DDEVICE=1 $(DEVICECFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

$(BUILDDIR)-device/%.o: %.cpp
	@$(MKDIR)
	@echo DEV compiling $<
	@$(DEVICECC) -DDEVICE=1 $(DEVICECPPFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

$(BUILDDIR)-device/%.o: %.S
	@$(MKDIR)
	@echo DEV compiling $<
	@$(DEVICECC) -DDEVICE=1 $(DEVICEASMFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

ifeq ($(filter $(MAKECMDGOALS), clean), )
-include $(DEPS)
endif

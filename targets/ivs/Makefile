################################################################
#
#        Copyright 2013, Big Switch Networks, Inc.
#
# Licensed under the Eclipse Public License, Version 1.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#        http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.
#
################################################################
include ../../init.mk

ALLOW_DECLARATION_AFTER_STATEMENT = 1

#
# Defining a module and including standardinit.mk
# initializes the basic build infrastructure, setting
# it up to build "stuff" -- libraries, binaries, objects, etc. 
# 
MODULE := IVS
include $(BUILDER)/standardinit.mk

#
# We're now ready to specify the "stuff" we want built. 
#
# First, define a library for our local sources (main.c)
#
LIBRARY := IVSMain
$(LIBRARY)_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/lib.mk

#
# Set the modules we want to automatically build for this binary
#
DEPENDMODULES := SocketManager OFConnectionManager2 OFStateManager OVSDriver \
                 Configuration loci indigo BigList BigHash ivs_common pipeline pipeline_standard tcam xbuf \
                 PPE IOF \
                 AIM murmur cjson OS uCli debug_counter timer_wheel bloom_filter BigRing minimatch action \
                 stats pipeline_reflect shared_debug_counter packet_trace slot_allocator

ifndef NO_LUAJIT
DEPENDMODULES += luajit pipeline_lua
GLOBAL_CFLAGS += -DHAVE_LUAJIT=1
LDFLAGS += -rdynamic
GLOBAL_LINK_LIBS += -ldl
endif

#
# Resolve module dependencies
#
include $(BUILDER)/dependmodules.mk


#
# Now define the LRI application binary target. 
# This should come after all of the library dependencies
# specified above:
#
BINARY := ivs

# 
# This binary is going to link against every library we've included thus far.
# $(LIBRARY_TARGETS) is kept by the Builder and specifies every
# library already defined, either through local definitions or
# module dependencies. 
#
$(BINARY)_LIBRARIES := $(LIBRARY_TARGETS) 
include $(BUILDER)/bin.mk


#
# Now that we've specified all the things we want to build, 
# finalize with target definitions. 
#
include $(BUILDER)/targets.mk


# Enable uCLI
GLOBAL_CFLAGS += $(foreach mod,$(DEPENDMODULES_UPPER),-D$(mod)_CONFIG_INCLUDE_UCLI=1)


# These indicate Linux specific implementations to be used for
# various features
GLOBAL_CFLAGS += -DINDIGO_LINUX_LOGGING
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_FAULT_ON_ASSERT
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_PVS_SYSLOG=1
GLOBAL_CFLAGS += -DAIM_CONFIG_LOG_INCLUDE_ENV_VARIABLES=0
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_GNU_SOURCE=1
GLOBAL_CFLAGS += -DSOCKETMANAGER_CONFIG_MAX_TIMERS=512
GLOBAL_CFLAGS += -DSOCKETMANAGER_CONFIG_MAX_SOCKETS=4096
GLOBAL_CFLAGS += -DBIGRING_CONFIG_INCLUDE_LOCKING=0
GLOBAL_CFLAGS += -g
GLOBAL_CFLAGS += -I .
GLOBAL_CFLAGS += -I $(ROOT)/openvswitch
GLOBAL_CFLAGS += -fno-omit-frame-pointer

ifeq ($(RELEASE),1)
GLOBAL_CFLAGS += -DNDEBUG=1
GLOBAL_CFLAGS += -O2
else
#GLOBAL_CFLAGS += -DOF_WIRE_BUFFER_DEBUG
#GLOBAL_CFLAGS += -DOF_OBJECT_TRACKING
GLOBAL_CFLAGS += -O1
endif

ifdef LRI_DEBUG_LEVEL
GLOBAL_CFLAGS += -DLRI_DEBUG_LEVEL=${LRI_DEBUG_LEVEL}
endif

ifdef OF_CXN_DUMP_ALL_OBJECTS
GLOBAL_CFLAGS += -DOF_CXN_DUMP_ALL_OBJECTS
endif

ifdef PROFILE_GENERATE
export CCACHE_DISABLE=1
GLOBAL_CFLAGS += -fprofile-generate
LDFLAGS += -fprofile-generate
endif

ifdef PROFILE_USE
export CCACHE_DISABLE=1
GLOBAL_CFLAGS += -fprofile-use -fprofile-correction
LDFLAGS += -fprofile-use -fprofile-correction
endif

GLOBAL_LINK_LIBS += -lpthread -lrt -lm -lcap

LIBNL_CFLAGS := $(shell pkg-config --cflags libnl-3.0)
LIBNL_CFLAGS += $(shell pkg-config --cflags --silence-errors libnl-genl-3.0)
LIBNL_CFLAGS += $(shell pkg-config --cflags --silence-errors libnl-route-3.0)
LIBNL_LIBS := $(shell pkg-config --libs libnl-3.0)
LIBNL_LIBS += $(shell pkg-config --libs --silence-errors libnl-genl-3.0)
LIBNL_LIBS += $(shell pkg-config --libs --silence-errors libnl-route-3.0)
GLOBAL_CFLAGS += $(LIBNL_CFLAGS)
GLOBAL_LINK_LIBS += $(LIBNL_LIBS)

ifdef BUILD_ID
GLOBAL_CFLAGS += "-DBUILD_ID=$(BUILD_ID)"
endif

ifdef BUILD_OS
GLOBAL_CFLAGS += "-DBUILD_OS=$(BUILD_OS)"
endif


ucli:
	$(INDIGO)/Tools/uclihandlers.py ucli.c

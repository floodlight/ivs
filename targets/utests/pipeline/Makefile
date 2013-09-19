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

###############################################################################
#
#  pipeline Unit Testing Module Makefile
#
#
#
###############################################################################
MODULE := pipeline_utest
NOMODULEMAKE := 1
TEST_MODULE :=  pipeline
DEPENDMODULES := AIM indigo xbuf OVSDriver loci flowtable SocketManager OFStateManager murmur cjson Configuration BigList OFConnectionManager
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_POSIX=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DINDIGO_LINUX_LOGGING
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_FAULT_ON_ASSERT
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_PVS_SYSLOG=1
GLOBAL_CFLAGS += -DAIM_CONFIG_LOG_INCLUDE_ENV_VARIABLES=0
GLOBAL_CFLAGS += -D_BSD_SOURCE
#OS_MAKE_CONFIG_AUTOSELECT := 1
#PEDANTIC := 1

# Disable uCLI
GLOBAL_CFLAGS += $(foreach mod,$(DEPENDMODULES_UPPER),-D$(mod)_CONFIG_INCLUDE_UCLI=0)


GLOBAL_LINK_LIBS += -lpthread -lrt -lm

LIBNL_CFLAGS := $(shell pkg-config --cflags libnl-3.0)
LIBNL_CFLAGS += $(shell pkg-config --cflags --silence-errors libnl-genl-3.0)
LIBNL_CFLAGS += $(shell pkg-config --cflags --silence-errors libnl-route-3.0)
LIBNL_LIBS := $(shell pkg-config --libs libnl-3.0)
LIBNL_LIBS += $(shell pkg-config --libs --silence-errors libnl-genl-3.0)
LIBNL_LIBS += $(shell pkg-config --libs --silence-errors libnl-route-3.0)
GLOBAL_CFLAGS += $(LIBNL_CFLAGS)
GLOBAL_LINK_LIBS += $(LIBNL_LIBS)

GLOBAL_CFLAGS += -I $(ROOT)/openvswitch

include ../make/utestmodule.mk

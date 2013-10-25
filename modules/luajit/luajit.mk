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

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
LUAJIT := $(THIS_DIR)/../../submodules/luajit-2.0
luajit_INCLUDES := -I $(LUAJIT)/src

LIBRARY_TARGETS += libluajit.a

.PHONY: libluajit.a
libluajit.a:
	$(MAKE) -C $(LUAJIT)/src libluajit.a LJCORE_O=ljamalg.o BUILDMODE=static
	cp $(LUAJIT)/src/libluajit.a $(LIBRARY_DIR)/libluajit.a

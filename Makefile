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

IVS_BUILD := targets/ivs/build/gcc-local
IVS_CTL_BUILD := targets/ivs-ctl/build/gcc-local

all:
	make -C targets/ivs
	make -C targets/ivs-ctl

install: all
	install -D $(IVS_BUILD)/bin/ivs $(DESTDIR)/usr/sbin/ivs
	install -D $(IVS_CTL_BUILD)/bin/ivs-ctl $(DESTDIR)/usr/sbin/ivs-ctl

clean:
	make -C targets/ivs clean
	make -C targets/ivs-ctl clean
	# The build system creates these even during make clean
	rm -f modules/OVSDriver/OVSDriver.mk targets/ivs-ctl/IVSCtl.mk targets/ivs/Manifest.mk targets/ivs/IVS.mk targets/ivs/dependmodules.x
	(cd indigo; rm -f modules/AIM/AIM.mk modules/BigData/BigList/BigList.mk modules/ELS/ELS.mk modules/FME/FME.mk modules/IOF/IOF.mk modules/IVS/IVS.mk modules/Indigo/OFConnectionManager/OFConnectionManager.mk modules/Indigo/OFStateManager/OFStateManager.mk modules/Indigo/SocketManager/SocketManager.mk modules/Indigo/indigo/indigo.mk modules/NSS/NSS.mk modules/PPE/PPE.mk modules/loci/loci.mk modules/murmur/murmur.mk modules/uCli/uCli.mk)

deb:
	fakeroot make -f debian/rules binary

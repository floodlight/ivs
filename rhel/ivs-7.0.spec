# Spec file for Indigo Virtual Switch.
#
# Copyright 2014, Big Switch Networks, Inc.
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

Name: ivs
Summary: Indigo Virtual Switch
URL: http://www.bigswitch.com/
Version: 0.5
Release: 1%{?dist}

License: EPL-1.0
Source: ivs.tar.gz

Requires(post):  systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
Indigo Virtual Switch (IVS) is a pure OpenFlow virtual switch designed for high
performance and minimal administration. It is built on the [Indigo
platform][1], which provides a common core for many physical and virtual switches,

[1]: http://www.projectfloodlight.org/indigo/

%prep
(cd "$RPM_BUILD_DIR" && rm -rf *)
tar -xvf $RPM_SOURCE_DIR/ivs.tar.gz 

%build
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
install -d -m 755 $RPM_BUILD_ROOT/etc
install -p -D -m 0644 rhel/ivs.service \
        $RPM_BUILD_ROOT%{_unitdir}/ivs.service
install -d -m 755 $RPM_BUILD_ROOT/etc/sysconfig
install -p -D -m 0644 debian/ivs.default \
        $RPM_BUILD_ROOT/etc/sysconfig/ivs
install -p -D -m 0644 targets/ivs/ivs.8 \
        $RPM_BUILD_ROOT/usr/share/man/man8/ivs.8.gz
install -p -D -m 0644 targets/ivs-ctl/ivs-ctl.8 \
        $RPM_BUILD_ROOT/usr/share/man/man8/ivs-ctl.8.gz

# Get rid of stuff we don't want to make RPM happy.
(cd "$RPM_BUILD_ROOT" && rm -f usr/lib/lib*)

%clean
rm -rf $RPM_BUILD_ROOT

%preun
# Package removal, not upgrade
systemctl stop ivs.service
systemctl disable ivs.service

%post
# Initial installation
lsmod | grep -q openvswitch || modprobe openvswitch
systemctl enable ivs.service
systemctl start ivs.service

%files
%defattr(-,root,root)
%config /etc/sysconfig/ivs
%{_unitdir}/ivs.service
/usr/sbin/ivs
/usr/sbin/ivs-ctl
%doc /usr/share/man/man8/ivs.8.gz
%doc /usr/share/man/man8/ivs-ctl.8.gz

%changelog
* Tue Sep 9 2014 Harshmeet Singh <harshmeet.singh@bigswitch.com>
- First build on Centos 7.0 

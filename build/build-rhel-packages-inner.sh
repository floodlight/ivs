#!/bin/bash -eux
SPEC="/rpmbuild/SOURCES/ivs-7.0.spec"

# RPM runs as root and doesn't like source files owned by a random UID
OUTER_UID=$(stat -c '%u' $SPEC)
OUTER_GID=$(stat -c '%g' $SPEC)
trap "chown -R $OUTER_UID:$OUTER_GID /rpmbuild" EXIT
export PATH=/usr/lib64/ccache:$PATH
chown -R root:root /rpmbuild

ln -s /rpmbuild /root/rpmbuild
rpmbuild -bb $SPEC

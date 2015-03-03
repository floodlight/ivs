#!/bin/bash -eux
################################################################
#
#        Copyright 2015, Big Switch Networks, Inc.
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

ROOTDIR=$(dirname $(readlink -f $0))/..
cd "$ROOTDIR"

: Build ID: ${BUILD_ID:=devel}

BUILDDIR=$(mktemp -d)

mkdir -p $BUILDDIR/SOURCES $BUILDDIR/RPMS

# Copy source code to a volume that will be mounted in the container
cp build/build-rhel-packages-inner.sh $BUILDDIR/build-rhel-packages-inner.sh
cp rhel/ivs-7.0.spec $BUILDDIR/SOURCES
./build/files.sh | tar -T- -c -z -f $BUILDDIR/SOURCES/ivs.tar.gz --transform 's,^,ivs/,'

docker.io run -v $BUILDDIR:/rpmbuild bigswitch/ivs-builder:centos7 /rpmbuild/build-rhel-packages-inner.sh

# Copy built RPMs to pkg/
OUTDIR=$(readlink -m "pkg/centos7-x86_64/$BUILD_ID")
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
mv $BUILDDIR/RPMS/x86_64/*.rpm "$OUTDIR"
git log > "$OUTDIR/gitlog.txt"
touch "$OUTDIR/build-$BUILD_ID"
ln -snf $(basename $OUTDIR) $OUTDIR/../latest

rm -rf "$BUILDDIR"

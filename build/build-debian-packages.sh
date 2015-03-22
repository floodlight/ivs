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
SUITE=trusty
ARCH=amd64
DOCKER_IMAGE=bigswitch/ivs-builder:ubuntu14.04
BUILD_OS="$SUITE-$ARCH"

BUILDDIR=$(mktemp -d)

mkdir -p $BUILDDIR/ivs

# Copy source code to a volume that will be mounted in the container
#cp build/build-debian-packages-inner.sh $BUILDDIR/build-debian-packages-inner.sh
rsync --files-from <(./build/files.sh) . "$BUILDDIR/ivs"

docker.io run -e BUILD_ID=$BUILD_ID -e BUILD_OS=$BUILD_OS -v $BUILDDIR:/work -w /work/ivs $DOCKER_IMAGE ./build/build-debian-packages-inner.sh

# Copy built packages to pkg/
OUTDIR=$(readlink -m "pkg/$BUILD_OS/$BUILD_ID")
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
mv $BUILDDIR/*.deb "$OUTDIR"
git log > "$OUTDIR/gitlog.txt"
touch "$OUTDIR/build-$BUILD_ID"
ln -snf $(basename $OUTDIR) $OUTDIR/../latest

rm -rf "$BUILDDIR"

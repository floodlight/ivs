#!/bin/bash -ex
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

if [ -f /etc/debian_version ]; then
    : Suite: ${SUITE:=$(lsb_release -sc)}
    : Arch: ${ARCH:=$(dpkg --print-architecture)}
else
    : Suite: ${SUITE:=oneiric}
    : Arch: ${ARCH:=i386}
fi

BASEPATH="/var/cache/pbuilder/base-${SUITE}-${ARCH}.cow"
BUILD=$(date +'%F.%R%z')-$(git rev-parse -q --short HEAD)
OUTDIR=$(readlink -m "pkg/$SUITE-$ARCH/$BUILD")

if [ ! -d ${BASEPATH} ]; then
    sudo cowbuilder --create \
                    --basepath ${BASEPATH} \
                    --distribution ${SUITE} \
                    --debootstrapopts --arch --debootstrapopts ${ARCH} \
                    --components "main universe"
fi

rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"

REPO=$PWD
COPY=`mktemp -d`

./build/files.sh > "$COPY/files"
rsync --files-from="$COPY/files" . "$COPY"

cd "$COPY"
./build/setup.sh

pdebuild --pbuilder cowbuilder \
         --architecture "$ARCH" \
         --buildresult "$OUTDIR" \
         -- \
         --distribution "$SUITE" \
         --basepath "$BASEPATH"

cd -
rm -rf "$COPY"
git log > "$OUTDIR/gitlog.txt"
touch "$OUTDIR/build-$BUILD"

ln -snf $(basename $OUTDIR) $OUTDIR/../latest

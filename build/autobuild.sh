#!/bin/bash -eu
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

ROOTDIR=$(dirname $(readlink -f $0))/..
cd "$ROOTDIR"
BSC=../bigswitchcontroller

# TODO the test db scripts need to be factored out of bigswitchcontroller
if [ ! -d "$BSC" ]; then
  echo "missing $BSC"
  exit 1
fi

# TODO report commits to build status page
echo "+++ Last 10 commits:"
git log -n 10 --stat | cat

echo "+++ Starting build"
[ "${ABAT_TASK-}" ] && "$BSC/build/update-build-info.py" "$ABAT_TASK" "$ABAT_ID" "$ABAT_TIMESTAMP-$ABAT_TASK"
build/setup.sh
build/precheckin.py

echo "+++ Build finished"

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

export VALGRIND_OPTIONS="--tool=callgrind --cache-sim=yes --branch-sim=yes --dump-instr=yes --callgrind-out-file=profile.kcg"
trap "{ sudo chmod a+r profile.kcg; echo Output left in profile.kcg; }" EXIT
$(dirname $(readlink -f $0))/ivs-valgrind.sh "$@"

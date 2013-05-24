#!/bin/bash
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

# Run this script after git clone or pull.
ROOTDIR=$(dirname $(readlink -f $0))/..
cd "$ROOTDIR"

APT_GET="sudo DEBIAN_FRONTEND=noninteractive apt-get -q -y"

# Run these only if part of git tree
if [ -d ".git" ]; then
    git submodule init
    git submodule update

    # Show whitespace errors in git diff
    git config core.whitespace "trailing-space,space-before-tab"

    # Convert newlines to LF on commit, regardless of OS
    # (see http://help.github.com/dealing-with-lineendings/)
    git config core.autocrlf input

    # Include original text in conflict markers, as well as theirs and ours
    git config merge.conflictstyle diff3

    # Install our hooks
    for hook in .hooks/*; do
        ln -sf "../../$hook" .git/hooks/
    done
fi

if ! python -c 'import pcap' &> /dev/null; then
    echo "Installing python-pypcap"
    $APT_GET install python-pypcap
fi

if ! which cowbuilder &> /dev/null; then
    echo "Installing cowbuilder"
    $APT_GET install cowbuilder
fi

# libnl packaging changed between oneiric and precise
if [ $(lsb_release -sc) \< precise ]; then
    if ! pkg-config --exists libnl-3.0; then
        echo "Installing libnl"
        $APT_GET install libnl3-dev
    fi
else
    if ! pkg-config --exists libnl-3.0 libnl-route-3.0 libnl-genl-3.0; then
        echo "Installing libnl"
        $APT_GET install libnl-3-dev libnl-route-3-dev libnl-genl-3-dev
    fi
fi

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

BASEDIR := $(dir $(lastword $(MAKEFILE_LIST)))
OVSDriver_BASEDIR := $(BASEDIR)/OVSDriver
flowtable_BASEDIR := $(BASEDIR)/flowtable
l2table_BASEDIR := $(BASEDIR)/l2table
luajit_BASEDIR := $(BASEDIR)/luajit
xbuf_BASEDIR := $(BASEDIR)/xbuf
pipeline_BASEDIR := $(BASEDIR)/pipeline
ivs_common_BASEDIR := $(BASEDIR)/ivs

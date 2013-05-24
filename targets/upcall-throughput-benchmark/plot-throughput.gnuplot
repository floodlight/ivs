#!/usr/bin/env gnuplot
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

# Set OUTPUT_FILENAME=upcall-throughput.data when running upcall-throughput-benchmark,
# then run this script to plot the throughput over time. Any files matching
# upcall-throughput*.data will be graphed.

# Uncomment these (and comment out the pause at the bottom) to render to a file
#set terminal pngcairo enhanced font "arial,10" size 500, 350
#set output 'upcall-throughtput.png'

set title "Upcall Throughput"
set xlabel "Time (s)"
set ylabel "upcall/s"

set yrange[0:]

filenames = system("echo upcall-throughput*.data")
plot for [filename in filenames] filename title filename with lines
pause -1

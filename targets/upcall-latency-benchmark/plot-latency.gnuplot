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

# Set OUTPUT_FILENAME=upcall-latency.data when running upcall-latency-benchmark,
# then run this script to plot the latencies as a histogram. Any files matching
# upcall-latency*.data will be graphed.

# Uncomment these (and comment out the pause at the bottom) to render to a file
#set terminal pngcairo enhanced font "arial,10" size 500, 350
#set output 'upcall-latency-histogram.png'

set title "Upcall Latency Histogram"
set xlabel "Latency (nanoseconds, bucket size 500ns)"
set ylabel "#"

set style histogram clustered gap 5
set style fill solid 1
set xrange[10000:30000]
set boxwidth 249

binwidth=500
bin(x,width)=width*floor(x/width) + binwidth/2.0

filenames = system("echo upcall-latency*.data")
plot for [filename in filenames] filename title filename using (bin($1,binwidth)+(binwidth/2)):(1.0) smooth freq with boxes
pause -1

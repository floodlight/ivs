#!/usr/bin/python
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
_help="""
-------------------------------------------------------------------------------
NAME
        oftest.py - Run OFTest against IVS

SYNOPSIS
        oftest.py [--ivs-args=...] [--oft-args=...] [--test-file|-f=...] [--test-spec|-t=...]

DESCRIPTION
        This script automates the execution of OFTest suites against
        the IVS binary. You can use it to execute any subset of
        tests against your locally built IVS binary.

        This script is used in the automated testing tasks.

        This script can be used by developers for manual tests.


OPTIONS
        --test-spec, -T The oftest test-spec you want to execute.
                        This parameter is required. If you want to run
                        all tests, specify "all".
        --test-file, -f Path to an OFTest test-file.
        --log-base-dir  Set Log base directory.

NOTES
       You must set the following environment variables before
       using this script:

         $OFTEST         Set to the top of the OFTest repository.


LOGFILES
        The output from IVS is stored in   'testlogs/OFTest/{testname}/ivs.log
        The output from oftest is store in 'testlogs/OFTest/{testname}/output.log
        The oft.log file is stored in      'testlogs/OFTest/{testname}/oft.log


EXAMPLES
        # Run all oftests against IVS:
        > build/oftest.py -T all
"""

import os
import sys
import time
import argparse
import random
import subprocess
import pprint
import platform
import datetime
import StringIO
import signal
import select
import platform
import logging

###############################################################################
#
# Helpers
#
###############################################################################

def dirlist(d):
    if d == None:
        return [ "." ]
    if type(d) == str:
        return [ d ]
    if type(d) != list:
        raise Exception("'%s' is a bad dirlist" % d)
    return d

def fselect(name, tops, subs, p=False):

    tops = dirlist(tops)
    subs = dirlist(subs)

    for top in tops:
        for sub in subs:
            f = "%s/%s/%s" % (top, sub, name)
            if os.path.exists(f):
                return f
            if p:
                print "%s: not found" % f

    if p == False:
        fselect(name, tops, subs, p=True)
        raise Exception("Could not find the '%s' binary. Search paths were %s:%s" % (name, tops, subs))

def system(command, die=False):
    logging.debug("Running %s ", command)
    rv = os.system(command)
    if rv != 0 and die:
        raise Exception("    [ %s ] FAILED: %d" % (command, rv))

    return rv

def randomports(count):
    return random.sample(xrange(30000, 32000), count)

def requirePathEnv(name):
    p = os.getenv(name)
    if p is None:
        raise Exception("You must set the $%s variable." % name)
    if not os.path.isdir(p):
        raise Exception("The $%s variable does not point to a directory." % name)
    return p

###############################################################################

IVS_BASEDIR = os.path.join(os.path.dirname(__file__), "..")
OFTEST_BASEDIR = requirePathEnv("OFTEST")
LOG_BASEDIR = "%s/testlogs/oftest" % (IVS_BASEDIR)
OFT = fselect("oft", OFTEST_BASEDIR, ".")
IVS_BINARY = fselect("ivs", IVS_BASEDIR, ["targets/ivs/build/gcc-local/bin"]);

if sys.stderr.isatty():
    RED = "\x1B[31m"
    GREEN = "\x1B[32m"
    NORM = "\x1B[39m"
else:
    RED = ""
    GREEN = ""
    NORM = ""

class VethNetworkConfig(object):
    def __init__(self, portCount):
        self.caddr = "127.0.0.1"
        self.cport = randomports(1)[0]
        self.switchInterfaces = ["veth%d" % (i*2) for i in range(portCount)]
        self.oftestInterfaces = ["%d@veth%d" % (i+1, i*2+1) for i in range(portCount)]

def listOFTests(spec=None, testfile=None):
    args = [ OFT, "--list-test-names" ]
    if spec:
        args.append(spec)
    if testfile:
        args.append("--test-file=%s" % testfile)
    stdout = subprocess.check_output(args);
    return stdout.splitlines();

def runOFTest(test, networkConfig, logDir, oftArgs=None):
    args = [ OFT,
             "-H", str(networkConfig.caddr),
             "-p", str(networkConfig.cport),
             "--verbose",
             "--log-file", "%s/oft.log" % logDir,
             "--fail-skipped" ]

    for iface in networkConfig.oftestInterfaces:
        args.append('-i')
        args.append(iface)

    if oftArgs:
        args = args + oftArgs

    args.append(test)

    with open("%s/oft.stdout.log" % (logDir), "w") as logfile:
        child = subprocess.Popen(args,
                                 stdin=subprocess.PIPE,
                                 stdout=logfile,
                                 stderr=subprocess.STDOUT)

    if not child:
        raise Exception("Failed to start: ", args)

    child.wait()

    return child.returncode;

class IVS(object):
    def __init__(self, networkConfig, logDir, ivsArgs=None):
        self.networkConfig = networkConfig
        self.logDir = logDir
        self.ivsArgs = ivsArgs
        self.child = None

    def start(self):
        args = [ IVS_BINARY,
                 "-c", "%s:%d" % (self.networkConfig.caddr, self.networkConfig.cport) ]

        if self.ivsArgs:
            args += self.ivsArgs

        for iface in self.networkConfig.switchInterfaces:
            args.append("-i");
            args.append(iface);

        with open("%s/ivs.log" % (self.logDir), "w") as logfile:
            self.child = subprocess.Popen(args,
                                        stdin=subprocess.PIPE,
                                        stdout=logfile,
                                        stderr=subprocess.STDOUT)

        if self.child is None:
            raise Exception("Failed to start IVS")

    def stop(self):
        if self.child:
            self.child.send_signal(signal.SIGTERM)
            self.child.wait()
            self.child = None

# BSN test system integration
class AbatTask(object):
    def __init__(self):
        self.abatId = os.getenv("ABAT_ID");
        assert(self.abatId)
        self.abatTimestamp = os.getenv("ABAT_TIMESTAMP")
        self.abatTask = os.getenv("ABAT_TASK")

        self.abatWorkspace = "%s-%s" % (self.abatTimestamp, self.abatTask)
        self.bscBaseDir = requirePathEnv("BSC");

        self.runIds = {}

    def addTestcase(self, test, testLogDir):
        logUrl = "http://%s/abat/%s/%s" % (platform.node(), self.abatWorkspace, testLogDir)
        runId = os.popen("%s/build/add-testcase.py %s %s %s %s | tail -n 1" % (
                self.bscBaseDir, self.abatId, test, "OFTest", logUrl)).read().rstrip()
        self.runIds[test] = runId

    def updateTestcase(self, test, result):
        system("%s/build/update-testcase.py %s %s" % (
               self.bscBaseDir, self.runIds[test], result))

class AutotestIVS(object):
    def __init__(self, config):
        self.config = config
        if os.getenv("ABAT_TASK"):
            print "Running in ABAT."
            self.abat = AbatTask()
        else:
            self.abat = None
        self.__setup()

    def __setup(self):
        self.oftests = listOFTests(spec=self.config.test_spec,
                                   testfile=self.config.test_file)

    def runTests(self):
        results = { 'FAILED' : [], 'PASSED' : [] }
        for test in self.oftests:
            result = self.runTest(test)
            results[result].append(test)

        print
        print "%d PASSED, %d FAILED." % (len(results['PASSED']), len(results['FAILED'])),

        if results['FAILED']:
            print
            print "Failing tests:"
            for test in results['FAILED']:
                print test

    def runTest(self, test):
        testLogDir = "%s/%s" % (LOG_BASEDIR, test)
        system("mkdir -p %s" % (testLogDir))

        sys.stdout.write("Running %s ... " % test)
        sys.stdout.flush()

        if self.abat:
            self.abat.addTestcase(test, testLogDir)

        networkConfig = VethNetworkConfig(4)
        ivs = IVS(networkConfig, testLogDir, self.config.ivs_args)

        ivs.start()
        rv = runOFTest(test, networkConfig, testLogDir, self.config.oft_args)
        ivs.stop()

        if rv == 0:
            result = 'PASSED'
            sys.stdout.write(GREEN + "OK" + NORM + "\n")
        else:
            result = 'FAILED'
            sys.stdout.write(RED + "FAIL" + NORM + "\n")
            print "Test logs in %s" % testLogDir

        if self.abat:
            self.abat.updateTestcase(test, result)

        return result

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="",
                                 epilog=_help,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-T", "--test-spec", help="OFTest test specification", default=None)
    ap.add_argument("-f", "--test-file", help="OFTest test file", default=None)
    ap.add_argument("--ivs-args", help="Additional arguments passed to IVS.")
    ap.add_argument("--oft-args", help="Additional arguments passed to oft.")
    ap.add_argument("--log-base-dir", help="Set the log base directory.", default=None)

    config = ap.parse_args()

    if config.log_base_dir:
        LOG_BASEDIR = config.log_base_dir

    if not (config.test_spec or config.test_file):
        sys.exit("Must specify at least one of --test-spec or --test-file")

    a = AutotestIVS(config)
    a.runTests()

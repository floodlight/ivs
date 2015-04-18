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
"""
Basic testcases for the Lua pipeline
"""

import logging
import time
import xdrlib

import ofp

from oftest.testutils import *

import lua_common

class TableRegister(lua_common.BaseTest):
    """
    Verify that Lua code can register gentables
    """

    sources = ["tables"]

    def runTest(self):
        self.assertIn("l2", self.gentable_ids);
        self.assertIn("vlan", self.gentable_ids);

class Concatenate(lua_common.BaseTest):
    """
    Verify that successive uploads with the same filename are concatenated
    """

    sources = []

    def runTest(self):
        a = "log('split"
        b = "string')"

        msg = ofp.message.bsn_lua_upload(
            flags=1,
            filename="test",
            data=a)
        self.controller.message_send(msg)

        msg = ofp.message.bsn_lua_upload(
            flags=2,
            filename="test",
            data=b)
        self.controller.message_send(msg)

        do_barrier(self.controller)
        verify_no_errors(self.controller)

class IdenticalCode(lua_common.BaseTest):
    """
    Verify that resending the same code does not reset the Lua VM
    """

    sources = ["tables", "command"]

    def runTest(self):
        self.command("not_reset = 1")

        # Send the same code as the base test
        self.upload(self.sources, force=False)

        do_barrier(self.controller)
        verify_no_errors(self.controller)

        self.command("assert(not_reset == 1)")

class Reload(lua_common.BaseTest):
    """
    Verify that we can upload code many times without crashing
    """

    sources = ["tables", "command"]

    def runTest(self):
        start_time = time.time()
        n = 100

        for i in range(0, n):
            # Send the same code as the base test
            self.upload(self.sources)

        do_barrier(self.controller, timeout=10)
        verify_no_errors(self.controller)

        elapsed = time.time() - start_time
        logging.info("%d iterations in %.3fs", n, elapsed)

class Command(lua_common.BaseTest):
    """
    Verify that the bsn_lua_command handler gets the correct arguments
    and can return a result
    """

    sources = ["command"]

    def runTest(self):
        code = """\
reader, writer = ...
assert(reader.int() == 100)
assert(reader.int() == -1)
assert(reader.uint() == 0xffffffff)
assert(reader.bool() == true)
assert(reader.bool() == false)
writer.uint(42)
"""
        packer = xdrlib.Packer()
        packer.pack_string(code)
        packer.pack_int(100)
        packer.pack_int(-1)
        packer.pack_uint(0xffffffff)
        packer.pack_bool(True)
        packer.pack_bool(False)
        packer.pack_array([1, 2, 3], lambda x: packer.pack_uint(x))
        reply, _ = self.controller.transact(ofp.message.bsn_lua_command_request(data=packer.get_buffer()))
        self.assertIsInstance(reply, ofp.message.bsn_lua_command_reply)
        unpacker = xdrlib.Unpacker(reply.data)
        self.assertEquals(unpacker.unpack_int(), 42)

class Hashtable(lua_common.BaseTest):
    """
    Run hashtable_test.lua
    """

    sources = ["command", "hashtable_test"]

    def runTest(self):
        self.command("hashtable_test()")

class HashtableBenchmark(lua_common.BaseTest):
    """
    Run hashtable_benchmark.lua
    """

    sources = ["command", "hashtable_benchmark"]

    def runTest(self):
        self.command("hashtable_benchmark()")

class WriteTooMuch(lua_common.BaseTest):
    """
    Verify we get an error message when the result of a command doesn't
    fit in an OpenFlow message
    """

    sources = ["command"]

    def runTest(self):
        code = """\
reader, writer = ...
for i = 1, 100000 do
    writer.uint(1)
end
"""
        packer = xdrlib.Packer()
        packer.pack_string(code)
        reply, _ = self.controller.transact(ofp.message.bsn_lua_command_request(data=packer.get_buffer()))
        self.assertIsInstance(reply, ofp.message.bad_request_error_msg)

# TODO broken
@disabled
class AllocateTooMuch(lua_common.BaseTest):
    """
    Check what happens when we allocate too much in the Lua VM
    """

    sources = ["command"]

    def runTest(self):
        code = """\
local t = {}
for i = 1, 100000000 do
    table.insert(t, {})
end
"""
        packer = xdrlib.Packer()
        packer.pack_string(code)
        reply, _ = self.controller.transact(ofp.message.bsn_lua_command_request(data=packer.get_buffer()))
        self.assertIsInstance(reply, ofp.message.bad_request_error_msg)

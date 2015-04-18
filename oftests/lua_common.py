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
Common code shared between Lua testcases
"""

import os
import xdrlib

import oftest.base_tests as base_tests
import ofp

from oftest.testutils import *

class BaseTest(base_tests.SimpleDataPlane):
    """
    Base test class which sets up the Lua pipeline
    """

    # Names of Lua files to upload (minus .lua)
    # Overriden by each subclass
    sources = []

    def setUp(self):
        """
        Setup switch
        """
        base_tests.SimpleDataPlane.setUp(self)
        self.ports = openflow_ports(6)

        reply, _ = self.controller.transact(ofp.message.bsn_set_switch_pipeline_request(pipeline="lua"))
        self.assertEquals(reply.status, 0)

        self.upload(self.sources)

        do_barrier(self.controller)
        verify_no_errors(self.controller)

        self.fetch_gentables()
        self.clear_gentables()

        self.dataplane.flush()

    def upload(self, sources, force=True):
        """
        Upload Lua code

        'sources' is a list of names of files in oftests/lua, minus the '.lua' extension.
        """
        for source in self.sources:
            code = file(os.path.join(os.path.dirname(__file__), "lua", source + '.lua')).read()
            msg = ofp.message.bsn_lua_upload(
                flags=ofp.OFP_BSN_LUA_UPLOAD_MORE,
                filename=source,
                data=code)
            self.controller.message_send(msg)

        # Commit
        msg = ofp.message.bsn_lua_upload(
            flags=force and ofp.OFP_BSN_LUA_UPLOAD_FORCE or 0, data="")
        self.controller.message_send(msg)

    def fetch_gentables(self):
        """
        Populates self.gentable_ids with the name -> id mapping
        """
        gentables = get_stats(self, ofp.message.bsn_gentable_desc_stats_request())
        self.gentable_ids = { x.name: x.table_id for x in gentables }

    def clear_gentables(self):
        """
        Clear gentables with count > 0
        """
        gentable_stats = get_stats(self, ofp.message.bsn_gentable_stats_request())
        for stat in gentable_stats:
            if stat.entry_count > 0:
                request = ofp.message.bsn_gentable_clear_request(table_id=stat.table_id)
                self.controller.transact(request)

    def command(self, code):
        """
        Send a bsn_lua_command message to the switch

        Compatible with command.lua but doesn't support arguments or
        deserializing the result.
        """
        packer = xdrlib.Packer()
        packer.pack_string(code)
        reply, _ = self.controller.transact(
            ofp.message.bsn_lua_command_request(data=packer.get_buffer()))
        self.assertIsInstance(reply, ofp.message.bsn_lua_command_reply)
        return reply.data

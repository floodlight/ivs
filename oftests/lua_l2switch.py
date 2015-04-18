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
Testcases for the l2switch sample Lua code
"""

import time
import xdrlib
import ofp

from oftest.testutils import *
from oftest.parse import parse_mac, parse_ip

import lua_common

def parse_mac_words(mac):
    a = parse_mac(mac)
    return (a[0] << 8) | a[1], (a[2] << 24) | (a[3] << 16) | (a[4] << 8) | a[5]

def insert_l2(self, vlan, mac, port):
    mac_hi, mac_lo = parse_mac_words(mac)

    # TODO replace with code generated from floodlight/xdr
    packer = xdrlib.Packer()
    packer.pack_uint(vlan)
    packer.pack_uint(mac_hi)
    packer.pack_uint(mac_lo)
    key_data = packer.get_buffer()

    packer = xdrlib.Packer()
    packer.pack_uint(port)
    value_data = packer.get_buffer()

    msg = ofp.message.bsn_gentable_entry_add(
        table_id=self.gentable_ids['l2'],
        key=[ofp.bsn_tlv.data(key_data)],
        value=[ofp.bsn_tlv.data(value_data)])
    self.controller.message_send(msg)

def insert_vlan(self, vlan, ports):
    port_bitmap = 0
    for port in ports:
        port_bitmap |= (1 << port)

    # TODO replace with code generated from floodlight/xdr
    packer = xdrlib.Packer()
    packer.pack_uint(vlan)
    key_data = packer.get_buffer()

    packer = xdrlib.Packer()
    packer.pack_uint(port_bitmap)
    value_data = packer.get_buffer()

    msg = ofp.message.bsn_gentable_entry_add(
        table_id=self.gentable_ids['vlan'],
        key=[ofp.bsn_tlv.data(key_data)],
        value=[ofp.bsn_tlv.data(value_data)])
    self.controller.message_send(msg)

class L2Forwarding(lua_common.BaseTest):
    """
    Test various forwarding cases
    """

    sources = ["l2switch"]

    def runTest(self):
        insert_vlan(self, vlan=1, ports=[1, 2])
        insert_vlan(self, vlan=2, ports=[3])
        insert_l2(self, vlan=1, mac="00:00:00:00:00:01", port=1)
        insert_l2(self, vlan=1, mac="00:00:00:00:00:02", port=2)
        insert_l2(self, vlan=2, mac="00:00:00:00:00:03", port=3)
        do_barrier(self.controller)
        verify_no_errors(self.controller)

        # 1 -> 2
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                    eth_dst="00:00:00:00:00:02",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(1, pkt)
        verify_packets(self, pkt, [2])

        # 2 -> 1
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:02",
                                    eth_dst="00:00:00:00:00:01",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(2, pkt)
        verify_packets(self, pkt, [1])

        # broadcast
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                    eth_dst="ff:ff:ff:ff:ff:ff",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(1, pkt)
        verify_packets(self, pkt, [1, 2])

        # new host
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:ff",
                                    eth_dst="00:00:00:00:00:01",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(2, pkt)
        verify_packets(self, pkt, [])

        # station move
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                    eth_dst="00:00:00:00:00:01",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(2, pkt)
        verify_packets(self, pkt, [])

        # unknown destination
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                    eth_dst="00:00:00:00:00:ff",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(1, pkt)
        verify_packets(self, pkt, [1, 2])

        # vlan isolation
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                    eth_dst="00:00:00:00:00:03",
                                    dl_vlan_enable=True, vlan_vid=1))
        self.dataplane.send(1, pkt)
        verify_packets(self, pkt, [1, 2])

        # port not allowed on vlan
        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                    eth_dst="00:00:00:00:00:03",
                                    dl_vlan_enable=True, vlan_vid=2))
        self.dataplane.send(1, pkt)
        verify_packets(self, pkt, [])

class ManyPackets(lua_common.BaseTest):
    """
    Send a bunch of packets through the switch
    """

    sources = ["l2switch"]

    def runTest(self):
        insert_vlan(self, vlan=1, ports=[1, 2])
        insert_vlan(self, vlan=2, ports=[3])
        insert_l2(self, vlan=1, mac="00:00:00:00:00:01", port=1)
        insert_l2(self, vlan=1, mac="00:00:00:00:00:02", port=2)
        insert_l2(self, vlan=2, mac="00:00:00:00:00:03", port=3)
        do_barrier(self.controller)
        verify_no_errors(self.controller)

        for i in xrange(0, 100):
            pkt = str(simple_tcp_packet(eth_src="00:00:00:00:00:01",
                                        eth_dst="00:00:00:00:00:02",
                                        dl_vlan_enable=True, vlan_vid=1,
                                        tcp_sport=i))
            self.dataplane.send(1, pkt)
            verify_packet(self, pkt, 2)

        verify_no_other_packets(self)

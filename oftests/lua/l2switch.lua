--        Copyright 2015, Big Switch Networks, Inc.
--
-- Licensed under the Eclipse Public License, Version 1.0 (the
-- "License"); you may not use this file except in compliance
-- with the License. You may obtain a copy of the License at
--
--        http://www.eclipse.org/legal/epl-v10.html
--
-- Unless required by applicable law or agreed to in writing,
-- software distributed under the License is distributed on an
-- "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
-- either express or implied. See the License for the specific
-- language governing permissions and limitations under the
-- License.

-- L2 switch with VLAN isolation
--
-- This isn't intended to be a full featured switch, but just enough to run
-- OFTests against.
--
-- TODO use a single "endpoint" OpenFlow table
-- TODO remove limitation of 32 ports

local fields = fields
local bit_check, flood
local xdr = require("l2switch_xdr")

local l2_table = hashtable.create({ "vlan", "mac_hi", "mac_lo" }, { "port", "stats" })
local l2_stats = {}

register_table("l2", {
    parse_key=xdr.read_l2_key,
    parse_value=xdr.read_l2_value,

    add=function(k, v, cookie)
        log("l2_add %p: vlan=%u mac=%04x%08x -> port %u", cookie, k.vlan, k.mac_hi, k.mac_lo, v.port)
        l2_stats[cookie] = stats.alloc()
        l2_table:insert(k, { port=v.port, stats=l2_stats[cookie] })
    end,

    modify=function(k, v, cookie)
        log("l2_modify %p: vlan=%u mac=%04x%08x -> port %u", cookie, k.vlan, k.mac_hi, k.mac_lo, v.port)
        l2_table:insert(k, { port=v.port, stats=l2_stats[cookie] })
    end,

    delete=function(k, cookie)
        log("l2_delete %p: vlan=%u mac=%04x%08x", cookie, k.vlan, k.mac_hi, k.mac_lo)
        stats.free(l2_stats[cookie])
        l2_stats[cookie] = nil
        l2_table:remove(k)
    end,

    get_stats=function(k, writer, cookie)
        log("l2_get_stats %p: vlan=%u mac=%04x%08x", cookie, k.vlan, k.mac_hi, k.mac_lo)
        local packets, bytes = stats.get(l2_stats[cookie])
        xdr.write_l2_stats(writer, { packets=packets, bytes=bytes })
    end
})

local vlan_table = hashtable.create({ "vlan" }, { "port_bitmap" })

register_table("vlan", {
    parse_key=xdr.read_vlan_key,
    parse_value=xdr.read_vlan_value,

    add=function(k, v, cookie)
        log("vlan_add %p: vlan=%u -> port_bitmap %08x", cookie, k.vlan, v.port_bitmap)
        vlan_table:insert(k, v)
    end,

    modify=function(k, v, cookie)
        log("vlan_modify %p: vlan=%u -> port_bitmap %08x", cookie, k.vlan, v.port_bitmap)
        vlan_table:insert(k, v)
    end,

    delete=function(k, cookie)
        log("vlan_delete %p: vlan=%u", cookie, k.vlan)
        vlan_table:remove(k)
    end,
})

function ingress()
    if fields.eth_type == 0x88cc then
        log("sending pdu to controller")
        userspace(0)
        return
    end

    local vlan_entry = vlan_table:lookup({ vlan=fields.vlan_vid })
    if not vlan_entry then
        trace("VLAN lookup failure, dropping")
        userspace(0)
        return
    end

    if not bit_check(vlan_entry.port_bitmap, fields.in_port) then
        trace("Port %u not allowed on VLAN %u, dropping", fields.in_port, fields.vlan_vid)
        userspace(0)
        return
    end

    local l2_src_entry = l2_table:lookup({ vlan=fields.vlan_vid,
                                           mac_hi=fields.eth_src_hi,
                                           mac_lo=fields.eth_src_lo })
    if not l2_src_entry then
        trace("L2 source lookup failure, dropping")
        userspace(0)
        return
    elseif l2_src_entry.port ~= fields.in_port then
        trace("Station move, dropping")
        userspace(0)
        return
    end

    stats.add(l2_src_entry.stats)

    if bit.band(fields.eth_dst_hi, 0x0100) ~= 0 then
        trace("Broadcast/multicast, flooding")
        return flood(vlan_entry)
    end

    local l2_dst_entry = l2_table:lookup({ vlan=fields.vlan_vid,
                                           mac_hi=fields.eth_dst_hi,
                                           mac_lo=fields.eth_dst_lo })
    if not l2_dst_entry then
        trace("L2 destination lookup failure, flooding")
        return flood(vlan_entry)
    end

    output(l2_dst_entry.port)
end

function flood(vlan_entry)
    for port = 0, 31 do
        if bit_check(vlan_entry.port_bitmap, port) then
            output(port)
        end
    end
end

function bit_check(bitmap, index)
    return bit.band(bitmap, bit.lshift(1, index)) ~= 0
end

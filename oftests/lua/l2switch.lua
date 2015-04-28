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

local fields = fields
local bit_check, flood
local xdr = require("l2switch_xdr")

local l2_table = hashtable.create({ "vlan", "mac_hi", "mac_lo" }, { "port", "stats" })

local vlan_table = {} -- vlan -> { port -> refcount }
for vlan = 0, 4095 do
    vlan_table[vlan] = {}
end

local function vlan_add_member(vlan, port)
    vlan_entry = vlan_table[vlan]
    vlan_entry[port] = (vlan_entry[port] or 0) + 1
end

local function vlan_remove_member(vlan, port)
    vlan_entry = vlan_table[vlan]
    local refcount = vlan_entry[port]
    if refcount > 1 then
        vlan_entry[port] = refcount - 1
    else
        vlan_entry[port] = nil
    end
end

local endpoints = {} -- cookie -> { stats, port }

register_table("endpoint", {
    parse_key=xdr.read_endpoint_key,
    parse_value=xdr.read_endpoint_value,

    add=function(k, v, cookie)
        log("endpoint add %p: vlan=%u mac=%04x%08x -> port %u", cookie, k.vlan, k.mac_hi, k.mac_lo, v.port)
        local s = stats.alloc()
        l2_table:insert(k, { port=v.port, stats=s })
        vlan_add_member(k.vlan, v.port)
        endpoints[cookie] = { port=v.port, stats=s }
    end,

    modify=function(k, v, cookie)
        log("endpoint modify %p: vlan=%u mac=%04x%08x -> port %u", cookie, k.vlan, k.mac_hi, k.mac_lo, v.port)
        local e = endpoints[cookie]
        l2_table:insert(k, { port=v.port, stats=e.stats })
        vlan_remove_member(k.vlan, e.port) -- remove old port from VLAN
        vlan_add_member(k.vlan, v.port) -- add new port to VLAN
    end,

    delete=function(k, cookie)
        log("endpoint delete %p: vlan=%u mac=%04x%08x", cookie, k.vlan, k.mac_hi, k.mac_lo)
        local e = endpoints[cookie]
        l2_table:remove(k)
        vlan_remove_member(k.vlan, e.port)
        stats.free(e.stats)
        endpoints[cookie] = nil
    end,

    get_stats=function(k, writer, cookie)
        log("endpoint get_stats %p: vlan=%u mac=%04x%08x", cookie, k.vlan, k.mac_hi, k.mac_lo)
        local e = endpoints[cookie]
        local packets, bytes = stats.get(e.stats)
        xdr.write_endpoint_stats(writer, { packets=packets, bytes=bytes })
    end
})

function ingress()
    if fields.eth_type == 0x88cc then
        trace("sending pdu to controller")
        userspace(0)
        return
    end

    local vlan_entry = vlan_table[fields.vlan_vid]
    if not vlan_entry then
        trace("VLAN lookup failure, dropping")
        userspace(0)
        return
    end

    if not vlan_entry[fields.in_port] then
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
    for port in pairs(vlan_entry) do
        output(port)
    end
end

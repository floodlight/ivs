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
-- TODO send packet-in instead of dropping
-- TODO use a single "endpoint" OpenFlow table
-- TODO stats
-- TODO remove limitation of 32 ports
-- TODO send LLDPs to controller

local fields = fields
local bit_check, flood

local l2_table = hashtable.create({ "vlan", "mac_hi", "mac_lo" }, { "port" })

register_table("l2", {
    parse_key=function(r)
        return {
            vlan=r.uint(),
            mac_hi=r.uint(),
            mac_lo=r.uint(),
        }
    end,

    parse_value=function(r)
        return {
            port=r.uint(),
        }
    end,

    add=function(k, v)
        log("l2_add: vlan=%u mac=%04x%08x -> port %u", k.vlan, k.mac_hi, k.mac_lo, v.port)
        l2_table:insert(k, v)
    end,

    modify=function(k, v)
        log("l2_modify: vlan=%u mac=%04x%08x -> port %u", k.vlan, k.mac_hi, k.mac_lo, v.port)
        l2_table:insert(k, v)
    end,

    delete=function(k)
        log("l2_delete: vlan=%u mac=%04x%08x", k.vlan, k.mac_hi, k.mac_lo)
        l2_table:remove(k)
    end,
})

local vlan_table = hashtable.create({ "vlan" }, { "port_bitmap" })

register_table("vlan", {
    parse_key=function(r)
        return {
            vlan=r.uint(),
        }
    end,

    parse_value=function(r)
        return {
            port_bitmap=r.uint(),
        }
    end,

    add=function(k, v)
        log("vlan_add: vlan=%u -> port_bitmap %08x", k.vlan, v.port_bitmap)
        vlan_table:insert(k, v)
    end,

    modify=function(k, v)
        log("vlan_modify: vlan=%u -> port_bitmap %08x", k.vlan, v.port_bitmap)
        vlan_table:insert(k, v)
    end,

    delete=function(k)
        log("vlan_delete: vlan=%u", k.vlan)
        vlan_table:remove(k)
    end,
})

function ingress()
    local vlan_entry = vlan_table:lookup({ vlan=fields.vlan_vid })
    if not vlan_entry then
        log("VLAN lookup failure, dropping")
        return
    end

    if not bit_check(vlan_entry.port_bitmap, fields.in_port) then
        log("Port %u not allowed on VLAN %u, dropping", fields.in_port, fields.vlan_vid)
        return
    end

    local l2_src_entry = l2_table:lookup({ vlan=fields.vlan_vid,
                                           mac_hi=fields.eth_src_hi,
                                           mac_lo=fields.eth_src_lo })
    if not l2_src_entry then
        log("L2 source lookup failure, dropping")
        return
    elseif l2_src_entry.port ~= fields.in_port then
        log("Station move, dropping")
        return
    end

    if bit.band(fields.eth_dst_hi, 0x0100) ~= 0 then
        log("Broadcast/multicast, flooding")
        return flood(vlan_entry)
    end

    local l2_dst_entry = l2_table:lookup({ vlan=fields.vlan_vid,
                                           mac_hi=fields.eth_dst_hi,
                                           mac_lo=fields.eth_dst_lo })
    if not l2_dst_entry then
        log("L2 destination lookup failure, flooding")
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

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

-- Register a couple of tables for testing with no-op add/remove ops

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
    end,

    modify=function(k, v)
        log("l2_modify: vlan=%u mac=%04x%08x -> port %u", k.vlan, k.mac_hi, k.mac_lo, v.port)
    end,

    delete=function(k)
        log("l2_delete: vlan=%u mac=%04x%08x", k.vlan, k.mac_hi, k.mac_lo)
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
    end,

    modify=function(k, v)
        log("vlan_modify: vlan=%u -> port_bitmap %08x", k.vlan, v.port_bitmap)
    end,

    delete=function(k)
        log("vlan_delete: vlan=%u", k.vlan)
    end,
})

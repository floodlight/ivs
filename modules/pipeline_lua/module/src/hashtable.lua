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

local ffi = require("ffi")
local bit = require("bit")
local band, bor = bit.band, bit.bor
local ipairs = ipairs

local function make_hash_function(fields)
    local lines = {}
    table.insert(lines, "local murmur_round, murmur_finish = murmur.round, murmur.finish")
    table.insert(lines, "local tobit, band = bit.tobit, bit.band")
    table.insert(lines, "return function (obj)")
    table.insert(lines, "local h = 0")
    for i, v in ipairs(fields) do
        table.insert(lines, string.format("h = murmur_round(h, obj.%s)", v))
    end
    table.insert(lines, "h = murmur_finish(h)")
    table.insert(lines, "h = band(h, 0x7fffffff)")
    table.insert(lines, "if h == 0 then h = 1 end")
    table.insert(lines, "return (tobit(h))")
    table.insert(lines, "end")
    local str = table.concat(lines, "\n")
    local chunk = loadstring(str, "hash")
    return chunk()
end

local function make_compare_function(fields)
    local lines = {}
    table.insert(lines, "return function (a, b)")
    for i, v in ipairs(fields) do
        table.insert(lines, string.format("if a.%s ~= b.%s then return false end", v, v))
    end
    table.insert(lines, "return true")
    table.insert(lines, "end")
    local str = table.concat(lines, "\n")
    local chunk = loadstring(str, "compare")
    return chunk()
end

local function make_lookup_function(fields, lookup_int)
    local lines = {}
    table.insert(lines, "local lookup_int = ...")
    table.insert(lines, "local key = {}")
    table.insert(lines, "local select, type = select, type")
    table.insert(lines, "return function (self, ...)")
    table.insert(lines, "local first = select(1, ...)")
    table.insert(lines, "if type(first) == \"table\" then")
    for i, v in ipairs(fields) do
        table.insert(lines, string.format("key.%s = first.%s", v, v))
    end
    table.insert(lines, "else")
    for i, v in ipairs(fields) do
        table.insert(lines, string.format("key.%s = select(%d, ...)", v, i))
    end
    table.insert(lines, "end")
    table.insert(lines, "return lookup_int(key)")
    table.insert(lines, "end")
    local str = table.concat(lines, "\n")
    local chunk = loadstring(str, "lookup")
    return chunk(lookup_int)
end

local initial_size = 16
local load_factor = 0.8

-- Special hash codes
local DELETED = 0x80000000
local EMPTY = 0

local function make_struct(fields)
    local lines = {}
    table.insert(lines, "struct {")
    for i, v in ipairs(fields) do
        table.insert(lines, string.format("uint32_t %s;", v))
    end
    table.insert(lines, "}")
    local str = table.concat(lines, "\n")
    return ffi.typeof(str)
end

local function format_struct(obj, fields)
    local items = {}
    for i, v in ipairs(fields) do
        table.insert(items, string.format("%s=%u", v, obj[v]))
    end
    return table.concat(items, " ")
end

local function create(key_fields, value_fields)
    local hash_key = make_hash_function(key_fields)
    local compare_key = make_compare_function(key_fields)

    local Entry = ffi.typeof([[
    struct {
        uint32_t hash;
        $ key;
        $ value;
    }
    ]], make_struct(key_fields), make_struct(value_fields))

    local Entries = ffi.typeof('$[?]', Entry)

    local methods = {}

    -- Mutable state
    local size = initial_size
    local count = 0
    local entries = ffi.new(Entries, size)
    local mask = size - 1

    local function copy_key(dst, src)
        for i, v in ipairs(key_fields) do
            if src[v] == nil then
                error("Key field " .. v .. " is nil")
            end
            dst[v] = src[v]
        end
    end

    local function copy_value(dst, src)
        for i, v in ipairs(value_fields) do
            if src[v] == nil then
                error("Value field " .. v .. " is nil")
            end
            dst[v] = src[v]
        end
    end

    local function index(h, dist)
        return (band(h + dist, mask))
    end

    local function distance(idx, h)
        local start_idx = index(h, 0);
        return (band(idx + size - start_idx, mask))
    end

    local function insert_internal(key, value, h)
        local dist = 0
        while dist < size do
            local idx = index(h, dist)
            local entry = entries[idx]
            local bucket_dist = distance(idx, entry.hash)
            local should_steal = dist > bucket_dist

            if entry.hash == EMPTY or band(entry.hash, DELETED) ~= 0 then
                entry.hash = h
                copy_key(entry.key, key)
                copy_value(entry.value, value)
                return
            elseif entry.hash == EMPTY or
                    distance(idx, entry.hash) < dist then
                -- Save previous bucket
                local prev_hash = entry.hash
                local prev_key = {}
                local prev_value = {}
                copy_key(prev_key, entry.key)
                copy_value(prev_value, entry.value)

                -- Steal bucket
                entry.hash = h
                copy_key(entry.key, key)
                copy_value(entry.value, value)

                -- Continue inserting victim
                h = prev_hash
                key = prev_key
                value = prev_value
                dist = bucket_dist
            end

            dist = dist + 1
        end
    end

    local function grow()
        local old_size = size
        size = size * 2
        mask = size - 1
        local old_entries = entries
        entries = Entries(size)
        for i = 0, old_size-1 do
            local old_entry = old_entries[i]
            if old_entry.hash ~= EMPTY and band(old_entry.hash, DELETED) == 0 then
                insert_internal(old_entry.key, old_entry.value, old_entry.hash)
            end
        end
    end

    function methods:insert(key, value)
        if count >= size * load_factor then
            grow()
        end

        local h = hash_key(key)

        insert_internal(key, value, h)

        count = count + 1
    end

    local function lookup_int(key)
        local h = hash_key(key)

        for dist = 0, size - 1 do
            local idx = index(h, dist)
            local entry = entries[idx]
            if entry.hash == h and compare_key(key, entry.key) then
                return entry.value
            elseif entry.hash == EMPTY or
                    distance(idx, entry.hash) < dist then
                break
            end
        end

        return nil
    end

    methods.lookup = make_lookup_function(key_fields, lookup_int)

    function methods:remove(key)
        local h = hash_key(key)

        for dist = 0, size - 1 do
            local idx = index(h, dist)
            local entry = entries[idx]
            if entry.hash == h and compare_key(key, entry.key) then
                entry.hash = bor(entry.hash, DELETED)
                count = count - 1
                return
            end
        end

        error("Did not find entry during remove")
    end

    function methods:size()
        return size
    end

    function methods:count()
        return count
    end

    local ht = {}

    local metatable = {
        __index=methods,
    }

    setmetatable(ht, metatable)
    return ht
end

hashtable = { create=create }
sandbox.hashtable = hashtable

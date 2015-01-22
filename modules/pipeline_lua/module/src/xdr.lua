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

local bit = require("bit")
local ffi = require("ffi")
local band, bnot = bit.band, bit.bnot
local ntohl = ffi.abi("le") and bit.bswap or function(x) return x end
local P8 = ffi.typeof("uint8_t *")
local P32 = ffi.typeof("uint32_t *")

-- buf is a lightuserdata
-- len is the maximum offset + 1
-- offset is our current position
Reader = {}
Reader.new = function(buf, len, offset)
    local self = {}
    offset = offset or 0
    buf = ffi.cast(P8, buf)

    local function check_length(n)
        assert(offset + n <= len)
    end

    self.int = function()
        check_length(4)
        local ptr = ffi.cast(P32, buf+offset)
        local ret = ntohl(ptr[0])
        offset = offset + 4
        return ret
    end

    self.uint = function()
        local x = self.int()
        -- Converted signed to unsigned
        if x < 0 then
            return 0x100000000 + x
        else
            return x
        end
    end

    self.bool = function()
        return self.uint() ~= 0
    end

    self.fstring = function(n)
        local padded = band(n + 3, bnot(3))
        check_length(padded)
        local ret = ffi.string(buf+offset, n)
        offset = offset + padded
        return ret
    end

    self.string = function()
        return self.fstring(self.uint())
    end

    return self
end

Writer = {}
Writer.new = function(buf, len)
    local self = {}
    local offset = 0
    buf = ffi.cast(P8, buf)

    local function check_length(n)
        assert(offset + n <= len)
    end

    self.uint = function(x)
        check_length(4)
        local ptr = ffi.cast(P32, buf+offset)
        ptr[0] = ntohl(x)
        offset = offset + 4
    end

    self.int = self.uint

    self.bool = function(x)
        self.uint(x and 1 or 0)
    end

    self.fstring = function(x)
        local n = x:len()
        local padded = band(n + 3, bnot(3))
        check_length(padded)
        ffi.copy(buf+offset, x, n)
        ffi.fill(buf+offset+n, padded-n)
        offset = offset + padded
    end

    self.string = function(x)
        self.uint(x:len())
        self.fstring(x)
    end

    self.offset = function()
        return offset
    end

    return self
end

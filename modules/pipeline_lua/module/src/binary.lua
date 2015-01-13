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
local rshift = bit.rshift
local ntohl = ffi.abi("le") and bit.bswap or function(x) return x end
local ntohs = ffi.abi("le") and function(x) return rshift(ntohl(x), 16) end or function(x) return x end
local P8 = ffi.typeof("uint8_t *")
local P16 = ffi.typeof("uint16_t *")
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

    self.u8 = function()
        check_length(1)
        local ret = buf[offset]
        offset = offset + 1
        return ret
    end

    self.u16 = function()
        check_length(2)
        local ptr = ffi.cast(P16, buf+offset)
        local ret = ntohs(ptr[0])
        offset = offset + 2
        return ret
    end

    self.u32 = function()
        check_length(4)
        local ptr = ffi.cast(P32, buf+offset)
        local ret = ntohl(ptr[0])
        offset = offset + 4
        return ret
    end

    self.blob = function(n)
        check_length(n)
        local ret = ffi.string(buf+offset, n)
        offset = offset + n
        return ret
    end

    self.skip = function(n)
        assert(offset + n <= len)
        offset = offset + n
    end

    self.is_empty = function()
        return offset == len
    end

    self.slice = function(n)
        assert(offset + n <= len)
        r = Reader.new(buf, n, offset)
        offset = offset + n
        return r
    end

    self.offset = function()
        return offset
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

    self.u8 = function(x)
        check_length(1)
        buf[offset] = x
        offset = offset + 1
    end

    self.u16 = function(x)
        check_length(2)
        local ptr = ffi.cast(P16, buf+offset)
        ptr[0] = ntohs(x)
        offset = offset + 2
    end

    self.u32 = function(x)
        check_length(4)
        local ptr = ffi.cast(P32, buf+offset)
        ptr[0] = ntohl(x)
        offset = offset + 4
    end

    self.blob = function(x)
        local n = x:len()
        check_length(n)
        ffi.copy(buf+offset, x, n)
        offset = offset + n
    end

    self.offset = function()
        return offset
    end

    return self
end

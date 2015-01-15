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
local bxor, rshift, rol = bit.bxor, bit.rshift, bit.rol

local function mul(x1, x2)
    return x1 * x2
end

local function round(state, data)
    data = mul(data, 0xcc9e2d51)
    data = rol(data, 15)
    data = mul(data, 0x1b873593)

    state = bxor(state, data)
    state = rol(state, 13)
    state = mul(state, 5) + 0xe6546b64

    return state
end

local function finish(h)
    h = bxor(h, rshift(h, 16))
    h = mul(h, 0x85ebca6b)
    h = bxor(h, rshift(h, 13))
    h = mul(h, 0xc2b2ae35)
    h = bxor(h, rshift(h, 16))
    return h
end

murmur = { round=round, finish=finish }
sandbox.murmur = murmur

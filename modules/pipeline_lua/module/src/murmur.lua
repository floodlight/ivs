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
local bxor, rshift, rol, tobit = bit.bxor, bit.rshift, bit.rol, bit.tobit

local function mul(x1, x2)
    return (tobit(x1*(x2+0LL)))
end

local function round(state, data)
    data = mul(data, -862048943)
    data = rol(data, 15)
    data = mul(data, 0x1b873593)

    state = bxor(state, data)
    state = rol(state, 13)
    state = mul(state, 5) - 430675100

    return state
end

local function finish(h)
    h = bxor(h, rshift(h, 16))
    h = mul(h, -2048144789)
    h = bxor(h, rshift(h, 13))
    h = mul(h, -1028477387)
    h = bxor(h, rshift(h, 16))
    return h
end

murmur = { round=round, finish=finish }
sandbox.murmur = murmur

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

function hashtable_test()
    do
        local ht = hashtable.create({ "x", "y" }, { "a" })
        assert(ht:lookup({ x=0, y=1 }) == nil)
        ht:insert({ x=0, y=1 }, { a=1000 })
        assert(ht:lookup({ x=0, y=1 }).a == 1000)
        ht:remove({ x=0, y=1 })
        assert(ht:lookup({ x=0, y=1 }) == nil)
    end

    do
        local ht = hashtable.create({ "x", "y" }, { "a" })
        for i = 1, 1000 do
            assert(ht:lookup({ x=i, y=i }) == nil)
            ht:insert({ x=i, y=i }, { a=i })
            assert(ht:lookup({ x=i, y=i }).a == i)
        end
    end

    do
        local ht = hashtable.create({ "x", "y" }, { "a" })
        local max = 4000*1000*1000
        local n = 1639
        local seed = 42

        local keys = {}
        for i = 1, n do
            table.insert(keys, { x=math.random(max), y=math.random(max) })
        end

        for i, key in ipairs(keys) do
            assert(ht:lookup(key) == nil)
            ht:insert(key, { a=i })
            assert(ht:lookup(key).a == i)
        end

        for i, key in ipairs(keys) do
            assert(ht:lookup(key).a == i)
            assert(ht:lookup(key.x, key.y).a == i)
        end

        for i, key in ipairs(keys) do
            assert(ht:lookup(key).a == i)
            ht:remove(key)
            assert(ht:lookup(key) == nil)
        end
    end
end

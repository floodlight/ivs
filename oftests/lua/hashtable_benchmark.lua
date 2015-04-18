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

function hashtable_benchmark()
    local num_lookups = 1*1000*1000
    local max_table_size = 2^20

    local total_lookups = 0
    local total_time = 0

    local ht = hashtable.create({ "x", "y" }, { "a" })

    local table_size = 16
    while table_size <= max_table_size do
        local n = math.floor(table_size * 0.8)

        for i = ht:count()+1, n do
            ht:insert({ x=i, y=i }, { a=i })
        end

        assert(ht:size() == table_size)
        assert(ht:count() == n)

        local start_time = os.clock()

        local key = 1
        for i = 1, num_lookups do
            local value = ht:lookup({ x=key, y=key })
            if not value then
                error("missing value for key " .. key)
            end
            key = value.a + 1 -- create data dependency
            if key > n then
                key = 1
            end
            total_lookups = total_lookups + 1
        end

        local elapsed = os.clock() - start_time
        total_time = total_time + elapsed
        log("size=%u count=%u elapsed=%.3fs avg=%.3fns",
            ht:size(), ht:count(), elapsed, elapsed/num_lookups*1e9)

        table_size = table_size * 2
    end

    log("total time=%.3fs avg time=%.3fns", total_time, total_time/total_lookups*1e9)
end

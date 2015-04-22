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

-- Command message handler that executes the first string argument as Lua code
-- This is great for testing but a more performant implementation wouldn't
-- parse Lua code for every command.

function command(reader, writer)
    local code = reader.string()
    log("Received command: %s", code)
    assert(loadstring(code))(reader, writer)
end

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

-- pktin handler that decides if the packet needs to be consumed
-- by the switch or it needs to be sent to the controller
-- Todo: Add packet parsing

function pktin(reader, writer, reason, metadata)
    log("Received pktin with reason: %u, metadata: %u", reason, metadata)
    writer.bool(1)
end

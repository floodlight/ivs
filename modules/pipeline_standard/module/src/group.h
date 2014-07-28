/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#ifndef PIPELINE_STANDARD_GROUP_H
#define PIPELINE_STANDARD_GROUP_H

struct group_bucket {
    struct xbuf actions;
};

struct group_value {
    uint16_t num_buckets;
    struct group_bucket *buckets;
};

struct group {
    uint32_t id;
    uint8_t type;
    struct group_value value;
};

void pipeline_standard_group_register(void);
void pipeline_standard_group_unregister(void);

#endif

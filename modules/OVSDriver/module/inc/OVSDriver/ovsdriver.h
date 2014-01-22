/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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

#ifndef __OVSDRIVER_H__
#define __OVSDRIVER_H__

struct xbuf;
struct ind_ovs_cfr;

indigo_error_t ind_ovs_init(const char *datapath_name);
void ind_ovs_finish(void);

indigo_error_t ind_ovs_tunnel_init(void);

/*
 * Exported from OVSDriver for use by the pipeline
 */
struct ind_ovs_flow_effects *ind_ovs_fwd_pipeline_lookup(int table_id, struct ind_ovs_cfr *cfr, struct xbuf *stats);


#endif

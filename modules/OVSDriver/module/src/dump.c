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

/*
 * Functions to log Netlink messages in human-readable form.
 *
 * Each set of OVS Netlink attributes has its own ind_ovs_dump_*_attr
 * function.
 */
#include "ovsdriver_log.h"
#include "ovs_driver_int.h"
#include <byteswap.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>
#include <endian.h>

#define FORMAT_MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define VALUE_MAC(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define FORMAT_IPV4 "%hhu.%hhu.%hhu.%hhu"
#define VALUE_IPV4(a) (a)[0],(a)[1],(a)[2],(a)[3]

#define output(fmt, ...) LOG_VERBOSE("%*s" fmt, indent*2, "", ##__VA_ARGS__)

#define leaf(attr_type, c_type, fmt, ...) \
    case attr_type: { \
        c_type __attribute__((unused)) *x = nla_data(attr); \
        output(#attr_type ": " fmt, ##__VA_ARGS__); \
        break; \
    }

#define unimplemented(attr_type) leaf(attr_type, void, "unimplemented")

#define nest_start(attr_type) output(#attr_type ":"); indent++
#define nest_end() indent--

static void ind_ovs_dump_unknown_attr(const struct nlattr *attr);

static __thread int indent = 0;

void
ind_ovs_dump_nested(const struct nlattr *key, void (*cb)(const struct nlattr *attr))
{
    struct nlattr *pos;
    int rem;
    nla_for_each_nested(pos, key, rem) {
        cb(pos);
    }
}

void
ind_ovs_dump_dp_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
    leaf(OVS_DP_ATTR_NAME, char, "%s", x);
    leaf(OVS_DP_ATTR_UPCALL_PID, uint32_t, "%u", x);
    leaf(OVS_DP_ATTR_STATS, struct ovs_dp_stats,
         "hit=%"PRIu64" miss=%"PRIu64" lost=%"PRIu64" flows=%"PRIu64,
         x->n_hit, x->n_missed, x->n_lost, x->n_flows);
    default: ind_ovs_dump_unknown_attr(attr);
    }
}

void
ind_ovs_dump_packet_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
    leaf(OVS_PACKET_ATTR_PACKET, void, "len=%u", nla_len(attr));

    case OVS_PACKET_ATTR_KEY:
        nest_start(OVS_PACKET_ATTR_KEY);
        ind_ovs_dump_nested(attr, ind_ovs_dump_key_attr);
        nest_end();
        break;

    case OVS_PACKET_ATTR_ACTIONS:
        nest_start(OVS_PACKET_ATTR_ACTIONS);
        ind_ovs_dump_nested(attr, ind_ovs_dump_action_attr);
        nest_end();
        break;

    leaf(OVS_PACKET_ATTR_USERDATA, uint64_t, "%"PRIu64, *x);
    default: ind_ovs_dump_unknown_attr(attr);
    }
}

static const char *
ind_ovs_vport_type_str(uint32_t type)
{
    switch (type) {
    case OVS_VPORT_TYPE_NETDEV: return "netdev";
    case OVS_VPORT_TYPE_INTERNAL: return "internal";
    case OVS_VPORT_TYPE_GRE: return "gre";
    default: return "unknown";
    }
}

void
ind_ovs_dump_vport_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
    leaf(OVS_VPORT_ATTR_PORT_NO, uint32_t, "%u", *x);
    leaf(OVS_VPORT_ATTR_TYPE, uint32_t, "%u (%s)", *x, ind_ovs_vport_type_str(*x));
    leaf(OVS_VPORT_ATTR_NAME, char, "%s", x);
    leaf(OVS_VPORT_ATTR_UPCALL_PID, uint32_t, "%u", *x);
    leaf(OVS_VPORT_ATTR_STATS, struct ovs_vport_stats,
         "rx (%"PRIu64"/%"PRIu64"/%"PRIu64"/%"PRIu64") "
         "tx (%"PRIu64"/%"PRIu64"/%"PRIu64"/%"PRIu64")",
         x->rx_packets, x->rx_bytes, x->rx_errors, x->rx_dropped,
         x->tx_packets, x->tx_bytes, x->tx_errors, x->tx_dropped);

    case OVS_VPORT_ATTR_OPTIONS:
        if (nla_len(attr) > 0) {
            nest_start(OVS_VPORT_ATTR_OPTIONS);
            /* TODO options attr namespace depends on port type, which is hard to
            * get from here. For now assume tunnel options. */
            nest_end();
        }
        break;

    default: ind_ovs_dump_unknown_attr(attr);
    }
}

void ind_ovs_dump_tunnel_key_attr(const struct nlattr *attr);

void
ind_ovs_dump_key_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
        case OVS_KEY_ATTR_ENCAP:
            nest_start(OVS_KEY_ATTR_ENCAP);
            ind_ovs_dump_nested(attr, ind_ovs_dump_key_attr);
            nest_end();
            break;

        case OVS_KEY_ATTR_TUNNEL:
            nest_start(OVS_KEY_ATTR_TUNNEL);
            ind_ovs_dump_nested(attr, ind_ovs_dump_tunnel_key_attr);
            nest_end();
            break;

        leaf(OVS_KEY_ATTR_PRIORITY, uint32_t, "%u", *x);
        leaf(OVS_KEY_ATTR_IN_PORT, uint32_t, "%u", *x);
        leaf(OVS_KEY_ATTR_ETHERNET, struct ovs_key_ethernet,
             "src=" FORMAT_MAC " dst=" FORMAT_MAC,
             VALUE_MAC(x->eth_src), VALUE_MAC(x->eth_dst));
        leaf(OVS_KEY_ATTR_VLAN, uint16_t,
             "vid=%u pcp=%u",
             VLAN_VID(ntohs(*x)), VLAN_PCP(ntohs(*x)));
        leaf(OVS_KEY_ATTR_ETHERTYPE, uint16_t, "%#.4hx", ntohs(*x));
        leaf(OVS_KEY_ATTR_IPV4, struct ovs_key_ipv4,
             "proto=%u src=" FORMAT_IPV4 " dst=" FORMAT_IPV4 " tos=%hhu",
             x->ipv4_proto,
             VALUE_IPV4((uint8_t *)&x->ipv4_src),
             VALUE_IPV4((uint8_t *)&x->ipv4_dst),
             x->ipv4_tos);
        case OVS_KEY_ATTR_IPV6: {
            struct ovs_key_ipv6 *x = nla_data(attr);
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, x->ipv6_src, src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, x->ipv6_dst, dst, INET6_ADDRSTRLEN);
            output("OVS_KEY_ATTR_IPV6: proto=%hhu src=%s dst=%s label=%u tclass=%hhu",
                   x->ipv6_proto, src, dst, ntohl(x->ipv6_label), x->ipv6_tclass);
            break;
        }
        leaf(OVS_KEY_ATTR_TCP, struct ovs_key_tcp,
             "src=%hu dst=%hu", ntohs(x->tcp_src), ntohs(x->tcp_dst));
        leaf(OVS_KEY_ATTR_UDP, struct ovs_key_udp,
             "src=%hu dst=%hu", ntohs(x->udp_src), ntohs(x->udp_dst));
        leaf(OVS_KEY_ATTR_ICMP, struct ovs_key_icmp,
             "type=%hhu code=%hhu", x->icmp_type, x->icmp_code);
        leaf(OVS_KEY_ATTR_ICMPV6, struct ovs_key_icmpv6,
             "type=%hhu code=%hhu", x->icmpv6_type, x->icmpv6_code);
        leaf(OVS_KEY_ATTR_ARP, struct ovs_key_arp,
             "op=%hu sip="FORMAT_IPV4" tip="FORMAT_IPV4" sha="FORMAT_MAC" tha="FORMAT_MAC,
             ntohs(x->arp_op),
             VALUE_IPV4((uint8_t *)&x->arp_sip),
             VALUE_IPV4((uint8_t *)&x->arp_tip),
             VALUE_MAC(x->arp_sha),
             VALUE_MAC(x->arp_tha));
        unimplemented(OVS_KEY_ATTR_ND);
        default: ind_ovs_dump_unknown_attr(attr);
    }
}

void
ind_ovs_dump_tunnel_key_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
        leaf(OVS_TUNNEL_KEY_ATTR_ID, uint64_t, "0x%"PRIx64, be64toh(*x));
        leaf(OVS_TUNNEL_KEY_ATTR_IPV4_SRC, uint8_t, FORMAT_IPV4, VALUE_IPV4(x));
        leaf(OVS_TUNNEL_KEY_ATTR_IPV4_DST, uint8_t, FORMAT_IPV4, VALUE_IPV4(x));
        leaf(OVS_TUNNEL_KEY_ATTR_TOS, uint8_t, "%hhu", *x);
        leaf(OVS_TUNNEL_KEY_ATTR_TTL, uint8_t, "%hhu", *x);
        leaf(OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT, void, "");
        leaf(OVS_TUNNEL_KEY_ATTR_CSUM, void, "");
        default: ind_ovs_dump_unknown_attr(attr);
    }
}

void
ind_ovs_dump_flow_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
    case OVS_FLOW_ATTR_KEY:
        nest_start(OVS_FLOW_ATTR_KEY);
        ind_ovs_dump_nested(attr, ind_ovs_dump_key_attr);
        nest_end();
        break;

    case OVS_FLOW_ATTR_ACTIONS:
        nest_start(OVS_FLOW_ATTR_ACTIONS);
        ind_ovs_dump_nested(attr, ind_ovs_dump_action_attr);
        nest_end();
        break;

    leaf(OVS_FLOW_ATTR_STATS, struct ovs_flow_stats,
         "pkts=%"PRIu64" bytes=%"PRIu64, x->n_packets, x->n_bytes);
    leaf(OVS_FLOW_ATTR_TCP_FLAGS, uint8_t, "%#hhx", *x);
    leaf(OVS_FLOW_ATTR_USED, uint64_t, "%"PRIu64, *x);
    leaf(OVS_FLOW_ATTR_CLEAR, void, "");
    default: ind_ovs_dump_unknown_attr(attr);
    }
}

void
ind_ovs_dump_userspace_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
        leaf(OVS_USERSPACE_ATTR_PID, uint32_t, "%"PRIu32, *x);
        leaf(OVS_USERSPACE_ATTR_USERDATA, uint64_t, "%"PRIu64, *x);
        default: ind_ovs_dump_unknown_attr(attr);
    }
}

void
ind_ovs_dump_sample_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
        leaf(OVS_SAMPLE_ATTR_PROBABILITY, uint32_t, "%u", *x);

        case OVS_SAMPLE_ATTR_ACTIONS:
            nest_start(OVS_ACTION_ATTR_ACTIONS);
            ind_ovs_dump_nested(attr, ind_ovs_dump_action_attr);
            nest_end();
            break;

        default: ind_ovs_dump_unknown_attr(attr);
    }
}

void
ind_ovs_dump_action_attr(const struct nlattr *attr)
{
    switch (nla_type(attr)) {
        leaf(OVS_ACTION_ATTR_OUTPUT, uint32_t, "port=%u", *x);

        case OVS_ACTION_ATTR_USERSPACE:
            nest_start(OVS_ACTION_ATTR_USERSPACE);
            ind_ovs_dump_nested(attr, ind_ovs_dump_userspace_attr);
            nest_end();
            break;

        case OVS_ACTION_ATTR_SET:
            nest_start(OVS_ACTION_ATTR_SET);
            ind_ovs_dump_nested(attr, ind_ovs_dump_key_attr);
            nest_end();
            break;

        leaf(OVS_ACTION_ATTR_PUSH_VLAN, struct ovs_action_push_vlan,
             "tpid=%#.4hx vid=%u pcp=%u cfi=%u",
             ntohs(x->vlan_tpid), VLAN_VID(ntohs(x->vlan_tci)),
             VLAN_PCP(ntohs(x->vlan_tci)), !!(ntohs(x->vlan_tci) & VLAN_CFI_BIT));

        leaf(OVS_ACTION_ATTR_POP_VLAN, void, "");

        case OVS_ACTION_ATTR_SAMPLE:
            nest_start(OVS_ACTION_ATTR_SAMPLE);
            ind_ovs_dump_nested(attr, ind_ovs_dump_sample_attr);
            nest_end();
            break;

        default: ind_ovs_dump_unknown_attr(attr);
    }
}

static void
ind_ovs_dump_unknown_attr(const struct nlattr *attr)
{
    output("unknown attribute type=%u len=%u", nla_type(attr), nla_len(attr));
}

#define ARRAYSIZE(x) (sizeof(x)/sizeof(x[0]))

#define cmd(x) [x] = #x

static const char *dp_cmds[] = {
    cmd(OVS_DP_CMD_NEW),
    cmd(OVS_DP_CMD_DEL),
    cmd(OVS_DP_CMD_GET),
    cmd(OVS_DP_CMD_SET),
};

static const char *packet_cmds[] = {
    cmd(OVS_PACKET_CMD_MISS),
    cmd(OVS_PACKET_CMD_ACTION),
    cmd(OVS_PACKET_CMD_EXECUTE),
};

static const char *vport_cmds[] = {
    cmd(OVS_VPORT_CMD_NEW),
    cmd(OVS_VPORT_CMD_DEL),
    cmd(OVS_VPORT_CMD_GET),
    cmd(OVS_VPORT_CMD_SET),
};

static const char *flow_cmds[] = {
    cmd(OVS_FLOW_CMD_NEW),
    cmd(OVS_FLOW_CMD_DEL),
    cmd(OVS_FLOW_CMD_GET),
    cmd(OVS_FLOW_CMD_SET),
};

#undef cmd

const char *
ind_ovs_cmd_str(int family, uint8_t cmd)
{
    const char **cmd_strs;
    int cmd_strs_size;

    if (family == ovs_datapath_family) {
        cmd_strs = dp_cmds;
        cmd_strs_size = ARRAYSIZE(dp_cmds);
    } else if (family == ovs_packet_family) {
        cmd_strs = packet_cmds;
        cmd_strs_size = ARRAYSIZE(packet_cmds);
    } else if (family == ovs_vport_family) {
        cmd_strs = vport_cmds;
        cmd_strs_size = ARRAYSIZE(vport_cmds);
    } else if (family == ovs_flow_family) {
        cmd_strs = flow_cmds;
        cmd_strs_size = ARRAYSIZE(flow_cmds);
    } else {
        abort();
    }

    if (cmd < cmd_strs_size && cmd_strs[cmd]) {
        return cmd_strs[cmd];
    } else {
        return NULL;
    }
}

static void
ind_ovs_dump_msg__(const struct nlmsghdr *nlh,
                   void (*attr_dumper)(const struct nlattr *attr))
{
    struct nlattr *pos;
    int rem;
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    const char *cmd_str = ind_ovs_cmd_str(nlh->nlmsg_type, gnlh->cmd);
    if (cmd_str != NULL) {
        output("%s:", cmd_str);
    } else {
        output("Unknown command %u:", gnlh->cmd);
    }
    indent++;
    nlmsg_for_each_attr(pos, nlh, sizeof(struct ovs_header) + sizeof(struct genlmsghdr), rem) {
        attr_dumper(pos);
    }
    indent--;
}

void
ind_ovs_dump_msg(const struct nlmsghdr *nlh)
{
    int family = nlh->nlmsg_type;

    if (!aim_log_fid_get(AIM_LOG_STRUCT_POINTER, AIM_LOG_FLAG_VERBOSE)) {
        /* Exit early if we wouldn't log anything */
        return;
    }

    if (family == ovs_datapath_family) {
        ind_ovs_dump_msg__(nlh, ind_ovs_dump_dp_attr);
    } else if (family == ovs_packet_family) {
        ind_ovs_dump_msg__(nlh, ind_ovs_dump_packet_attr);
    } else if (family == ovs_vport_family) {
        ind_ovs_dump_msg__(nlh, ind_ovs_dump_vport_attr);
    } else if (family == ovs_flow_family) {
        ind_ovs_dump_msg__(nlh, ind_ovs_dump_flow_attr);
    } else {
        LOG_ERROR("unknown message family %d", family);
    }
}

void
ind_ovs_dump_key(const struct nlattr *key)
{
    indent++;
    ind_ovs_dump_nested(key, ind_ovs_dump_key_attr);
    indent--;
}

/* Not a Netlink message, but uses some of the dump helpers */
void
ind_ovs_dump_cfr(const struct ind_ovs_cfr *cfr)
{
    if (!aim_log_fid_get(AIM_LOG_STRUCT_POINTER, AIM_LOG_FLAG_VERBOSE)) {
        /* Exit early if we wouldn't log anything */
        return;
    }

    indent++;
    output("dl_dst="FORMAT_MAC, VALUE_MAC(cfr->dl_dst));
    output("dl_src="FORMAT_MAC, VALUE_MAC(cfr->dl_src));
    output("in_port=%u", cfr->in_port);
    output("dl_type=0x%04x", ntohs(cfr->dl_type));
    output("dl_vlan=0x%04x", ntohs(cfr->dl_vlan));
    output("nw_tos=0x%x", cfr->nw_tos);
    output("nw_proto=0x%x", cfr->nw_proto);
    output("nw_src="FORMAT_IPV4, VALUE_IPV4((uint8_t *)&cfr->nw_src));
    output("nw_dst="FORMAT_IPV4, VALUE_IPV4((uint8_t *)&cfr->nw_dst));
    output("tp_src=%u", cfr->tp_src);
    output("tp_dst=%u", cfr->tp_dst);

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, cfr->ipv6_src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, cfr->ipv6_dst, dst, INET6_ADDRSTRLEN);
    output("ipv6_src=%s", src);
    output("ipv6_dst=%s", dst);

    output("in_ports=%08x%08x%08x%08x", cfr->in_ports[0], cfr->in_ports[1],
                                        cfr->in_ports[2], cfr->in_ports[3]);

    output("lag_id=%u", cfr->lag_id);
    output("vrf=%u", cfr->vrf);
    output("l3_interface_class_id=%u", cfr->l3_interface_class_id);
    output("l3_src_class_id=%u", cfr->l3_src_class_id);
    output("l3_dst_class_id=%u", cfr->l3_dst_class_id);
    output("global_vrf_allowed=%u", cfr->global_vrf_allowed);
    output("egr_port_group_id=%u", cfr->egr_port_group_id);

    indent--;
}

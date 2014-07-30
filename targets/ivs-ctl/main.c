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

/******************************************************************************
 *
 *  ivs-ctl
 *
 *  A tool to add/remove interfaces and view basic information about the switch.
 *  Designed to be compatible with a small subset of ovs-vsctl/ovs-dpctl syntax.
 *
 *****************************************************************************/
#include <stdio.h>
#include <inttypes.h>
#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/un.h>
#include "openvswitch.h"

static int transact(struct nl_sock *sk, struct nl_msg *msg);

static int ovs_datapath_family, ovs_packet_family, ovs_vport_family, ovs_flow_family;
static struct nl_sock *sk, *sk2;

static const char *datapath_name = "indigo";

static void help(void)
{
    fprintf(stderr, "usage: ivs-ctl COMMAND [ARG..]\n");
    fprintf(stderr, "  help: show this message\n");
    fprintf(stderr, "  show: print information about each datapath\n");
    fprintf(stderr, "  add-port INTERFACE: add a port to the datapath\n");
    fprintf(stderr, "  add-internal-port INTERFACE: add an internal port to the datapath\n");
    fprintf(stderr, "  del-port INTERFACE: delete a port from the datapath\n");
    fprintf(stderr, "  cli ...: run an internal CLI command\n");
    fprintf(stderr, "  dump-flows: print information about each kernel flow\n");
}

static void
parse_options(int argc, char **argv)
{
    while (1) {
        int option_index = 0;

        /* Options without short equivalents */
        enum long_opts {
            OPT_START = 256,
            OPT_DATAPATH,
        };

        static struct option long_options[] = {
            {"help",        no_argument,       0,  'h' },
            /* Undocumented options */
            {"datapath",    required_argument, 0,  OPT_DATAPATH },
            {0,             0,                 0,  0 }
        };

        int c = getopt_long(argc, argv, "h",
                            long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DATAPATH:
            datapath_name = strdup(optarg);
            break;

        case 'h':
        case '?':
            help();
            exit(c == '?');
        }
    }
}

static const char *
vport_type_str__(uint32_t type)
{
    switch (type) {
    case OVS_VPORT_TYPE_NETDEV: return "";
    case OVS_VPORT_TYPE_INTERNAL: return "(internal)";
    case OVS_VPORT_TYPE_GRE: return "(gre)";
    case OVS_VPORT_TYPE_GRE64: return "(gre64)";
    default: return "(unknown vport type)";
    }
}

static int
show_vport__(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[OVS_VPORT_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                    attrs, OVS_VPORT_ATTR_MAX,
                    NULL) < 0) {
        abort();
    }

    fprintf(stderr, "    %d %s %s\n",
            nla_get_u32(attrs[OVS_VPORT_ATTR_PORT_NO]),
            (char *)nla_data(attrs[OVS_VPORT_ATTR_NAME]),
            vport_type_str__(nla_get_u32(attrs[OVS_VPORT_ATTR_TYPE])));

    struct ovs_vport_stats *stats = nla_data(attrs[OVS_VPORT_ATTR_STATS]);
    fprintf(stderr, "      rx: packets=%"PRIu64" bytes=%"PRIu64" errors=%"PRIu64" dropped=%"PRIu64"\n",
            (uint64_t)stats->rx_packets, (uint64_t)stats->rx_bytes,
            (uint64_t)stats->rx_errors, (uint64_t)stats->rx_dropped);
    fprintf(stderr, "      tx: packets=%"PRIu64" bytes=%"PRIu64" errors=%"PRIu64" dropped=%"PRIu64"\n",
            (uint64_t)stats->tx_packets, (uint64_t)stats->tx_bytes,
            (uint64_t)stats->tx_errors, (uint64_t)stats->tx_dropped);

    return NL_OK;
}

static void
show_vports__(int dp_ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_vport_family, sizeof(*hdr),
                                         NLM_F_DUMP, OVS_VPORT_CMD_GET, OVS_VPORT_VERSION);
    hdr->dp_ifindex = dp_ifindex;
    if (nl_send_auto(sk2, msg) < 0) {
        abort();
    }

    nl_socket_modify_cb(sk2, NL_CB_VALID, NL_CB_CUSTOM, show_vport__, NULL);
    nl_recvmsgs_default(sk2);

    nlmsg_free(msg);
}

static int
show_datapath__(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    struct ovs_header *hdr = (void *)(gnlh + 1);
    struct nlattr *attrs[OVS_DP_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                    attrs, OVS_DP_ATTR_MAX,
                    NULL) < 0) {
        abort();
    }

    struct ovs_dp_stats *stats = nla_data(attrs[OVS_DP_ATTR_STATS]);

    fprintf(stderr, "%s:\n", (char *)nla_data(attrs[OVS_DP_ATTR_NAME]));
    fprintf(stderr, "  kernel lookups: hit=%"PRIu64" missed=%"PRIu64" lost=%"PRIu64"\n",
            (uint64_t)stats->n_hit, (uint64_t)stats->n_missed,
            (uint64_t)stats->n_lost);
    fprintf(stderr, "  kernel flows=%"PRIu64"\n", (uint64_t)stats->n_flows);
    fprintf(stderr, "  ports:\n");
    show_vports__(hdr->dp_ifindex);

    return NL_OK;
}

static void
show(void)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_datapath_family, sizeof(*hdr),
                                         NLM_F_DUMP, OVS_DP_CMD_GET, OVS_DATAPATH_VERSION);
    hdr->dp_ifindex = 0;
    if (nl_send_auto(sk, msg) < 0) {
        abort();
    }

    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, show_datapath__, NULL);
    nl_recvmsgs_default(sk);
}

static void
add_port(const char *datapath, const char *interface)
{
    unsigned int dp_ifindex = if_nametoindex(datapath);
    if (dp_ifindex == 0) {
        fprintf(stderr, "Failed: no such datapath '%s'\n", datapath);
        exit(1);
    }

    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_vport_family, sizeof(*hdr),
                                         NLM_F_ACK, OVS_VPORT_CMD_NEW,
                                         OVS_VPORT_VERSION);
    hdr->dp_ifindex = dp_ifindex;
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_NETDEV);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, interface);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    int err = transact(sk, msg);
    if (err) {
        fprintf(stderr, "Failed: %s\n", strerror(-err));
        exit(1);
    }
}

static void
add_internal_port(const char *datapath, const char *interface)
{
    if (strlen(interface) > IFNAMSIZ) {
        fprintf(stderr, "Failed: Interface name too long\n");
        exit(1);
    }

    unsigned int dp_ifindex = if_nametoindex(datapath);
    if (dp_ifindex == 0) {
        fprintf(stderr, "Failed: no such datapath '%s'\n", datapath);
        exit(1);
    }

    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_vport_family, sizeof(*hdr),
                                         NLM_F_ACK, OVS_VPORT_CMD_NEW,
                                         OVS_VPORT_VERSION);
    hdr->dp_ifindex = dp_ifindex;
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_INTERNAL);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, interface);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    int err = transact(sk, msg);
    if (err) {
        fprintf(stderr, "Failed: %s\n", strerror(-err));
        exit(1);
    }
}

static void
del_port(const char *datapath, const char *interface)
{
    unsigned int dp_ifindex = if_nametoindex(datapath);
    if (dp_ifindex == 0) {
        fprintf(stderr, "Failed: no such datapath '%s'\n", datapath);
        exit(1);
    }

    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_vport_family, sizeof(*hdr),
                                         NLM_F_ACK, OVS_VPORT_CMD_DEL,
                                         OVS_VPORT_VERSION);
    hdr->dp_ifindex = dp_ifindex;
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, interface);
    int err = transact(sk, msg);

    /*
     * HACK the OVS kernel module had a bug (fixed by rlane in d5c9288d) which
     * returned random values on success. Work around this by assuming the
     * operation was successful if the kernel returned an invalid errno.
     */
    if (err > 0 || err < -4095) {
        err = 0;
    }

    if (err) {
        fprintf(stderr, "Failed: %s\n", strerror(-err));
        exit(1);
    }
}

static void
del_dp(const char *datapath)
{
    unsigned int dp_ifindex = if_nametoindex(datapath);
    if (dp_ifindex == 0) {
        fprintf(stderr, "Failed: no such datapath '%s'\n", datapath);
        exit(1);
    }

    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_datapath_family, sizeof(*hdr),
                                         NLM_F_ACK, OVS_DP_CMD_DEL,
                                         OVS_DATAPATH_VERSION);
    hdr->dp_ifindex = dp_ifindex;
    int err = transact(sk, msg);
    if (err) {
        fprintf(stderr, "Failed: %s\n", strerror(-err));
        exit(1);
    }
}

static void
cli(int argc, char **argv)
{
    char path[UNIX_PATH_MAX];
    snprintf(path, sizeof(path), "/var/run/ivs-ucli.%s.sock", datapath_name);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    strcpy(saddr.sun_path, path);

    if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("connect");
        exit(1);
    }

    FILE *f = fdopen(fd, "r+");
    if (f == NULL) {
        perror("fdopen");
        exit(1);
    }

    int i;
    for (i = 0; i < argc; i++) {
        fprintf(f, "%s ", argv[i]);
    }
    fprintf(f, "\n");

    fflush(f);
    shutdown(fd, SHUT_WR);

    char buf[1024];
    int c;
    while ((c = fread(buf, 1, sizeof(buf), f)) > 0) {
        fwrite(buf, c, 1, stdout);
    }

    fclose(f);
}

#define FORMAT_MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define VALUE_MAC(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define FORMAT_IPV4 "%hhu.%hhu.%hhu.%hhu"
#define VALUE_IPV4(a) (a)[0],(a)[1],(a)[2],(a)[3]

static void
output_key(struct nlattr *attr)
{
    struct nlattr *key_attrs[OVS_KEY_ATTR_MAX+1];
    if (nla_parse_nested(key_attrs, OVS_KEY_ATTR_MAX, attr, NULL) < 0) {
        abort();
    }

#define key(attr_type, c_type, fmt, ...) \
    if (key_attrs[attr_type]) { \
        c_type __attribute__((unused)) *x = nla_data(key_attrs[attr_type]); \
        printf(fmt " ", ##__VA_ARGS__); \
    }

    key(OVS_KEY_ATTR_IN_PORT, uint32_t, "port=%u", *x);

    key(OVS_KEY_ATTR_ETHERNET, struct ovs_key_ethernet,
            "eth src=" FORMAT_MAC " dst=" FORMAT_MAC,
            VALUE_MAC(x->eth_src), VALUE_MAC(x->eth_dst));
    key(OVS_KEY_ATTR_VLAN, uint16_t,
            "vlan=%u pcp=%u",
            ntohs(*x) & 0xfff, ntohs(*x) >> 13);

    if (key_attrs[OVS_KEY_ATTR_ENCAP]) {
        output_key(key_attrs[OVS_KEY_ATTR_ENCAP]);
    } else {
        key(OVS_KEY_ATTR_ETHERTYPE, uint16_t, "type=%#.4hx", ntohs(*x));
    }

    key(OVS_KEY_ATTR_IPV4, struct ovs_key_ipv4,
            "ipv4 src=" FORMAT_IPV4 " dst=" FORMAT_IPV4 " tos=%hhu ttl=%u proto=%u",
            VALUE_IPV4((uint8_t *)&x->ipv4_src),
            VALUE_IPV4((uint8_t *)&x->ipv4_dst),
            x->ipv4_tos,
            x->ipv4_ttl,
            x->ipv4_proto);

    key(OVS_KEY_ATTR_TCP, struct ovs_key_tcp,
            "tcp src=%hu dst=%hu", ntohs(x->tcp_src), ntohs(x->tcp_dst));
    key(OVS_KEY_ATTR_TCP_FLAGS, uint16_t,
            "flags=%#x", ntohs(*x));
    key(OVS_KEY_ATTR_UDP, struct ovs_key_udp,
            "udp src=%hu dst=%hu", ntohs(x->udp_src), ntohs(x->udp_dst));
    key(OVS_KEY_ATTR_SCTP, struct ovs_key_sctp,
            "sctp src=%hu dst=%hu", ntohs(x->sctp_src), ntohs(x->sctp_dst));
    key(OVS_KEY_ATTR_ICMP, struct ovs_key_icmp,
            "icmp type=%hhu code=%hhu", x->icmp_type, x->icmp_code);
    key(OVS_KEY_ATTR_ICMPV6, struct ovs_key_icmpv6,
            "icmpv6 type=%hhu code=%hhu", x->icmpv6_type, x->icmpv6_code);
    key(OVS_KEY_ATTR_ARP, struct ovs_key_arp,
            "arp op=%hu sip="FORMAT_IPV4" tip="FORMAT_IPV4" sha="FORMAT_MAC" tha="FORMAT_MAC,
            ntohs(x->arp_op),
            VALUE_IPV4((uint8_t *)&x->arp_sip),
            VALUE_IPV4((uint8_t *)&x->arp_tip),
            VALUE_MAC(x->arp_sha),
            VALUE_MAC(x->arp_tha));
#undef key
}

static void
output_actions(struct nlattr *parent)
{
    struct nlattr *attr;
    int rem;
    nla_for_each_nested(attr, parent, rem) {
        switch (nla_type(attr)) {
        case OVS_ACTION_ATTR_OUTPUT:
            printf("output %d", nla_get_u32(attr));
            break;
        case OVS_ACTION_ATTR_USERSPACE:
            printf("pktin");
            break;
        case OVS_ACTION_ATTR_POP_VLAN:
            printf("pop-vlan");
            break;
        case OVS_ACTION_ATTR_PUSH_VLAN: {
            struct ovs_action_push_vlan *x = nla_data(attr);
            printf("push-vlan { vid=%u pcp=%d }", ntohs(x->vlan_tci) & 0xfff, ntohs(x->vlan_tci) >> 13);
            break;
        }
        case OVS_ACTION_ATTR_SET:
            printf("set { ");
            output_key(attr);
            printf("}");
            break;
        default:
            printf("?");
            break;
        }
        printf(" ");
    }
}

static int
show_kflow__(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[OVS_FLOW_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                    attrs, OVS_FLOW_ATTR_MAX,
                    NULL) < 0) {
        abort();
    }

    output_key(attrs[OVS_FLOW_ATTR_KEY]);
    printf("-> ");
    output_actions(attrs[OVS_FLOW_ATTR_ACTIONS]);
    printf("\n");

    return NL_OK;
}

static void
dump_flows(const char *datapath)
{
    unsigned int dp_ifindex = if_nametoindex(datapath);
    if (dp_ifindex == 0) {
        fprintf(stderr, "Failed: no such datapath '%s'\n", datapath);
        exit(1);
    }

    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_flow_family, sizeof(*hdr),
                                         NLM_F_DUMP, OVS_FLOW_CMD_GET, OVS_FLOW_VERSION);
    hdr->dp_ifindex = dp_ifindex;
    if (nl_send_auto(sk2, msg) < 0) {
        abort();
    }

    nl_socket_modify_cb(sk2, NL_CB_VALID, NL_CB_CUSTOM, show_kflow__, NULL);
    nl_recvmsgs_default(sk2);

    nlmsg_free(msg);
}

static struct nl_sock *
create_genl_socket(void)
{
    int ret;
    struct nl_sock *sk = nl_socket_alloc();
    if (sk == NULL) {
        fprintf(stderr, "Failed to allocate netlink socket\n");
        abort();
    }

    if ((ret = genl_connect(sk)) != 0) {
        fprintf(stderr, "Failed to connect netlink socket: %s\n", nl_geterror(ret));
        abort();
    }

    return sk;
}

int
main(int argc, char *argv[])
{
    sk = create_genl_socket();
    sk2 = create_genl_socket();

    /* Resolve generic netlink families. */
    ovs_datapath_family = genl_ctrl_resolve(sk, OVS_DATAPATH_FAMILY);
    ovs_packet_family = genl_ctrl_resolve(sk, OVS_PACKET_FAMILY);
    ovs_vport_family = genl_ctrl_resolve(sk, OVS_VPORT_FAMILY);
    ovs_flow_family = genl_ctrl_resolve(sk, OVS_FLOW_FAMILY);
    if (ovs_datapath_family < 0 || ovs_packet_family < 0 ||
        ovs_vport_family < 0 || ovs_flow_family < 0) {
        fprintf(stderr, "Failed to resolve Open vSwitch generic netlink families; module not loaded?\n");
        return 1;
    }

    parse_options(argc, argv);

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        help();
        return 1;
    }

    const char *cmd = argv[0];

    if (!strcmp(cmd, "help")) {
        help();
    } else if (!strcmp(cmd, "show")) {
        show();
    } else if (!strcmp(cmd, "add-port") ||!strcmp(cmd, "add-if")) {
        if (argc != 2) {
            fprintf(stderr, "Wrong number of arguments for the %s command (try help)\n", cmd);
            return 1;
        }
        add_port(datapath_name, argv[1]);
    } else if (!strcmp(cmd, "add-internal-port")) {
        if (argc != 2) {
            fprintf(stderr, "Wrong number of arguments for the %s command (try help)\n", cmd);
            return 1;
        }
        add_internal_port(datapath_name, argv[1]);
    } else if (!strcmp(cmd, "del-port") ||!strcmp(cmd, "del-if")) {
        if (argc != 2) {
            fprintf(stderr, "Wrong number of arguments for the %s command (try help)\n", cmd);
            return 1;
        }
        del_port(datapath_name, argv[1]);
    } else if (!strcmp(cmd, "del-br") ||!strcmp(cmd, "del-dp")) {
        if (argc != 1) {
            fprintf(stderr, "Wrong number of arguments for the %s command (try help)\n", cmd);
            return 1;
        }
        del_dp(datapath_name);
    } else if (!strcmp(cmd, "cli")) {
        cli(argc-1, argv+1);
    } else if (!strcmp(cmd, "dump-flows")) {
        if (argc != 1) {
            fprintf(stderr, "Wrong number of arguments for the %s command (try help)\n", cmd);
            return 1;
        }
        dump_flows(datapath_name);
    } else {
        fprintf(stderr, "Unknown command '%s' (try help)\n", cmd);
        return 1;
    }

    return 0;
}

/* Replacement for nl_send_sync that returns the real error code */
static int
transact(struct nl_sock *sk, struct nl_msg *msg)
{
    if (nl_send_auto(sk, msg) < 0) {
        return -EBADE;
    }
    nlmsg_free(msg);

    struct nlmsghdr *reply;
    struct sockaddr_nl nla;
    if (nl_recv(sk, &nla, (unsigned char **)&reply, NULL) < 0) {
        return -EBADE;
    }

    assert(reply->nlmsg_type == NLMSG_ERROR);
    int err = ((struct nlmsgerr *)nlmsg_data(reply))->error;
    free(reply);

    return err;
}

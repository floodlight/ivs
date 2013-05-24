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
 * Benchmark upcall throughput
 *
 * Sends packets as fast as possible through multiple ports and measures
 * the rate they're received at the destination port.
 *
 * This benchmark requires a connected controller that does MAC-learning, and
 * two ports connected to the switch.
 *
 * example:
 *   floodlight &
 *   ivs -c 127.0.0.1 -i veth0 -i veth2 -i veth4 -i veth6 &
 *   upcall-throughput veth1 veth3 veth5 veth7
 *
 * If OUTPUT_FILENAME is set the data will be written to that file, which can
 * be graphed with plot-throughput.gnuplot.
 */

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>

#ifndef _LINUX_IF_H
/* Some versions of libnetlink include linux/if.h, which conflicts with net/if.h. */
#include <net/if.h>
#endif

static struct nl_sock *nlsock;
static struct nl_cache *link_cache;
static FILE *output;
static volatile int finished = 0;

struct host {
    char ifname[IFNAMSIZ];
    uint8_t mac[ETH_ALEN];
    uint32_t ip;
};

struct tx_thread_arg {
    const struct host *src;
    const struct host *dst;
};

static void
generate_packet(uint8_t pkt[65536], int *pktlen,
                const uint8_t *src_mac, const uint8_t *dst_mac,
                uint32_t src_ip, uint32_t dst_ip)
{
    *pktlen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct ether_header *ether = (void *)pkt;
    memcpy(ether->ether_dhost, dst_mac, ETH_ALEN);
    memcpy(ether->ether_shost, src_mac, ETH_ALEN);
    ether->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (void*)(ether+1);
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(28);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->check = 0;
    ip->saddr = htonl(src_ip);
    ip->daddr = htonl(dst_ip);

    struct udphdr *udp = (void *)(ip+1);
    udp->source = 1;
    udp->dest = 0;
    udp->len = htons(8);
    udp->check = 0;
}

static void
update_packet(uint8_t pkt[65536], uint32_t v)
{
    struct ether_header *ether = (void *)pkt;
    struct iphdr *ip = (void*)(ether+1);
    struct udphdr *udp = (void *)(ip+1);
    udp->dest = htons(v & 0xFFFF);
    udp->source = htons(v >> 16);
}

static pcap_t *
create_pcap(const char *ifname)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_create(ifname, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        abort();
    }

    pcap_set_timeout(pcap, 10);

    if (pcap_activate(pcap) != 0) {
        pcap_perror(pcap, "pcap_activate");
        abort();
    }

    return pcap;
}

/*
 * Send traffic to cause the controller to install a flow from src to dst.
 * Assumes controller installs an L2 and/or L3 flow.
 */
static void
train_controller(const struct host *src, const struct host *dst)
{
    fprintf(stderr, "training %s -> %s\n", src->ifname, dst->ifname);

    pcap_t *src_pcap = create_pcap(src->ifname);
    pcap_t *dst_pcap = create_pcap(dst->ifname);

    uint8_t *pkt = malloc(65536);
    int pktlen;

    /* First advertise the dst host */
    generate_packet(pkt, &pktlen, dst->mac, src->mac, dst->ip, src->ip);
    pcap_inject(dst_pcap, pkt, pktlen);

    /* Now send traffic from src to dst */
    generate_packet(pkt, &pktlen, src->mac, dst->mac, src->ip, dst->ip);

    int i;
    int recvd = 0;
    const int n = 100;
    for (i = 0; i < n; i++) {
        /* Send a packet through the src interface */
        pcap_inject(src_pcap, pkt, pktlen);

        /* Receive the packet from the dst interface */
        /* Loop until we get the right one or timeout */
        while (1) {
            struct pcap_pkthdr *pkt_header;
            const uint8_t *pkt_data;
            int ret = pcap_next_ex(dst_pcap, &pkt_header, &pkt_data);
            if (ret == 1 && !memcmp(pkt_data, pkt, pktlen)) {
                recvd++;
                break;
            } else if (ret == 0) {
                break;
            }
        }

        usleep(1000);
    }

    pcap_close(src_pcap);
    pcap_close(dst_pcap);
    free(pkt);

    fprintf(stderr, "%s -> %s recvd %d/%d pkts during training\n", src->ifname, dst->ifname, recvd, n);

    if (recvd < n/2) {
        fprintf(stderr, "aborting due to failed training\n");
        abort();
    }
}

static void
run_tx(const struct host *src, const struct host *dst)
{
    int rawsock = socket(AF_PACKET, SOCK_RAW, 0);
    if (rawsock == -1) {
        perror("socket");
        abort();
    }

    struct ifreq ifreq;
    memset(&ifreq, 0, sizeof(ifreq));
    strncpy(ifreq.ifr_name, src->ifname, IFNAMSIZ);

    if(ioctl(rawsock, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl");
        abort();
    }

    struct sockaddr_ll saddr;
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = 0;
    saddr.sll_ifindex = ifreq.ifr_ifindex;

    if(bind(rawsock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        abort();
    }

    uint8_t *pkt = malloc(65536);
    int pktlen;
    generate_packet(pkt, &pktlen, src->mac, dst->mac, src->ip, dst->ip);

    uint32_t i = 0;
    while (!finished) {
        update_packet(pkt, i);
        if (send(rawsock, pkt, pktlen, 0) != pktlen) {
            perror("write");
            abort();
        }
        i++;
    }

    free(pkt);
}

static void *
start_tx_thread(void *_arg)
{
    struct tx_thread_arg *arg = _arg;
    run_tx(arg->src, arg->dst);
    return NULL;
}

uint64_t
monotonic_us(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return ((uint64_t)tp.tv_sec * 1000*1000) + (tp.tv_nsec / 1000);
}

static void get_rx_packets_iter(struct nl_object *obj, void *arg)
{
    struct rtnl_link *link = (struct rtnl_link *) obj;
    uint64_t *st = arg;
    *st = rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS);
}

static uint64_t get_rx_packets(const char *ifname)
{
    nl_cache_refill(nlsock, link_cache);
    struct rtnl_link *link_filter;
    link_filter = rtnl_link_alloc();
    rtnl_link_set_name(link_filter, (char *)ifname);
    uint64_t st = -1;
    nl_cache_foreach_filter(link_cache, OBJ_CAST(link_filter), get_rx_packets_iter, &st);
    rtnl_link_put(link_filter);
    return st;
}

static void
run_rx(const char *ifname)
{
    nlsock = nl_socket_alloc();
    nl_connect(nlsock, NETLINK_ROUTE);
    rtnl_link_alloc_cache(nlsock, AF_UNSPEC, &link_cache);
    nl_cache_mngt_provide(link_cache);

    if (getenv("OUTPUT_FILENAME")) {
        output = fopen(getenv("OUTPUT_FILENAME"), "w");
        if (!output) {
            fprintf(stderr, "WARNING: failed to open output file: %s\n", strerror(errno));
            abort();
        }
    }

    const uint64_t one_sec = 1000*1000;
    const uint64_t duration = one_sec * 10;
    const uint64_t interval = one_sec / 10;

    uint64_t start_rx_pkts = get_rx_packets(ifname);
    uint64_t start_time = monotonic_us();
    uint64_t last_rx_pkts = start_rx_pkts;
    uint64_t last_time = start_time;

    while (1) {
        uint64_t now = monotonic_us();
        if (now < last_time + interval) {
            usleep(interval + last_time - now);
            continue;
        }

        uint64_t elapsed = now - last_time;
        uint64_t rx_pkts = get_rx_packets(ifname);
        double pps = (rx_pkts - last_rx_pkts) / (elapsed * 1.0 / one_sec);

        fprintf(stderr, "%u pkt/s\n", (unsigned int)pps);

        if (output) {
            double time = 1.0*(now - start_time)/one_sec;
            fprintf(output, "%f %u\n", time, (unsigned int)pps);
        }

        last_rx_pkts = rx_pkts;
        last_time = now;

        if (now > start_time + duration) {
            double time = 1.0*(now - start_time)/one_sec;
            uint64_t total_rx_pkts = rx_pkts - start_rx_pkts;
            fprintf(stderr, "total: %"PRIu64" pkts in %f s (%u pkts/s)\n",
                    total_rx_pkts, time, (unsigned int)(total_rx_pkts/time));
            break;
        }
    }
}

static void
init_host(struct host *host, const char *ifname, const uint8_t *mac, uint32_t ip)
{
    strncpy(host->ifname, ifname, sizeof(host->ifname));
    memcpy(host->mac, mac, sizeof(host->mac));
    host->ip = ip;
}

int
main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s DST_INTERFACE SRC_INTERFACE...\n", argv[0]);
        return 1;
    }

    int num_tx_threads = argc - 2;

    uint8_t src_mac[] = { 0xaa, 0x3e, 0x8d, 0x56, 0xaf, 0x00 };
    uint8_t dst_mac[] = { 0xaa, 0x3e, 0x8d, 0x56, 0xaf, 0xff };
    uint32_t src_ip = 0xAC100100;
    uint32_t dst_ip = 0xAC1001FF;

    struct host dst;
    init_host(&dst, argv[1], dst_mac, dst_ip);

    struct host srcs[num_tx_threads];
    pthread_t tx_threads[num_tx_threads];

    int i;
    for (i = 0; i < num_tx_threads; i++) {
        src_mac[5]++;
        src_ip++;
        init_host(&srcs[i], argv[2+i], src_mac, src_ip);

        /* Make controller set up a flow from src to dst */
        train_controller(&srcs[i], &dst);
    }

    for (i = 0; i < num_tx_threads; i++) {
        /* Spawn a thread sending traffic */
        struct tx_thread_arg *arg = malloc(sizeof(*arg));
        arg->src = &srcs[i];
        arg->dst = &dst;
        pthread_create(&tx_threads[i], NULL, start_tx_thread, arg);
    }

    /* Measure the traffic received */
    run_rx(dst.ifname);

    /* Kill TX threads */
    finished = 1;
    __sync_synchronize();
    for (i = 0; i < num_tx_threads; i++) {
        pthread_join(tx_threads[i], NULL);
    }

    return 0;
}

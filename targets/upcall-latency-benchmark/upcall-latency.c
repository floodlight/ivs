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
 * Benchmark upcall latency
 *
 * Sends packets one at a time through one port and measures how long it takes
 * them to arrive at the other port.
 *
 * This benchmark requires a connected controller that does MAC-learning, and
 * two ports connected to the switch.
 *
 * example:
 *   floodlight &
 *   ivs -c 127.0.0.1 -i veth0 -i veth2 &
 *   upcall-latency veth1 veth3
 *
 * If OUTPUT_FILENAME is set the data will be written to that file, which can
 * be graphed with plot-latency.gnuplot.
 */

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

#define NUM_ITERS 10
#define NUM_WARMUP 100
#define NUM_PACKETS 10000
#define NUM_FLOWS 1000

pcap_t *src_pcap, *dst_pcap;

char pkt[65536];
int pktlen;

uint8_t src_mac[] = { 0xaa, 0x3e, 0x8d, 0x56, 0xaf, 0xdc };
uint8_t dst_mac[] = { 0x6a, 0xd9, 0x16, 0x9a, 0xb6, 0x3c };
uint32_t dst_ip = 0xAC100102;

bool verbose = false;
bool warmup;

uint32_t total_recvd;
uint32_t total_latency;

uint32_t latencies[NUM_PACKETS];

FILE *output;

static void
generate_initial_packet(void)
{
    pktlen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);

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
    ip->saddr = 0;
    ip->daddr = htonl(dst_ip);

    struct udphdr *udp = (void *)(ip+1);
    udp->source = getpid();
    udp->dest = 0;
    udp->len = htons(8);
    udp->check = 0;
}

static void
update_packet(uint32_t ip_src, uint16_t udp_dst)
{
    struct ether_header *ether = (void *)pkt;
    struct iphdr *ip = (void*)(ether+1);
    ip->saddr = htonl(ip_src);
    struct udphdr *udp = (void *)(ip+1);
    udp->dest = htons(udp_dst);
}

uint64_t
monotonic_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return ((uint64_t)tp.tv_sec * 1000*1000*1000) + tp.tv_nsec;
}

static void
advertise_dst(void)
{
    struct ether_header ether;
    memcpy(ether.ether_dhost, src_mac, ETH_ALEN);
    memcpy(ether.ether_shost, dst_mac, ETH_ALEN);
    ether.ether_type = htons(0xFFFF);
    pcap_inject(dst_pcap, (void*)&ether, sizeof(ether));
}

/*
 * Send packets from NUM_FLOWs hosts to the dst host to cause the controller
 * to insert NUM_FLOWS flows.
 */
static void
fill_flowtable(void)
{
    int drops = 0;
    int i;
    for (i = 0; i < NUM_FLOWS; i++) {
        uint8_t mac[] = { 0x6a, 0xd9, 0x16, 0x00, i>>8, i&0xFF };

        struct ether_header ether;
        memcpy(ether.ether_dhost, dst_mac, ETH_ALEN);
        memcpy(ether.ether_shost, mac, ETH_ALEN);
        ether.ether_type = htons(0xFFFF);

        /* Send packet */
        pcap_inject(src_pcap, (void*)&ether, sizeof(ether));

        /* Receive packet */
        while (1) {
            struct pcap_pkthdr *pkt_header;
            const uint8_t *pkt_data;
            int ret = pcap_next_ex(dst_pcap, &pkt_header, &pkt_data);
            if (ret == -1) {
                pcap_perror(dst_pcap, "pcap_next_ex");
                abort();
            } else if (ret == 1) {
                if (!memcmp(pkt_data, &ether, sizeof(ether))) {
                    break;
                }
            } else if (ret == 0) {
                drops++;
                break;
            }
        }
    }

    if (drops > 0) {
        fprintf(stderr, "dropped %u/%u packets while filling flowtable\n", drops, NUM_FLOWS);
    }
}

void
measure_latency(uint32_t ip_src, uint16_t udp_dst)
{
    /* Send packet */
    update_packet(ip_src, udp_dst);
    uint64_t send_time = monotonic_ns();
    pcap_inject(src_pcap, pkt, pktlen);

    /* Receive packet */
    while (1) {
        struct pcap_pkthdr *pkt_header;
        const uint8_t *pkt_data;
        int ret = pcap_next_ex(dst_pcap, &pkt_header, &pkt_data);
        if (ret == -1) {
            pcap_perror(dst_pcap, "pcap_next_ex");
            abort();
        } else if (ret == 1) {
            uint64_t recv_time = monotonic_ns();
            if (!memcmp(pkt_data, pkt, pktlen)) {
                if (!warmup) {
                    uint32_t latency = (uint32_t)(recv_time - send_time);
                    if (verbose) fprintf(stderr, "received packet in %u ns\n", latency);
                    if (output) fprintf(output, "%u\n", latency);
                    latencies[total_recvd] = latency;
                    total_recvd++;
                    total_latency += latency;
                }
                break;
            }
        } else if (ret == 0) {
            /* Dropped packet */
            break;
        }
    }
}

static int
compare_uint32(const void *_a, const void *_b)
{
    uint32_t a = *(const uint32_t *)_a;
    uint32_t b = *(const uint32_t *)_b;
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
}

int
main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s SRC_INTERFACE DST_INTERFACE\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    src_pcap = pcap_create(argv[1], errbuf);
    if (src_pcap == NULL) {
        fprintf(stderr, "%s (src)\n", errbuf);
        return 1;
    }

    if (pcap_activate(src_pcap) != 0) {
        pcap_perror(src_pcap, "pcap_activate (src)");
        return 1;
    }

    dst_pcap = pcap_create(argv[2], errbuf);
    if (dst_pcap == NULL) {
        fprintf(stderr, "%s (dst)\n", errbuf);
        return 1;
    }

    pcap_set_timeout(dst_pcap, 10);

    if (pcap_activate(dst_pcap) != 0) {
        pcap_perror(dst_pcap, "pcap_activate (dst)");
        return 1;
    }

    if (getenv("OUTPUT_FILENAME")) {
        output = fopen(getenv("OUTPUT_FILENAME"), "w");
    }

    generate_initial_packet();

    int iter;
    assert(NUM_WARMUP + NUM_PACKETS < 65536);

    uint32_t min_median_latency = -1;

    for (iter = 0; iter < NUM_ITERS; iter++) {
        int i;
        uint32_t ip_src = 0xAC100101 + iter;
        total_recvd = 0;
        total_latency = 0;

        advertise_dst();

        warmup = true;
        for (i = 0; i < NUM_WARMUP; i++) {
            measure_latency(ip_src, i);
        }

        fill_flowtable();

        warmup = true;
        for (i = 0; i < NUM_WARMUP; i++) {
            measure_latency(ip_src, i);
        }

        warmup = false;
        for (i = NUM_WARMUP; i < NUM_WARMUP+NUM_PACKETS; i++) {
            measure_latency(ip_src, i);
        }

        qsort(latencies, total_recvd, sizeof(latencies[0]), compare_uint32);
        uint32_t median_latency = latencies[total_recvd/2];

#if 1
        fprintf(stderr, "received %u/%u packets\n", total_recvd, NUM_PACKETS);
        fprintf(stderr, "mean latency: %u ns\n", total_latency/total_recvd);
        fprintf(stderr, "median latency: %u ns\n", median_latency);
        fprintf(stderr, "lowest latency: %u ns\n", latencies[0]);
        fprintf(stderr, "highest latency: %u ns\n", latencies[total_recvd-1]);
        fprintf(stderr, "90 percentile latency: %u ns\n", latencies[9*(total_recvd-1)/10]);
        fprintf(stderr, "99 percentile latency: %u ns\n", latencies[99*(total_recvd-1)/100]);
#endif

        if (median_latency < min_median_latency) {
            min_median_latency = median_latency;
        }
    }

    fprintf(stderr, "min median latency: %u ns\n", min_median_latency);

    return 0;
}

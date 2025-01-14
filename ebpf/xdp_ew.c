/* Copyright (C) 2019 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#define KBUILD_MODNAME "foo"
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
/* Workaround to avoid the need of 32bit headers */
#define _LINUX_IF_H
#define IFNAMSIZ 16
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "east_west_filter.h"
#include "network_headers.h"

#ifndef DEBUG
#define DEBUG 0
#endif


/* Both are required in order to ensure *everything* is inlined.  The kernel version that
 * we're using doesn't support calling functions in XDP, so it must appear as a single function.
 * Kernel 4.16+ support function calls:
 * https://stackoverflow.com/questions/70529753/clang-bpf-attribute-always-inline-does-not-working
 */
#define INLINE __always_inline __attribute__((always_inline))

#define DPRINTF(fmt_str, args...) \
    if (DEBUG) { \
        char fmt[] = fmt_str; \
        bpf_trace_printk(fmt, sizeof(fmt), args); \
    }

#define DPRINTF_ALWAYS(fmt_str, args...) \
    { \
        char fmt[] = fmt_str; \
        bpf_trace_printk(fmt, sizeof(fmt), args); \
    }

/* The ifndef's around CTX_GET_*() allow the UT's to override them */
#ifndef CTX_GET_DATA
#define CTX_GET_DATA(ctx) (void*)(long)ctx->data
#endif

#ifndef CTX_GET_DATA_END
#define CTX_GET_DATA_END(ctx) (void*)(long)ctx->data_end
#endif

#define LINUX_VERSION_CODE 263682

static INLINE int get_sport(void *trans_data, void *data_end, __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end) {
                return -1;
            }
            return th->source;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end) {
                return -1;
            }
            return uh->source;
        default:
            return 0;
    }
}

static INLINE int get_dport(void *trans_data, void *data_end, __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->dest;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
}

static int INLINE filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (is_east_west(iph->saddr) && is_east_west(iph->daddr)) {
        return XDP_DROP;
    }

#ifdef DROP_PORT_443
    void* layer4 = data + nh_off + (iph->ihl << 2);


    int dport = get_dport(layer4, data_end, iph->protocol);
    if (dport == -1) {
        return XDP_PASS;
    }

    int sport = get_sport(layer4, data_end, iph->protocol);
    if (sport == -1) {
        return XDP_PASS;
    }

    if ((dport == 443) || (sport == 443)) {
        return XDP_DROP;
    }
#endif

    return XDP_PASS;
}

static int INLINE filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    return XDP_PASS;
}

int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = CTX_GET_DATA_END(ctx);
    void *data = CTX_GET_DATA(ctx);
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    DPRINTF("Packet %d len\n", (int)(data_end - data));

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == __constant_htons(0x88e7)) {
        IEEE8021ahHdr *hdr;

        hdr = data + nh_off;
        nh_off += sizeof(IEEE8021ahHdr);
        if (data + nh_off > data_end)
            return XDP_PASS;

        h_proto = hdr->type;
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        return filter_ipv4(ctx, data, nh_off, data_end);
    }
    else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        return filter_ipv6(ctx, data, nh_off, data_end);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
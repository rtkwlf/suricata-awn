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
#include <bpf/bpf_helpers.h>
#include "hash_func01.h"
#include "network_headers.h"
#include "xdp_common.h"
#include "ot_meta.h"

#ifdef ENABLE_EAST_WEST_FILTER
#include "east_west_filter.h"
#endif

#ifdef ENABLE_STREAM_FILTER
#include "xdp_stream_filter_common.h"
#endif

#ifndef DEBUG
/* #define DEBUG 1 */
#define DEBUG 0
#endif

/* Sizes (in bytes) of various GRE/ERSPAN optional protocol options.
 */
#define GRE_CSUM_SIZE   (2)
#define GRE_OFFSET_SIZE (2)
#define GRE_KEY_SIZE    (4)
#define GRE_SEQ_SIZE    (4)
#define GRE_ERSPAN_TYPE_II_HEADER_SIZE (8)

/* Hashing initval */
#define INITVAL 15485863

/* Increase CPUMAP_MAX_CPUS if ever you have more than 128 CPUs */
#define CPUMAP_MAX_CPUS 128

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CPUMAP_MAX_CPUS);
} cpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CPUMAP_MAX_CPUS);
} cpus_available SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} cpus_count SEC(".maps");

/* Stats maps
 *
 *   l2_proto_stats   PERCPU_HASH  key = EtherType (native byte order, __u16)  value = u64
 *                    Counts packets per EtherType after VLAN/802.1ah stripping.
 *                    Only populated for EtherTypes present in l2_proto_config.
 *                    Covers L2 OT protocols (EtherCAT 0x88A4, Profinet 0x8892,
 *                    GOOSE 0x88B8, etc.) as well as IPv4/IPv6.
 *
 *   ip_proto_stats   PERCPU_HASH  key = (ip_proto << 16) | dport  value = u64
 *                    Counts TCP/UDP packets per protocol/destination-port pair.
 *                    Only populated for entries present in ip_proto_config.
 *                    Covers IP-based OT protocols (Modbus TCP:502, DNP3:20000,
 *                    EtherNet/IP TCP:44818, BACnet UDP:47808, etc.)
 *
 * Both maps are per-CPU; sum across CPUs for totals:
 *   bpftool map dump name l2_proto_stats
 *   bpftool map dump name ip_proto_stats
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u16);
    __type(value, __u64);
    __uint(max_entries, 100);
} l2_proto_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8192);
} ip_proto_stats SEC(".maps");

/* Config maps (whitelist) — populate from userspace before loading.
 * Empty = track nothing.  Add an entry to start counting that EtherType or port.
 *
 *   l2_proto_config  key = EtherType (native byte order, __u16)        value = __u8 (1)
 *   ip_proto_config  key = (ip_proto << 16) | dport (__u32)            value = __u8 (1)
 *
 * Examples (bpftool, using decimal byte values):
 *   # Track Profinet RT (0x8892): 0x88=136, 0x92=146
 *   bpftool map update name l2_proto_config key 136 146 value 01
 *   # Track Modbus TCP (proto=6, port=502): key MSB-first: 0x00 0x06 0x01 0xf6
 *   bpftool map update name ip_proto_config key 0x00 0x06 0x01 0xf6 value 01
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 100);
} l2_proto_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 8192);
} ip_proto_config SEC(".maps");

/* Schema versioning — ot_meta_map holds one entry per data map so userspace
 * consumers can verify map layout compatibility before reading stats or config.
 * Version constant, map ID enum, and struct defined in ot_meta.h.
 * Bump OT_SCHEMA_VERSION in ot_meta.h whenever any map's key or value layout changes.
 *
 * bpftool map dump name ot_meta_map
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ot_map_meta);
    __uint(max_entries, 16);
} ot_meta_map SEC(".maps");

/* Increment L2 counter if h_proto is in the config whitelist. */
static INLINE void stats_incr_l2(__u16 h_proto)
{
    __u8 *enabled = bpf_map_lookup_elem(&l2_proto_config, &h_proto);
    if (!enabled)
        return;

    __u64 *cnt = bpf_map_lookup_elem(&l2_proto_stats, &h_proto);
    if (cnt) {
        (*cnt)++;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&l2_proto_stats, &h_proto, &init, BPF_ANY);
    }
    DPRINTF("stats l2 etype 0x%x\n", __builtin_bswap16(h_proto));
}

/* Increment IP protocol/port counter if (proto, dport) is in the config whitelist.
 * Key encoding: upper 16 bits = ip_proto, lower 16 bits = dport (host byte order).
 * dport_nbo is in network byte order as returned by get_dport(). */
static INLINE void stats_incr_ip(__u8 proto, int dport_nbo)
{
    if (dport_nbo <= 0)
        return;

    __u16 port_hbo = __builtin_bswap16((__u16)dport_nbo);
    __u32 key = __builtin_bswap32(((__u32)proto << 16) | port_hbo);

    __u8 *enabled = bpf_map_lookup_elem(&ip_proto_config, &key);
    if (!enabled)
        return;

    __u64 *cnt = bpf_map_lookup_elem(&ip_proto_stats, &key);
    if (cnt) {
        (*cnt)++;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&ip_proto_stats, &key, &init, BPF_ANY);
    }
    DPRINTF("stats ip proto %d port %d\n", proto, port_hbo);
}

static int INLINE hash_ipv4(struct xdp_md *ctx, void *data, void *data_end, __u16 vlan0, __u16 vlan1)
{
    DPRINTF("hash_ipv4 %d\n", (int)(data_end - data));

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

#ifdef ENABLE_EAST_WEST_FILTER
    if (is_east_west(iph->saddr) && is_east_west(iph->daddr)) {
        return XDP_DROP;
    }
#endif

    void* layer4 = data + (iph->ihl << 2);

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;

    int dport = get_dport(layer4, data_end, iph->protocol);
    if (dport == -1) {
        return XDP_PASS;
    }

    int sport = get_sport(layer4, data_end, iph->protocol);
    if (sport == -1) {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        stats_incr_ip(iph->protocol, dport);

    DPRINTF("Flow proto  %d id %d\n", iph->protocol, iph->id);
    DPRINTF("     src %x:%d\n", iph->saddr, __constant_htons(sport));
    DPRINTF("     dst %x:%d\n", iph->daddr, __constant_htons(dport));

#ifdef ENABLE_STREAM_FILTER
    if (stream_filter_ipv4(ctx, iph, data, data_end, sport, dport, vlan0, vlan1) == XDP_DROP) {
        return XDP_DROP;
    }
#endif

     __u32 cpu_hash;
     __u64 cpu_hash_input = 0;

    /*
     * Sort the client/server parts of the 5-tuple for a symmetric hash
     *
     * NOTE: saddr and daddr are in network order (i.e., big endian), and we're running
     * an on Intel (little endian), which means the least significant bits contain the
     * network portion of the IP address, which we intentionally add the layer 4 port
     * on top of it.
     * This does two things:
     *   - it uses the full 5-tuple for hashing
     *   - creates more entropy by distrupting the fairly static network bits
     */
    if (iph->saddr > iph->daddr) {
        ((__u32*)&cpu_hash_input)[0] = iph->saddr + sport;
        ((__u32*)&cpu_hash_input)[1] = iph->daddr + dport;

        cpu_hash = SuperFastHash((char *)&cpu_hash_input, 8, INITVAL + iph->protocol);
    } else {
        ((__u32*)&cpu_hash_input)[0] = iph->daddr + dport;
        ((__u32*)&cpu_hash_input)[1] = iph->saddr + sport;

        cpu_hash = SuperFastHash((char *)&cpu_hash_input, 8, INITVAL + iph->protocol);
    }

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;

        DPRINTF("    hash %x to %d\n", cpu_hash, cpu_dest);
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected) {
            return XDP_ABORTED;
        }
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }
}

static int INLINE sort128(__u64 *source, __u64 *dest)
{
    return (source[0] < dest[0]) | ((source[0] == dest[0]) & (source[1] < dest[1]));
}

static int INLINE hash_ipv6(struct xdp_md *ctx, void *data, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct ipv6hdr *ip6h = data;
    if ((void *)(ip6h + 1) > data_end) {
        return XDP_PASS;
    }

    /**
     * TODO: we will likely eventually need to support a set
     * of IPV6 header extension; the UDP or TCP header wont
     * *always* be the next header after the IP header...
     */

    void* layer4 = (void*)(ip6h + 1);
    int dport = get_dport(layer4, data_end, ip6h->nexthdr);
    if (dport == -1) {
        return XDP_PASS;
    }

    int sport = get_sport(layer4, data_end, ip6h->nexthdr);
    if (sport == -1) {
        return XDP_PASS;
    }

    if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP)
        stats_incr_ip(ip6h->nexthdr, dport);

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;

    __u64 ip_hash_input;
    __u32 cpu_hash;

#ifdef ENABLE_STREAM_FILTER
    if (stream_filter_ipv6(ctx, ip6h, data, data_end, sport, dport, vlan0, vlan1) == XDP_DROP) {
        return XDP_DROP;
    }
#endif

    /*
     * IPV6 addresses are 128 bits, commonly expressed as a series of up to
     * 8 16-bit words; but very rarely are all 16-bit words defined.  Typically
     * the middle words are unset/zero.
     *
     * Additionally, like IPV4, the upper bits consist of more static network/routing
     * bits, while the lower bits identify individual interfaces/hosts, which
     * tend to be more variable.
     *
     * So, in order to create more entropy, we can merge source and dest
     * addresses in opposite orders -- colliding static bits with more dynamic bits
     * in both sides of the hash input.  However, to keep flow symmetry, we
     * must do this identically for each side of a flow, so we must have a way
     * to consistently choose which address is added in 0-1 order, and which is
     * added in 1-0 order.
     *
     * For IPV4 addresses, we simply sorted them, which can also work here,
     * although sorting 128 bits is a bit more involved and requires our own
     * function.
     *
     * NOTE that we're sorting the address in network order; this doens't matter,
     * as long as it's consistent.
     */
    __u64 *source = (__u64 *)&ip6h->saddr;
    __u64 *dest   = (__u64 *)&ip6h->daddr;
    if (sort128(source, dest)) {
        ip_hash_input = source[0] + dest[1] + sport;
        ip_hash_input += source[1] + dest[0] + dport;
    } else {
        ip_hash_input = dest[0] + source[1] + dport;
        ip_hash_input += dest[1] + source[0] + sport;
    }
    cpu_hash = SuperFastHash((char *)&ip_hash_input, 8, INITVAL + ip6h->nexthdr);

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected) {
            return XDP_ABORTED;
        }
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }

    return XDP_PASS;
}

static int INLINE filter_gre(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    __u16 proto;
    struct gre_hdr {
        __be16 flags;
        __be16 proto;
    };

    nh_off += iph->ihl << 2;

    /* need to save this off before we advance the packet beyond it, else the bpf verifier
     * will catch this and refuse to load our program
     */
    int pkt_id = iph->id;

    struct gre_hdr *grhdr = (struct gre_hdr *)(data + nh_off);

    if ((void *)(grhdr + 1) > data_end) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    if (grhdr->flags & (GRE_VERSION|GRE_ROUTING)) {
        DPRINTF_ALWAYS("unsupported gre flags %x on %d",grhdr->flags, __LINE__);
        return XDP_PASS;
    }

    // skip past gre header...
    nh_off += 4;
    proto = grhdr->proto;
    if (grhdr->flags & GRE_CSUM) {
        nh_off += GRE_CSUM_SIZE + GRE_OFFSET_SIZE;
    }
    if (grhdr->flags & GRE_KEY) {
        nh_off += GRE_KEY_SIZE;
    }
    if (grhdr->flags & GRE_SEQ) {
        nh_off += GRE_SEQ_SIZE;
    }

    /* Update offset to skip ERSPAN header if we have one */
    if (proto == __constant_htons(ETH_P_ERSPAN)) {
        // If sequence is set, then an ERSPAN header follows, otherwise the
        // inner ether header follows...
        if(grhdr->flags & GRE_SEQ) {
            nh_off += GRE_ERSPAN_TYPE_II_HEADER_SIZE;
        }
    } else if (proto != __constant_htons(ETH_P_IP) && proto != __constant_htons(ETH_P_IPV6)) {
	// if the encapsulated packet isn't IP-based, then we can't rebalance this flow 
	// anyway, so just return it to the stack...
        return XDP_PASS;
    }

    if (data + nh_off > data_end) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    if (bpf_xdp_adjust_head(ctx, 0 + nh_off)) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    data = CTX_GET_DATA(ctx);
    data_end = CTX_GET_DATA_END(ctx);

    /* we have now data starting at Ethernet header */
    struct ethhdr *eth = data;
    proto = eth->h_proto;
    /* we want to hash on IP so we need to get to ip hdr */
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    /* we need to increase offset and update protocol
     * in the case we have VLANs */
    if (proto == __constant_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)(data + nh_off);
        if ((void *)(vhdr + 1) > data_end) {
            DPRINTF_ALWAYS("malformed gre %d", __LINE__);
            return XDP_PASS;
        }
        proto = vhdr->h_vlan_encapsulated_proto;
        nh_off += sizeof(struct vlan_hdr);
    }

    if (data + nh_off > data_end)
        return XDP_PASS;
    /* proto should now be IP style */
    if (proto == __constant_htons(ETH_P_IP)) {
        return hash_ipv4(ctx, data + nh_off, data_end, 0, 0);
    } else if (proto == __constant_htons(ETH_P_IPV6)) {
        return hash_ipv6(ctx, data + nh_off, data_end, 0, 0);
    } else {
        /* This packet isn't IPV4 or IPV6... it's likely still a legit ether type, but we intentionally
         * keep the packet handling light here, so even though we don't understand it, return it to the
         * network stack (we've already advanced past the GRE/ERSPAN headers to the encapsulated ethernet
         * frame, so chances are the linux stack, and suricata, know what to do with it)
         */
        DPRINTF("GRE unknown inner proto %d id %d\n", __constant_htons(proto), __constant_htons(pkt_id));
        return XDP_PASS;
    }
}

static int INLINE filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_GRE) {
        return filter_gre(ctx, data, nh_off, data_end);
    }

    return hash_ipv4(ctx, data + nh_off, data_end, vlan0, vlan1);
}

static int INLINE filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct ipv6hdr *ip6h = data + nh_off;
    return hash_ipv6(ctx, (void *)ip6h, data_end, vlan0, vlan1);
}

int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = CTX_GET_DATA_END(ctx);
    void *data = CTX_GET_DATA(ctx);
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    __u16 vlan0 = 0;
    __u16 vlan1 = 0;

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
        vlan0 = vhdr->h_vlan_TCI & 0x0fff;
        DPRINTF("nh_off %x vhdr->h_vlan_TCI %x\n", nh_off, vhdr->h_vlan_TCI);
        DPRINTF("vlan0 %x\n", vlan0);
    }
    if (h_proto == __constant_htons(0x88e7)) {
        IEEE8021ahHdr *hdr;

        hdr = data + nh_off;
        nh_off += sizeof(IEEE8021ahHdr);
        if (data + nh_off > data_end)
            return XDP_PASS;

        h_proto = hdr->type;
        DPRINTF("802.1ah next header %x\n", __constant_htons(h_proto));
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        vlan1 = vhdr->h_vlan_TCI & 0x0fff;
        DPRINTF("vlan1 %x\n", vlan1);
    }

    stats_incr_l2(h_proto);

    if (h_proto == __constant_htons(ETH_P_IP)) {
        return filter_ipv4(ctx, data, nh_off, data_end, vlan0, vlan1);
    }
    else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, vlan1);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;

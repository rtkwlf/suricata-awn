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
 *   l2_proto_stats   PERCPU_HASH  key = EtherType (native byte order, __u16)
 *                                value = struct ot_stat { count, last_updated_ns }
 *                    Counts packets per EtherType after VLAN/802.1ah stripping.
 *                    Only populated for EtherTypes present in l2_proto_config.
 *                    Covers L2 OT protocols (EtherCAT 0x88A4, Profinet 0x8892,
 *                    GOOSE 0x88B8, etc.) as well as IPv4/IPv6.
 *
 *   l4_proto_stats   PERCPU_HASH  key = (protocol << 16) | dport
 *                                value = struct ot_stat { pkt_count, last_updated_ns }
 *                    Counts TCP/UDP packets per protocol/destination-port pair.
 *                    Only populated for entries present in l4_proto_config.
 *                    Covers IP-based OT protocols (Modbus TCP:502, DNP3:20000,
 *                    EtherNet/IP TCP:44818, BACnet UDP:47808, etc.)
 *
 * Both maps are per-CPU; sum across CPUs for totals:
 *   bpftool map dump name l2_proto_stats
 *   bpftool map dump name l4_proto_stats
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u16);
    __type(value, struct ot_stat);
    __uint(max_entries, 100);
} l2_proto_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct ot_stat);
    __uint(max_entries, 8192);
} l4_proto_stats SEC(".maps");

/* Double-buffered config maps (whitelist) — unified for both L2 and L3 protocols.
 * Key encoding: (type << 31) | proto_id
 *   type=0 → L2: proto_id = ethertype (__u16, padded to 31 bits)
 *   type=1 → L3: proto_id = (protocol << 16) | port (MSB-first)
 * Value: __u8 (1 = enabled)
 *
 * External program writes the inactive buffer then flips ot_proto_cfg_sel[0].
 * XDP reads sel[0] and branches to the compile-time map reference — no nested
 * map lookup, so this works on all kernels from 4.1 (including kernel 5.4).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 8292); /* 100 L2 + 8192 L3 */
} ot_proto_cfg_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 8292); /* 100 L2 + 8192 L3 */
} ot_proto_cfg_b SEC(".maps");

/* Selector: 0 → ot_proto_cfg_a is active, 1 → ot_proto_cfg_b is active.
 * External program flips this after fully writing the inactive buffer. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} ot_proto_cfg_sel SEC(".maps");

/* Config generation ID — incremented by external program after config entries
 * are fully written, so consumers can detect a completed update without polling.
 * Type: ARRAY with 1 entry (key=0, value=u64 counter).
 * Pinned map; owned and initialized by suricataconfig, not by Suricata.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} ot_config_generation_id SEC(".maps");

/* Schema versioning — ot_meta_map holds one entry per data map so userspace
 * consumers can verify map layout compatibility before reading stats or config.
 * Each map has its own schema version in ot_meta.h (OT_SCHEMA_VERSION_*).
 * Maps can evolve independently; bump the specific map's version if its layout changes.
 * util-ebpf.c writes all versions to ot_meta_map[0..3] on startup.
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
    __u32 cfg_key = (0U << 31) | (__u32)__builtin_bswap16(h_proto);  /* type=0 for L2 */

    __u32 sel_key = 0, *sel;
    __u8 *enabled;
    __u64 now;
    sel = bpf_map_lookup_elem(&ot_proto_cfg_sel, &sel_key);
    if (!sel) {
        return;
    }

    if (*sel == 0) {
        enabled = bpf_map_lookup_elem(&ot_proto_cfg_a, &cfg_key);
    } else {
        enabled = bpf_map_lookup_elem(&ot_proto_cfg_b, &cfg_key);
    }

    if (!enabled) {
        return;
    }

    now = bpf_ktime_get_ns();
    struct ot_stat *s = bpf_map_lookup_elem(&l2_proto_stats, &h_proto);
    if (s) {
        s->pkt_count++;
        s->last_updated_ns = now;
    } else {
        struct ot_stat init = { .pkt_count = 1, .last_updated_ns = now };
        bpf_map_update_elem(&l2_proto_stats, &h_proto, &init, BPF_ANY);
    }
    DPRINTF("stats l2 etype 0x%x\n", __builtin_bswap16(h_proto));
}

/* Increment L4 protocol/port counter if (proto, dport) is in the config whitelist.
 * Key encoding: upper 16 bits = protocol, lower 16 bits = dport (host byte order).
 * dport_nbo is in network byte order as returned by get_dport(). */
static INLINE void stats_incr_l4(__u8 proto, int dport_nbo)
{
    if (dport_nbo <= 0)
        return;

    __u16 port_hbo = __builtin_bswap16((__u16)dport_nbo);
    __u32 key = __builtin_bswap32(((__u32)proto << 16) | port_hbo);

    __u32 sel_key = 0;
    __u32 cfg_key = (1U << 31) | key;  /* type=1 for L3 */
    __u8 *enabled;
    __u64 now;
    __u32 *sel = bpf_map_lookup_elem(&ot_proto_cfg_sel, &sel_key);
    if (!sel) {
        return;
    }

    if (*sel == 0) {
        enabled = bpf_map_lookup_elem(&ot_proto_cfg_a, &cfg_key);
    } else {
        enabled = bpf_map_lookup_elem(&ot_proto_cfg_b, &cfg_key);
    }

    if (!enabled) {
        return;
    }

    now = bpf_ktime_get_ns();
    struct ot_stat *s = bpf_map_lookup_elem(&l4_proto_stats, &key);
    if (s) {
        s->pkt_count++;
        s->last_updated_ns = now;
    } else {
        struct ot_stat init = { .pkt_count = 1, .last_updated_ns = now };
        bpf_map_update_elem(&l4_proto_stats, &key, &init, BPF_ANY);
    }
    DPRINTF("stats l4 proto %d port %d\n", proto, port_hbo);
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

    /* Mask the 4-bit ihl field before shifting: kernel 5.4 verifier requires a
     * known non-negative range before allowing packet pointer arithmetic. */
    __u32 hdr_len = ((__u32)(iph->ihl) & 0x0F) << 2;
    if (hdr_len < sizeof(*iph) || (void *)data + hdr_len > data_end)
        return XDP_PASS;
    void *layer4 = data + hdr_len;

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

    /* Pre-load all packet-derived scalars before the stats call.
     * On kernel 5.4, inlining helpers (bpf_map_lookup_elem, bpf_ktime_get_ns)
     * can cause the verifier to lose PTR_TO_PACKET range tracking for iph.
     * Reading everything needed from packet memory first avoids any packet
     * pointer reads after the inlined stats code. */
    __u32 saddr    = iph->saddr;
    __u32 daddr    = iph->daddr;
    __u8  protocol = iph->protocol;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        stats_incr_l4(protocol, dport);

    DPRINTF("Flow proto  %d id %d\n", protocol, iph->id);
    DPRINTF("     src %x:%d\n", saddr, __constant_htons(sport));
    DPRINTF("     dst %x:%d\n", daddr, __constant_htons(dport));

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
    if (saddr > daddr) {
        ((__u32*)&cpu_hash_input)[0] = saddr + sport;
        ((__u32*)&cpu_hash_input)[1] = daddr + dport;

        cpu_hash = SuperFastHash((char *)&cpu_hash_input, 8, INITVAL + protocol);
    } else {
        ((__u32*)&cpu_hash_input)[0] = daddr + dport;
        ((__u32*)&cpu_hash_input)[1] = saddr + sport;

        cpu_hash = SuperFastHash((char *)&cpu_hash_input, 8, INITVAL + protocol);
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

    /* Pre-load all packet-derived scalars before the stats call (same reason
     * as hash_ipv4: avoids packet pointer reads after inlined helpers). */
    __u8 nexthdr          = ip6h->nexthdr;
    struct in6_addr lsrc  = ip6h->saddr;
    struct in6_addr ldst  = ip6h->daddr;

    if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)
        stats_incr_l4(nexthdr, dport);

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
    __u64 *source = (__u64 *)&lsrc;
    __u64 *dest   = (__u64 *)&ldst;
    if (sort128(source, dest)) {
        ip_hash_input = source[0] + dest[1] + sport;
        ip_hash_input += source[1] + dest[0] + dport;
    } else {
        ip_hash_input = dest[0] + source[1] + dport;
        ip_hash_input += dest[1] + source[0] + sport;
    }
    cpu_hash = SuperFastHash((char *)&ip_hash_input, 8, INITVAL + nexthdr);

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

    /* Same ihl mask as hash_ipv4: bound the nibble so the verifier accepts
     * the subsequent packet pointer arithmetic derived from nh_off. */
    __u32 ihl_bytes = ((__u32)(iph->ihl) & 0x0F) << 2;
    if (ihl_bytes < sizeof(*iph))
        return XDP_PASS;
    nh_off += ihl_bytes;

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


    /* Re-establish packet pointers and re-bound nh_off after inlined stats
     * helpers.  On kernel 4.15 (and other pre-5.x kernels), inlined map
     * lookups and bpf_ktime_get_ns reset the verifier's register range:
     *   - data/data_end lose PTR_TO_PACKET type → re-load from ctx
     *   - nh_off loses its smin (becomes S64_MIN) → explicit sign check
     * The sign check sets smin=0 on the false path; the bounds check then
     * constrains nh_off to [0, packet_size] so data+nh_off is accepted. */
    // data     = CTX_GET_DATA(ctx);
    // data_end = CTX_GET_DATA_END(ctx);
    // if ((long long)nh_off < 0)
    //     return XDP_PASS;
    // if (data + nh_off > data_end)
    //     return XDP_PASS;

    if (h_proto == __constant_htons(ETH_P_IP)) {
        return filter_ipv4(ctx, data, nh_off, data_end, vlan0, vlan1);
    }
    else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, vlan1);
    } else {
        stats_incr_l2(h_proto);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;

#ifndef OT_META_H
#define OT_META_H

#include <linux/types.h>

/* OT_SCHEMA_VERSION — bump this whenever any OT stats or config map's key or
 * value layout changes (size, encoding, or field semantics).  All maps share
 * one version so userspace consumers have a single value to check.
 *
 * Current layout (v1):
 *   l2_proto_config / l2_proto_stats : key = __u16 EtherType (network byte order)
 *   ip_proto_config / ip_proto_stats : key = bswap32((proto << 16) | port), MSB-first
 *   stats value = struct ot_stat { __u64 count; __u64 last_updated_ns; }
 */
#define OT_SCHEMA_VERSION  1

enum ot_map_id {
    OT_MAP_L2_PROTO_CONFIG = 0,
    OT_MAP_L2_PROTO_STATS  = 1,
    OT_MAP_IP_PROTO_CONFIG = 2,
    OT_MAP_IP_PROTO_STATS  = 3,
    OT_MAP_COUNT           = 4,
};

struct ot_map_meta {
    __u32 schema_version;
};

/* Value type for l2_proto_stats and ip_proto_stats PERCPU_HASH maps.
 * last_updated_ns is bpf_ktime_get_ns() (nanoseconds since boot, per CPU)
 * at the time the counter was last incremented. */
struct ot_stat {
    __u64 count;
    __u64 last_updated_ns;
};

#endif /* OT_META_H */

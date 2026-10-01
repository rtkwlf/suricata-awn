#ifndef OT_META_H
#define OT_META_H

#include <linux/types.h>

/* Independent schema versions for each OT data map.
 * Each map can evolve independently. Bump a specific version when that map's
 * key or value layout changes. Mismatch detection in util-ebpf.c discards stale pins.
 *
 * Map layouts (current):
 *   l2_proto_stats  : PERCPU_HASH, key=__u16 (EtherType), value=struct ot_stat
 *   l4_proto_stats  : PERCPU_HASH, key=__u32 ((proto<<16)|port MSB-first), value=struct ot_stat
 *   ot_proto_cfg_a/b: HASH, key=__u32 ((type<<31)|value), value=__u8; double-buffered config
 */
#define OT_SCHEMA_VERSION_L2_PROTO_STATS   1
#define OT_SCHEMA_VERSION_L4_PROTO_STATS   1
#define OT_SCHEMA_VERSION_CONFIG           1  /* applies to both cfg_a and cfg_b */
#define OT_MAPS_PATH                       "/sys/fs/bpf/suricata"

enum ot_map_id {
    OT_MAP_L2_PROTO_STATS  = 0,
    OT_MAP_L4_PROTO_STATS  = 1,
    OT_MAP_CONFIG_A        = 2,
    OT_MAP_CONFIG_B        = 3,
    OT_MAP_COUNT           = 4,
};

struct ot_map_meta {
    __u32 schema_version;
};

/* Value type for l2_proto_stats and l4_proto_stats PERCPU_HASH maps.
 * last_updated_ns is bpf_ktime_get_ns() (nanoseconds since boot, per CPU)
 * at the time the counter was last incremented. */
struct ot_stat {
    __u64 pkt_count;
    __u64 last_updated_ns;
};

/* Central registry of OT maps: name → ID mapping. Used by util-ebpf.c to:
 * 1. Determine which maps should be pinned
 * 2. Look up the OT map ID for schema version checks
 * This is the single source of truth for OT map configuration. */
struct ot_map_registry_entry {
    const char *name;
    __u32 id;
};

static const struct ot_map_registry_entry ot_map_registry[] = {
    { "l2_proto_stats",  OT_MAP_L2_PROTO_STATS },
    { "l4_proto_stats",  OT_MAP_L4_PROTO_STATS },
    { "ot_proto_cfg_a",  OT_MAP_CONFIG_A },
    { "ot_proto_cfg_b",  OT_MAP_CONFIG_B },
};

#define OT_MAP_REGISTRY_COUNT (sizeof(ot_map_registry) / sizeof(ot_map_registry[0]))

#endif /* OT_META_H */

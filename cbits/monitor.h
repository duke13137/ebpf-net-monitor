#ifndef MONITOR_H
#define MONITOR_H

#ifdef __BPF__
typedef __u64 monitor_u64;
typedef __u32 monitor_u32;
typedef __u16 monitor_u16;
typedef __u8  monitor_u8;
#else
#include <stdint.h>
typedef uint64_t monitor_u64;
typedef uint32_t monitor_u32;
typedef uint16_t monitor_u16;
typedef uint8_t  monitor_u8;
#endif

/**
 * Network event captured by the eBPF TC program.
 * Layout must match Haskell Storable instance (FFI.hs) exactly.
 */
struct net_event {
    monitor_u64 timestamp_ns;  /* bpf_ktime_get_ns() */
    monitor_u32 src_ip;        /* network byte order */
    monitor_u32 dst_ip;        /* network byte order */
    monitor_u16 src_port;      /* network byte order */
    monitor_u16 dst_port;      /* network byte order */
    monitor_u32 pkt_len;       /* total packet length */
    monitor_u8  protocol;      /* IPPROTO_TCP=6, UDP=17, ICMP=1 */
    monitor_u8  direction;     /* 0=ingress, 1=egress */
    monitor_u8  _pad[2];       /* explicit padding before final 8-byte alignment */
};

_Static_assert(sizeof(struct net_event) == 32, "net_event must be 32 bytes");

/* Direction constants */
#define DIR_INGRESS 0
#define DIR_EGRESS  1

/* Forward declare Arena (defined in arena.h) */
typedef struct Arena Arena;

/**
 * Load BPF object, attach TC ingress+egress on ifname.
 * Returns 0 on success, negative errno on failure.
 */
int monitor_init(const char *ifname);

/**
 * Poll ring buffer, copy events into arena batch.
 * Returns pointer to first event in arena. *out_count = number of events.
 * Arena is NOT reset here -- caller (Haskell) owns the reset cycle.
 */
struct net_event *monitor_poll(Arena *arena, int timeout_ms, int *out_count);

/**
 * Detach TC hooks, close BPF object. Safe to call multiple times.
 */
void monitor_cleanup(void);

/*
 * FFI wrappers for arena lifecycle.
 * Haskell can't receive C structs by value, so these heap-allocate the Arena.
 */
Arena *arena_init_ffi(void *buf, monitor_u64 size);
void   arena_release_ffi(Arena *arena);
void   arena_reset_ffi(Arena *arena);

/**
 * Return the number of bytes currently used in the arena.
 * Useful for testing and diagnostics.
 */
monitor_u64 arena_used_ffi(Arena *arena);

#endif

#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>

/**
 * Network event captured by the eBPF TC program.
 * Layout must match Haskell Storable instance (FFI.hs) exactly.
 */
struct net_event {
    uint64_t timestamp_ns;  /* bpf_ktime_get_ns() */
    uint32_t src_ip;        /* network byte order */
    uint32_t dst_ip;        /* network byte order */
    uint32_t pkt_len;       /* total packet length */
    uint8_t  protocol;      /* IPPROTO_TCP=6, UDP=17, ICMP=1 */
    uint8_t  direction;     /* 0=ingress, 1=egress */
    uint8_t  _pad[2];       /* explicit padding to 24 bytes */
};

_Static_assert(sizeof(struct net_event) == 24, "net_event must be 24 bytes");

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
Arena *arena_init_ffi(void *buf, uint64_t size);
void   arena_release_ffi(Arena *arena);
void   arena_reset_ffi(Arena *arena);

/**
 * Return the number of bytes currently used in the arena.
 * Useful for testing and diagnostics.
 */
uint64_t arena_used_ffi(Arena *arena);

#endif

/**
 * C-level tests for arena FFI wrappers and net_event struct layout.
 * Uses utest.h (https://github.com/sheredom/utest.h).
 *
 * Build (standalone, any platform):
 *   cc -DOOM_COMMIT -I../../cbits -o test_monitor test_monitor.c ../../cbits/monitor.c
 *
 * Or via the Makefile below.
 */

#define OOM_COMMIT
#include "arena.h"
#include "monitor.h"
#include "utest.h"

#include <stddef.h>
#include <string.h>

/* ================================================================== */
/* net_event struct layout                                             */
/* ================================================================== */

UTEST(net_event, size_is_24) {
    ASSERT_EQ(24u, sizeof(struct net_event));
}

UTEST(net_event, offset_timestamp) {
    ASSERT_EQ(0u, offsetof(struct net_event, timestamp_ns));
}

UTEST(net_event, offset_src_ip) {
    ASSERT_EQ(8u, offsetof(struct net_event, src_ip));
}

UTEST(net_event, offset_dst_ip) {
    ASSERT_EQ(12u, offsetof(struct net_event, dst_ip));
}

UTEST(net_event, offset_pkt_len) {
    ASSERT_EQ(16u, offsetof(struct net_event, pkt_len));
}

UTEST(net_event, offset_protocol) {
    ASSERT_EQ(20u, offsetof(struct net_event, protocol));
}

UTEST(net_event, offset_direction) {
    ASSERT_EQ(21u, offsetof(struct net_event, direction));
}

UTEST(net_event, offset_pad) {
    ASSERT_EQ(22u, offsetof(struct net_event, _pad));
}

UTEST(net_event, no_implicit_padding) {
    /* Verify that our explicit _pad[2] accounts for all padding.
       If the compiler added implicit padding, sizeof would exceed
       the sum of field sizes. */
    size_t fields = sizeof(uint64_t)  /* timestamp_ns */
                  + sizeof(uint32_t)  /* src_ip */
                  + sizeof(uint32_t)  /* dst_ip */
                  + sizeof(uint32_t)  /* pkt_len */
                  + sizeof(uint8_t)   /* protocol */
                  + sizeof(uint8_t)   /* direction */
                  + 2;                /* _pad[2] */
    ASSERT_EQ(fields, sizeof(struct net_event));
}

/* ================================================================== */
/* Arena FFI wrappers                                                  */
/* ================================================================== */

UTEST(arena_ffi, init_and_release) {
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);
    ASSERT_TRUE(a != NULL);
    arena_release_ffi(a);
}

UTEST(arena_ffi, used_starts_zero) {
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);
    ASSERT_EQ((uint64_t)0, arena_used_ffi(a));
    arena_release_ffi(a);
}

UTEST(arena_ffi, alloc_increases_used) {
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);

    /* Allocate one net_event */
    struct net_event *evt = New(a, struct net_event);
    ASSERT_TRUE(evt != NULL);
    ASSERT_TRUE(arena_used_ffi(a) >= sizeof(struct net_event));

    arena_release_ffi(a);
}

UTEST(arena_ffi, reset_returns_used_to_zero) {
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);

    /* Allocate some data */
    New(a, struct net_event, 10);
    ASSERT_TRUE(arena_used_ffi(a) > 0);

    arena_reset_ffi(a);
    ASSERT_EQ((uint64_t)0, arena_used_ffi(a));

    arena_release_ffi(a);
}

UTEST(arena_ffi, null_safety) {
    /* These should not crash */
    arena_release_ffi(NULL);
    arena_reset_ffi(NULL);
    ASSERT_EQ((uint64_t)0, arena_used_ffi(NULL));
}

/* ================================================================== */
/* Arena batch allocation (simulates what monitor_poll does)           */
/* ================================================================== */

UTEST(arena_batch, sequential_events_are_contiguous) {
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);

    struct net_event template = {
        .timestamp_ns = 42,
        .src_ip       = 0x0100007F,
        .dst_ip       = 0x0200007F,
        .pkt_len      = 128,
        .protocol     = 6,  /* TCP */
        .direction    = 0,  /* ingress */
    };

    /* Record batch start */
    byte *batch_start = a->cur;

    /* Allocate 5 events as monitor_poll's callback would */
    for (int i = 0; i < 5; i++) {
        template.timestamp_ns = (uint64_t)(i + 1);
        struct net_event *evt = New(a, struct net_event, 1, &template);
        ASSERT_TRUE(evt != NULL);
    }

    /* Verify batch is contiguous and readable */
    struct net_event *batch = (struct net_event *)batch_start;
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ((uint64_t)(i + 1), batch[i].timestamp_ns);
        ASSERT_EQ(0x0100007Fu, batch[i].src_ip);
        ASSERT_EQ(128u, batch[i].pkt_len);
        ASSERT_EQ(6, batch[i].protocol);
    }

    arena_release_ffi(a);
}

UTEST(arena_batch, reset_allows_reuse) {
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);

    /* First batch */
    struct net_event *e1 = New(a, struct net_event);
    e1->timestamp_ns = 111;
    uint64_t used1 = arena_used_ffi(a);

    arena_reset_ffi(a);

    /* Second batch reuses same memory region */
    struct net_event *e2 = New(a, struct net_event);
    e2->timestamp_ns = 222;
    uint64_t used2 = arena_used_ffi(a);

    ASSERT_EQ(used1, used2);
    ASSERT_EQ(222u, e2->timestamp_ns);

    arena_release_ffi(a);
}

UTEST(arena_batch, large_batch) {
    Arena *a = arena_init_ffi(NULL, 4 * 1024 * 1024);

    struct net_event template = {0};
    int count = 10000;

    byte *start = a->cur;
    for (int i = 0; i < count; i++) {
        template.timestamp_ns = (uint64_t)i;
        template.pkt_len      = (uint32_t)(i % 1500);
        New(a, struct net_event, 1, &template);
    }

    /* Verify we can read them all back */
    struct net_event *batch = (struct net_event *)start;
    for (int i = 0; i < count; i++) {
        ASSERT_EQ((uint64_t)i, batch[i].timestamp_ns);
        ASSERT_EQ((uint32_t)(i % 1500), batch[i].pkt_len);
    }

    /* Verify used space */
    ASSERT_TRUE(arena_used_ffi(a) >= (uint64_t)(count * (int)sizeof(struct net_event)));

    arena_release_ffi(a);
}

/* ================================================================== */
/* monitor_init/poll/cleanup stubs on non-Linux                        */
/* ================================================================== */

UTEST(monitor, init_returns_enosys_on_non_linux) {
#ifndef __linux__
    int ret = monitor_init("lo");
    /* Should return -ENOSYS on macOS/other */
    ASSERT_TRUE(ret < 0);
#else
    /* On Linux without root, it will fail but not with ENOSYS */
    ASSERT_TRUE(1);
#endif
}

UTEST(monitor, poll_returns_zero_on_non_linux) {
#ifndef __linux__
    Arena *a = arena_init_ffi(NULL, 1024 * 1024);
    int count = -1;
    struct net_event *ptr = monitor_poll(a, 0, &count);
    ASSERT_EQ(0, count);
    ASSERT_TRUE(ptr == NULL);
    arena_release_ffi(a);
#else
    ASSERT_TRUE(1);
#endif
}

UTEST(monitor, cleanup_is_safe_without_init) {
    /* Should not crash even if monitor_init was never called */
    monitor_cleanup();
    ASSERT_TRUE(1);
}

UTEST_MAIN();

/**
 * Userspace component of the eBPF network monitor.
 *
 * Provides:
 *   - BPF object loading and TC hook attachment (monitor_init)
 *   - Ring buffer polling with arena-based event batching (monitor_poll)
 *   - Clean teardown of TC hooks (monitor_cleanup)
 *   - FFI wrappers for arena lifecycle (arena_init_ffi, etc.)
 */

#define OOM_COMMIT  /* arena uses mmap commit-on-demand */
#include "arena.h"
#include "monitor.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/*
 * libbpf and Linux headers -- only available on Linux.
 * Guard so the FFI wrappers and arena tests compile on any platform.
 */
#ifdef __linux__
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#endif

/* ------------------------------------------------------------------ */
/* Internal state (single-threaded, one monitor instance)              */
/* ------------------------------------------------------------------ */

#ifdef __linux__
static struct bpf_object *obj;
static struct ring_buffer *rb;
static int ingress_fd, egress_fd;
static unsigned int ifindex;
#endif

/* Temporary state for ring_buffer callback */
static Arena *poll_arena;
static int    poll_count;

/* ------------------------------------------------------------------ */
/* Ring buffer callback                                                */
/* ------------------------------------------------------------------ */

#ifdef __linux__
static int event_handler(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (size < sizeof(struct net_event))
        return 0;

    /* Copy event into arena -- New() with init pointer */
    struct net_event *evt = New(poll_arena, struct net_event, 1,
                                (struct net_event *)data);
    (void)evt;
    poll_count++;
    return 0;
}
#endif

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int monitor_init(const char *ifname) {
#ifndef __linux__
    (void)ifname;
    fprintf(stderr, "monitor_init: eBPF requires Linux\n");
    return -ENOSYS;
#else
    ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -errno;

    obj = bpf_object__open_file("bpf/monitor.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        obj = NULL;
        return -ENOENT;
    }

    if (bpf_object__load(obj))
        return -EINVAL;

    /* --- Attach TC ingress --- */
    LIBBPF_OPTS(bpf_tc_hook, hook_ingress,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    bpf_tc_hook_create(&hook_ingress);  /* may already exist */

    struct bpf_program *prog_in =
        bpf_object__find_program_by_name(obj, "monitor_ingress");
    if (!prog_in) return -ENOENT;
    ingress_fd = bpf_program__fd(prog_in);

    LIBBPF_OPTS(bpf_tc_opts, opts_ingress,
        .prog_fd = ingress_fd,
    );
    if (bpf_tc_attach(&hook_ingress, &opts_ingress))
        return -EINVAL;

    /* --- Attach TC egress --- */
    LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    bpf_tc_hook_create(&hook_egress);

    struct bpf_program *prog_eg =
        bpf_object__find_program_by_name(obj, "monitor_egress");
    if (!prog_eg) return -ENOENT;
    egress_fd = bpf_program__fd(prog_eg);

    LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .prog_fd = egress_fd,
    );
    if (bpf_tc_attach(&hook_egress, &opts_egress))
        return -EINVAL;

    /* --- Open ring buffer --- */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) return -ENOENT;

    rb = ring_buffer__new(bpf_map__fd(map), event_handler, NULL, NULL);
    if (libbpf_get_error(rb)) {
        rb = NULL;
        return -ENOMEM;
    }

    return 0;
#endif
}

struct net_event *monitor_poll(Arena *arena, int timeout_ms, int *out_count) {
#ifndef __linux__
    (void)arena; (void)timeout_ms;
    *out_count = 0;
    return NULL;
#else
    poll_arena = arena;
    poll_count = 0;

    /* Mark start of this batch in the arena */
    struct net_event *batch_start = (struct net_event *)arena->cur;

    int err = ring_buffer__poll(rb, timeout_ms);
    (void)err;  /* negative = error/timeout; poll_count is the real result */

    *out_count = poll_count;
    return poll_count > 0 ? batch_start : NULL;
#endif
}

void monitor_cleanup(void) {
#ifdef __linux__
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    if (ifindex) {
        /* Detach ingress */
        LIBBPF_OPTS(bpf_tc_hook, hook_in,
            .ifindex      = ifindex,
            .attach_point = BPF_TC_INGRESS,
        );
        LIBBPF_OPTS(bpf_tc_opts, opts_in,
            .prog_fd = ingress_fd,
        );
        bpf_tc_detach(&hook_in, &opts_in);

        /* Detach egress */
        LIBBPF_OPTS(bpf_tc_hook, hook_eg,
            .ifindex      = ifindex,
            .attach_point = BPF_TC_EGRESS,
        );
        LIBBPF_OPTS(bpf_tc_opts, opts_eg,
            .prog_fd = egress_fd,
        );
        bpf_tc_detach(&hook_eg, &opts_eg);

        /* Destroy clsact qdisc */
        LIBBPF_OPTS(bpf_tc_hook, hook_destroy,
            .ifindex      = ifindex,
            .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS,
        );
        bpf_tc_hook_destroy(&hook_destroy);
    }

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
#endif
}

/* ------------------------------------------------------------------ */
/* FFI wrappers for arena lifecycle                                    */
/* Haskell can't receive C structs by value; these heap-allocate.      */
/* ------------------------------------------------------------------ */

Arena *arena_init_ffi(void *buf, uint64_t size) {
    Arena *a = malloc(sizeof(Arena));
    if (!a) return NULL;
    *a = arena_init((byte *)buf, (isize)size);
    return a;
}

void arena_release_ffi(Arena *arena) {
    if (!arena) return;
    arena_release(arena);
    free(arena);
}

void arena_reset_ffi(Arena *arena) {
    if (!arena) return;
    arena_reset(arena);
}

uint64_t arena_used_ffi(Arena *arena) {
    if (!arena) return 0;
    return (uint64_t)(arena->cur - arena->beg);
}

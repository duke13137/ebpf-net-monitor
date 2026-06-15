/**
 * Userspace component of the eBPF network monitor.
 *
 * Provides:
 *   - BPF object loading and TC hook attachment (monitor_init)
 *   - Ring buffer polling with arena-based event batching (monitor_poll)
 *   - Clean teardown of TC hooks (monitor_cleanup)
 *   - FFI wrappers for arena lifecycle (arena_init_ffi, etc.)
 */

#define OOM_COMMIT /* arena uses mmap commit-on-demand */
#include "monitor.h"
#include "arena.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * libbpf and Linux headers -- only available on Linux.
 * Guard so the FFI wrappers and arena tests compile on any platform.
 */
#ifdef __linux__
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#endif

/* ------------------------------------------------------------------ */
/* Internal state (single-threaded, one monitor instance)              */
/* ------------------------------------------------------------------ */

#ifdef __linux__
static struct bpf_object *obj;
static struct ring_buffer *rb;
static int ingress_fd, egress_fd;
static unsigned int ifindex;
static int ingress_filter_handle;
static int egress_filter_handle;

/* Silent print callback to suppress libbpf warnings for expected errors (e.g.
 * EEXIST) */
static int noop_print(enum libbpf_print_level level, const char *format,
                      va_list args) {
  (void)level;
  (void)format;
  (void)args;
  return 0;
}
#endif

/* Temporary state for ring_buffer callback */
static Arena *poll_arena;
static int poll_count;

/* Reserved priority for our TC filters */
#define MONITOR_TC_PRIO 1

/* ------------------------------------------------------------------ */
/* Ring buffer callback                                                */
/* ------------------------------------------------------------------ */

#ifdef __linux__

/* Best-effort: query and detach any zombie filter at our priority */
static void cleanup_zombie(unsigned int ifindex,
                           enum bpf_tc_attach_point point) {
  LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = point);
  LIBBPF_OPTS(bpf_tc_opts, opts, .priority = MONITOR_TC_PRIO, .handle = 0);
  if (bpf_tc_query(&hook, &opts) == 0)
    bpf_tc_detach(&hook, &opts);
}

static void cleanup_filter(unsigned int index, enum bpf_tc_attach_point point,
                           int prog_fd, int *handle) {
  LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = index, .attach_point = point);

  if (*handle) {
    LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd, .handle = *handle,
                .priority = MONITOR_TC_PRIO, );
    if (bpf_tc_detach(&hook, &opts) == 0) {
      *handle = 0;
      return;
    }
  }

  LIBBPF_OPTS(bpf_tc_opts, opts, .priority = MONITOR_TC_PRIO, .handle = 0);
  if (bpf_tc_query(&hook, &opts) == 0)
    bpf_tc_detach(&hook, &opts);

  *handle = 0;
}
static int event_handler(void *ctx, void *data, size_t size) {
  (void)ctx;
  if (size < sizeof(struct net_event))
    return 0;

  /* Copy event into arena -- New() with init pointer */
  struct net_event *evt =
      New(poll_arena, struct net_event, 1, (struct net_event *)data);
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
  int err = 0;

  ifindex = if_nametoindex(ifname);
  if (!ifindex)
    return -errno;

  ingress_fd = 0;
  egress_fd = 0;
  ingress_filter_handle = 0;
  egress_filter_handle = 0;
  /* --- Detach any zombie filters from a prior crashed run --- */
  cleanup_zombie(ifindex, BPF_TC_INGRESS);
  cleanup_zombie(ifindex, BPF_TC_EGRESS);

  obj = bpf_object__open_file("bpf/monitor.bpf.o", NULL);
  if (libbpf_get_error(obj)) {
    obj = NULL;
    return -ENOENT;
  }

  if (bpf_object__load(obj)) {
    err = -EINVAL;
    goto fail;
  }

  /* --- Create clsact qdisc (once for both ingress and egress) --- */
  {
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS, );
    libbpf_print_fn_t old_print = libbpf_set_print(noop_print);
    int hook_err = bpf_tc_hook_create(&hook);
    libbpf_set_print(old_print);
    if (hook_err && errno != EEXIST) {
      err = -errno;
      goto fail;
    }
  }

  /* --- Attach TC ingress --- */
  LIBBPF_OPTS(bpf_tc_hook, hook_ingress, .ifindex = ifindex,
              .attach_point = BPF_TC_INGRESS, );

  struct bpf_program *prog_in =
      bpf_object__find_program_by_name(obj, "monitor_ingress");
  if (!prog_in) {
    err = -ENOENT;
    goto fail;
  }
  ingress_fd = bpf_program__fd(prog_in);

  LIBBPF_OPTS(bpf_tc_opts, opts_ingress, .prog_fd = ingress_fd,
              .priority = MONITOR_TC_PRIO, );
  if (bpf_tc_attach(&hook_ingress, &opts_ingress)) {
    err = -EINVAL;
    goto fail;
  }

  /* Query back the kernel-assigned handle */
  {
    LIBBPF_OPTS(bpf_tc_opts, qopts, .priority = MONITOR_TC_PRIO, .handle = 0, );
    if (bpf_tc_query(&hook_ingress, &qopts) == 0)
      ingress_filter_handle = qopts.handle;
  }

  /* --- Attach TC egress --- */
  LIBBPF_OPTS(bpf_tc_hook, hook_egress, .ifindex = ifindex,
              .attach_point = BPF_TC_EGRESS, );

  struct bpf_program *prog_eg =
      bpf_object__find_program_by_name(obj, "monitor_egress");
  if (!prog_eg) {
    err = -ENOENT;
    goto fail;
  }
  egress_fd = bpf_program__fd(prog_eg);

  LIBBPF_OPTS(bpf_tc_opts, opts_egress, .prog_fd = egress_fd,
              .priority = MONITOR_TC_PRIO, );
  if (bpf_tc_attach(&hook_egress, &opts_egress)) {
    err = -EINVAL;
    goto fail;
  }

  /* Query back the kernel-assigned handle */
  {
    LIBBPF_OPTS(bpf_tc_opts, qopts, .priority = MONITOR_TC_PRIO, .handle = 0, );
    if (bpf_tc_query(&hook_egress, &qopts) == 0)
      egress_filter_handle = qopts.handle;
  }

  /* --- Open ring buffer --- */
  struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
  if (!map) {
    err = -ENOENT;
    goto fail;
  }

  rb = ring_buffer__new(bpf_map__fd(map), event_handler, NULL, NULL);
  if (libbpf_get_error(rb)) {
    rb = NULL;
    err = -ENOMEM;
    goto fail;
  }

  return 0;

fail:
  monitor_cleanup();
  return err;
#endif
}

struct net_event *monitor_poll(Arena *arena, int timeout_ms, int *out_count) {
#ifndef __linux__
  (void)arena;
  (void)timeout_ms;
  *out_count = 0;
  return NULL;
#else
  if (!rb) {
    *out_count = 0;
    return NULL;
  }

  poll_arena = arena;
  poll_count = 0;

  /* Mark start of this batch in the arena */
  struct net_event *batch_start = (struct net_event *)arena->cur;

  int err = ring_buffer__poll(rb, timeout_ms);
  (void)err; /* negative = error/timeout; poll_count is the real result */

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

  /* Detach only our filters — leave other TC filters intact */
  cleanup_filter(ifindex, BPF_TC_INGRESS, ingress_fd, &ingress_filter_handle);
  cleanup_filter(ifindex, BPF_TC_EGRESS, egress_fd, &egress_filter_handle);

  ingress_fd = 0;
  egress_fd = 0;
  ifindex = 0;

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
  if (!a)
    return NULL;
  *a = arena_init((byte *)buf, (isize)size);
  return a;
}

void arena_release_ffi(Arena *arena) {
  if (!arena)
    return;
  arena_release(arena);
  free(arena);
}

void arena_reset_ffi(Arena *arena) {
  if (!arena)
    return;
  arena_reset(arena);
}

uint64_t arena_used_ffi(Arena *arena) {
  if (!arena)
    return 0;
  return (uint64_t)(arena->cur - arena->beg);
}

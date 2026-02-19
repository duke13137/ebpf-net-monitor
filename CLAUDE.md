# ebpf-net-monitor

Minimal eBPF network packet monitor: C eBPF program + libbpf userspace, Haskell stream processing (Streamly) and TUI (brick), connected via FFI with arena-based zero-copy event batching.

## Architecture rationale

### Why C for eBPF and userspace polling

The eBPF verifier only accepts BPF bytecode produced from a restricted C subset (no dynamic allocation, bounded loops, no function pointers). There is no alternative — the kernel enforces this. The userspace polling layer is also C because libbpf is a C library and the ring_buffer callback is a C function pointer. Wrapping libbpf in Haskell directly would require re-implementing the entire loader; a thin C shim is simpler and auditable.

### Why Haskell for stream processing and TUI

- **Streamly** provides fused stream combinators that compile to tight loops with no intermediate allocation. Backpressure is automatic — if the TUI falls behind, the stream blocks on the BChan, which blocks the poll loop, which causes ring_buffer_poll to return with timeout. No data loss, no unbounded queues.
- **brick** provides a declarative TUI model (Elm-style: state → view, event → state update). This is dramatically simpler than ncurses imperative drawing for a live-updating table.

### Why Haskell owns arena memory

Haskell's `bracket` pattern provides exception-safe resource management equivalent to C++ RAII:
```haskell
withArena size action = bracket (c_arenaInit nullPtr size) c_arenaRelease action
```
If any exception (sync or async) fires during `action`, `c_arenaRelease` runs. This is stronger than C's lack of cleanup guarantees and avoids the need for signal handlers or `atexit`.

### Why FFI mmap, not GHC pinned ByteArray

The arena uses `mmap` with `PROT_NONE` reservation + incremental `mprotect` commit. This gives:
- **Commit-on-demand**: only physical pages touched are committed (define `OOM_COMMIT`)
- **No GC heap bloat**: pinned ByteArrays are visible to GHC's GC and inflate residency metrics, triggering unnecessary major GCs
- **No fragmentation**: mmap returns page-aligned regions outside the GHC heap
- **Growable**: the arena can commit more pages within its reservation without moving

### Why ForeignPtr + Storable for zero-copy

Events are written by C into the arena as packed structs. Haskell reads them directly via `Storable.peek` — no serialization, no schema, no copy. FlatBuffers or Cap'n Proto would add schema overhead for data that never leaves the process. `ForeignPtr` ties the arena lifetime to GHC's reference tracking as a safety net, though `bracket` is the primary cleanup mechanism.

### Safe vs unsafe FFI calls

| Function | FFI safety | Reason |
|---|---|---|
| `monitor_poll` | `safe` | Blocks on `ring_buffer__poll` with timeout; must release GHC capability so other Haskell threads run |
| `arena_init` | `unsafe` | Pure allocation, never blocks, ~50ns |
| `arena_reset` | `unsafe` | Pointer reset, never blocks, ~10ns |
| `arena_release` | `unsafe` | `munmap` syscall but instantaneous, no contention |
| `monitor_init` | `safe` | Loads BPF object, attaches TC — slow, may fail |
| `monitor_cleanup` | `safe` | Detaches TC hooks — kernel interaction |

Rule: `unsafe` only for functions that are guaranteed non-blocking and fast. Everything touching the kernel or doing I/O is `safe`.

## Repository structure

```
ebpf-net-monitor/
├── CLAUDE.md                 # This file — architecture + build instructions
├── cabal.project             # cabal project config
├── ebpf-net-monitor.cabal    # Package description
├── cbits/                    # C source compiled by cabal
│   ├── arena.h               # Copied from C-Makefile/include/arena.h
│   ├── monitor.h             # Event struct definitions, shared C↔Haskell
│   ├── monitor.c             # Userspace: libbpf loader, ring_buffer poll, arena batching
│   └── Makefile.bpf          # Builds the .bpf.o eBPF bytecode
├── bpf/
│   ├── monitor.bpf.c         # eBPF TC program (packet counting)
│   └── vmlinux.h             # Generated BTF header (bpftool btf dump)
├── src/
│   ├── Main.hs               # Entry point: bracket arena, launch pipeline
│   ├── FFI.hs                # Foreign imports, Storable instances, withArena
│   ├── Stream.hs             # Streamly pipeline: decode → filter → aggregate
│   └── TUI.hs                # brick app: live table of per-IP packet counts
└── scripts/
    └── gen-vmlinux.sh         # bpftool btf dump file /sys/kernel/btf/vmlinux format c
```

## C layer specification

### Event struct (`cbits/monitor.h`)

```c
#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>

// Shared between eBPF program and userspace.
// Layout must match Haskell Storable instance exactly.
struct net_event {
    uint64_t timestamp_ns;   // bpf_ktime_get_ns()
    uint32_t src_ip;         // network byte order
    uint32_t dst_ip;         // network byte order
    uint32_t pkt_len;        // total packet length
    uint8_t  protocol;       // IPPROTO_TCP=6, UDP=17, ICMP=1
    uint8_t  direction;      // 0=ingress, 1=egress
    uint8_t  _pad[2];        // explicit padding to 24 bytes
};

// Verify no implicit padding
_Static_assert(sizeof(struct net_event) == 24, "net_event must be 24 bytes");

#endif
```

This struct is 24 bytes with no implicit padding. The `_Static_assert` catches any compiler that would add padding. Both the eBPF program and userspace include this header to guarantee layout agreement.

### eBPF program (`bpf/monitor.bpf.c`)

TC classifier hook, attached to both ingress and egress:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../cbits/monitor.h"

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1 MB ring buffer
} events SEC(".maps");

// dir: 0=ingress, 1=egress
static __always_inline int handle_packet(struct __sk_buff *skb, __u8 dir) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return TC_ACT_OK;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip       = ip->saddr;
    evt->dst_ip       = ip->daddr;
    evt->pkt_len      = skb->len;
    evt->protocol     = ip->protocol;
    evt->direction    = dir;
    evt->_pad[0]      = 0;
    evt->_pad[1]      = 0;

    bpf_ringbuf_submit(evt, 0);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int monitor_ingress(struct __sk_buff *skb) {
    return handle_packet(skb, 0);
}

SEC("tc/egress")
int monitor_egress(struct __sk_buff *skb) {
    return handle_packet(skb, 1);
}

char LICENSE[] SEC("license") = "GPL";
```

Key constraints:
- All pointer arithmetic must be bounds-checked before dereference (verifier requirement)
- `bpf_ringbuf_reserve` can fail under load — drop the event, never block
- `TC_ACT_OK` means "pass packet through" — we're observing, not filtering

### Userspace C (`cbits/monitor.c`)

Three-function API exposed to Haskell via FFI:

```c
#define OOM_COMMIT  // arena uses mmap commit-on-demand
#include "arena.h"
#include "monitor.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

// --- Internal state ---
static struct bpf_object *obj;
static struct ring_buffer *rb;
static int ingress_fd, egress_fd;
static unsigned int ifindex;

// Temporary batch pointer for ring_buffer callback
static Arena *poll_arena;
static int poll_count;

static int event_handler(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (size < sizeof(struct net_event))
        return 0;

    struct net_event *evt = New(poll_arena, struct net_event, 1, (struct net_event *)data);
    (void)evt;
    poll_count++;
    return 0;
}

// Load BPF object, attach TC ingress+egress on ifname.
// Returns 0 on success, -errno on failure.
int monitor_init(const char *ifname) {
    ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -errno;

    obj = bpf_object__open_file("bpf/monitor.bpf.o", NULL);
    if (libbpf_get_error(obj))
        return -ENOENT;

    if (bpf_object__load(obj))
        return -EINVAL;

    // Attach TC ingress
    LIBBPF_OPTS(bpf_tc_hook, hook_ingress,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    bpf_tc_hook_create(&hook_ingress);  // may already exist, ignore error

    struct bpf_program *prog_in = bpf_object__find_program_by_name(obj, "monitor_ingress");
    if (!prog_in) return -ENOENT;
    ingress_fd = bpf_program__fd(prog_in);

    LIBBPF_OPTS(bpf_tc_opts, opts_ingress,
        .prog_fd = ingress_fd,
    );
    if (bpf_tc_attach(&hook_ingress, &opts_ingress))
        return -EINVAL;

    // Attach TC egress
    LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    bpf_tc_hook_create(&hook_egress);

    struct bpf_program *prog_eg = bpf_object__find_program_by_name(obj, "monitor_egress");
    if (!prog_eg) return -ENOENT;
    egress_fd = bpf_program__fd(prog_eg);

    LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .prog_fd = egress_fd,
    );
    if (bpf_tc_attach(&hook_egress, &opts_egress))
        return -EINVAL;

    // Open ring buffer
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) return -ENOENT;

    rb = ring_buffer__new(bpf_map__fd(map), event_handler, NULL, NULL);
    if (libbpf_get_error(rb))
        return -ENOMEM;

    return 0;
}

// Poll ring buffer, copy events into arena batch.
// Returns pointer to first event in arena. *out_count = number of events.
// Arena is NOT reset here — Haskell owns the reset cycle.
struct net_event *monitor_poll(Arena *arena, int timeout_ms, int *out_count) {
    poll_arena = arena;
    poll_count = 0;

    // Mark start of this batch in the arena
    struct net_event *batch_start = (struct net_event *)arena->cur;

    int err = ring_buffer__poll(rb, timeout_ms);
    (void)err;  // negative = error or timeout, poll_count tells us what we got

    *out_count = poll_count;
    return poll_count > 0 ? batch_start : NULL;
}

// Detach TC hooks, close BPF object.
void monitor_cleanup(void) {
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    // Detach ingress
    LIBBPF_OPTS(bpf_tc_hook, hook_ingress,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    LIBBPF_OPTS(bpf_tc_opts, opts_ingress,
        .prog_fd = ingress_fd,
    );
    bpf_tc_detach(&hook_ingress, &opts_ingress);

    // Detach egress
    LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .prog_fd = egress_fd,
    );
    bpf_tc_detach(&hook_egress, &opts_egress);

    // Destroy clsact qdisc (removes all TC hooks)
    LIBBPF_OPTS(bpf_tc_hook, hook_destroy,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS,
    );
    bpf_tc_hook_destroy(&hook_destroy);

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
}
```

**Critical notes for the C layer:**
- `poll_arena` / `poll_count` are module-level statics because `ring_buffer__poll` delivers events via callback — there's no way to pass an accumulator through the libbpf callback signature cleanly (the `void *ctx` could work but the arena + count pair is simpler as statics since we're single-threaded).
- `monitor_poll` does NOT reset the arena. Haskell calls `arena_reset` after it has finished peeking all events. This keeps ownership clear: C writes, Haskell reads and resets.
- `batch_start` captures the arena cursor before polling so we can return a pointer to the first event even though events are appended one-by-one in the callback.

### Makefile.bpf (`cbits/Makefile.bpf`)

```makefile
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_DIR := bpf
OUT     := $(BPF_DIR)/monitor.bpf.o

CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
          -Wall -Werror \
          -I$(BPF_DIR) -Icbits

.PHONY: all clean

all: $(OUT)

$(OUT): $(BPF_DIR)/monitor.bpf.c $(BPF_DIR)/vmlinux.h cbits/monitor.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OUT)
```

## Haskell layer specification

### FFI.hs

```haskell
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module FFI
  ( Arena
  , NetEvent(..)
  , Direction(..)
  , Protocol(..)
  , withArena
  , monitorInit
  , monitorPoll
  , monitorCleanup
  , arenaReset
  , ipToString
  ) where

import Foreign
import Foreign.C
import Data.Word
import Data.Bits (shiftR, (.&.))
import Control.Exception (bracket, throwIO)
import System.IO.Error (mkIOError, userErrorType)
import qualified Data.List as List

-- Opaque arena type — we only pass Ptr Arena through FFI
data Arena

data Direction = Ingress | Egress deriving (Show, Eq, Ord)
data Protocol  = TCP | UDP | ICMP | OtherProto Word8 deriving (Show, Eq, Ord)

data NetEvent = NetEvent
  { evTimestampNs :: !Word64
  , evSrcIp       :: !Word32
  , evDstIp       :: !Word32
  , evPktLen      :: !Word32
  , evProtocol    :: !Protocol
  , evDirection   :: !Direction
  } deriving (Show)

instance Storable NetEvent where
  sizeOf    _ = 24
  alignment _ = 8
  peek ptr = do
    ts    <- peekByteOff ptr 0  :: IO Word64
    sip   <- peekByteOff ptr 8  :: IO Word32
    dip   <- peekByteOff ptr 12 :: IO Word32
    plen  <- peekByteOff ptr 16 :: IO Word32
    proto <- peekByteOff ptr 20 :: IO Word8
    dir   <- peekByteOff ptr 21 :: IO Word8
    return $ NetEvent ts sip dip plen (toProtocol proto) (toDirection dir)
  poke ptr (NetEvent ts sip dip plen proto dir) = do
    pokeByteOff ptr 0  ts
    pokeByteOff ptr 8  sip
    pokeByteOff ptr 12 dip
    pokeByteOff ptr 16 plen
    pokeByteOff ptr 20 (fromProtocol proto)
    pokeByteOff ptr 21 (fromDirection dir)
    pokeByteOff ptr 22 (0 :: Word8)  -- pad
    pokeByteOff ptr 23 (0 :: Word8)  -- pad

toProtocol :: Word8 -> Protocol
toProtocol 1  = ICMP
toProtocol 6  = TCP
toProtocol 17 = UDP
toProtocol n  = OtherProto n

fromProtocol :: Protocol -> Word8
fromProtocol ICMP = 1
fromProtocol TCP  = 6
fromProtocol UDP  = 17
fromProtocol (OtherProto n) = n

toDirection :: Word8 -> Direction
toDirection 0 = Ingress
toDirection _ = Egress

fromDirection :: Direction -> Word8
fromDirection Ingress = 0
fromDirection Egress  = 1

-- | Convert network-byte-order IPv4 to "a.b.c.d"
ipToString :: Word32 -> String
ipToString ip = List.intercalate "."
  [ show (ip .&. 0xFF)
  , show ((ip `shiftR` 8) .&. 0xFF)
  , show ((ip `shiftR` 16) .&. 0xFF)
  , show ((ip `shiftR` 24) .&. 0xFF)
  ]

-- FFI imports
-- Arena ops: unsafe (non-blocking, < 100ns)
foreign import ccall unsafe "arena_init"
  c_arenaInit :: Ptr () -> CSize -> IO (Ptr Arena)

foreign import ccall unsafe "arena_reset"
  c_arenaReset :: Ptr Arena -> IO ()

foreign import ccall unsafe "arena_release"
  c_arenaRelease :: Ptr Arena -> IO ()

-- Monitor lifecycle: safe (kernel interaction, may block)
foreign import ccall safe "monitor_init"
  c_monitorInit :: CString -> IO CInt

foreign import ccall safe "monitor_cleanup"
  c_monitorCleanup :: IO ()

-- Poll: safe (blocks up to timeout_ms on ring_buffer__poll)
foreign import ccall safe "monitor_poll"
  c_monitorPoll :: Ptr Arena -> CInt -> Ptr CInt -> IO (Ptr NetEvent)

-- | Bracket pattern for arena lifecycle.
-- Size is the virtual reservation in bytes (physical pages committed on demand).
withArena :: Int -> (Ptr Arena -> IO a) -> IO a
withArena size = bracket acquire c_arenaRelease
  where
    acquire = c_arenaInit nullPtr (fromIntegral size)

-- | Initialize the monitor on the given interface.
-- Throws IOError on failure.
monitorInit :: String -> IO ()
monitorInit ifname = do
  ret <- withCString ifname c_monitorInit
  if ret /= 0
    then throwIO $ mkIOError userErrorType
           ("monitor_init failed on " ++ ifname ++ ": " ++ show ret) Nothing Nothing
    else return ()

-- | Poll for events, writing them into the arena.
-- Returns list of events. Does NOT reset the arena — caller must call arenaReset.
monitorPoll :: Ptr Arena -> Int -> IO [NetEvent]
monitorPoll arena timeoutMs = alloca $ \countPtr -> do
  evtPtr <- c_monitorPoll arena (fromIntegral timeoutMs) countPtr
  count  <- peek countPtr
  if count <= 0 || evtPtr == nullPtr
    then return []
    else peekArray (fromIntegral count) evtPtr

-- | Reset arena bump pointer to start. Invalidates all prior event pointers.
arenaReset :: Ptr Arena -> IO ()
arenaReset = c_arenaReset
```

**Note on `c_arenaInit` FFI signature:** The actual C function is `Arena arena_init(byte *buf, isize size)` which returns an `Arena` struct by value. Since we can't easily marshal a struct return value through FFI, create a thin C wrapper in `monitor.c`:

```c
// FFI wrapper — Haskell can't receive struct by value
Arena *arena_init_ffi(void *buf, size_t size) {
    Arena *a = malloc(sizeof(Arena));
    *a = arena_init((byte *)buf, (isize)size);
    return a;
}

void arena_release_ffi(Arena *arena) {
    arena_release(arena);
    free(arena);
}

void arena_reset_ffi(Arena *arena) {
    arena_reset(arena);
}
```

Update the FFI imports to use `arena_init_ffi`, `arena_release_ffi`, `arena_reset_ffi` instead of the raw arena functions.

### Stream.hs

```haskell
module Stream
  ( AggRow(..)
  , aggRowKey
  , eventStream
  , aggregateStream
  ) where

import FFI
import Foreign (Ptr)
import Data.Word (Word32)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Streamly.Data.Stream (Stream)
import qualified Streamly.Data.Stream as S
import qualified Streamly.Data.Fold as F

-- | Aggregation key: (src_ip, dst_ip, protocol, direction)
type AggKey = (Word32, Word32, Protocol, Direction)

data AggRow = AggRow
  { aggSrcIp     :: !Word32
  , aggDstIp     :: !Word32
  , aggProtocol  :: !Protocol
  , aggDirection :: !Direction
  , aggPktCount  :: !Int
  , aggByteCount :: !Int
  } deriving (Show)

aggRowKey :: AggRow -> AggKey
aggRowKey r = (aggSrcIp r, aggDstIp r, aggProtocol r, aggDirection r)

-- | Infinite stream of event batches from the ring buffer.
-- Each element is a batch of NetEvents from one poll cycle.
-- Arena is reset after each batch is consumed.
eventStream :: Ptr Arena -> Int -> Stream IO [NetEvent]
eventStream arena timeoutMs = S.repeatM pollAndReset
  where
    pollAndReset = do
      evts <- monitorPoll arena timeoutMs
      arenaReset arena
      return evts

-- | Running aggregation: fold batches into a cumulative Map.
aggregateStream :: Stream IO [NetEvent] -> Stream IO (Map AggKey AggRow)
aggregateStream = S.scan (F.foldl' step Map.empty)
  where
    step acc evts = foldl updateOne acc evts

    updateOne m evt =
      let key = (evSrcIp evt, evDstIp evt, evProtocol evt, evDirection evt)
      in Map.insertWith merge key (AggRow
            { aggSrcIp     = evSrcIp evt
            , aggDstIp     = evDstIp evt
            , aggProtocol  = evProtocol evt
            , aggDirection = evDirection evt
            , aggPktCount  = 1
            , aggByteCount = fromIntegral (evPktLen evt)
            }) m

    merge _new old = old
      { aggPktCount  = aggPktCount old + 1
      , aggByteCount = aggByteCount old + fromIntegral (evPktLen (error "unreachable"))
      }
```

**Important:** The `merge` function above has a bug placeholder — you cannot access the new event's `evPktLen` through `insertWith` because `insertWith` only passes the new *value*, not the original event. Fix this by pre-computing the `AggRow` with correct byte count before inserting:

```haskell
    updateOne m evt =
      let key = (evSrcIp evt, evDstIp evt, evProtocol evt, evDirection evt)
          row = AggRow
            { aggSrcIp     = evSrcIp evt
            , aggDstIp     = evDstIp evt
            , aggProtocol  = evProtocol evt
            , aggDirection = evDirection evt
            , aggPktCount  = 1
            , aggByteCount = fromIntegral (evPktLen evt)
            }
      in Map.insertWith mergeRow key row m

    mergeRow new old = old
      { aggPktCount  = aggPktCount old + aggPktCount new
      , aggByteCount = aggByteCount old + aggByteCount new
      }
```

### TUI.hs

```haskell
module TUI (runTUI) where

import FFI (ipToString, Direction(..), Protocol(..))
import Stream (AggRow(..), AggKey)

import Brick
import Brick.BChan (BChan, readBChan)
import Brick.Widgets.Table (table, renderTable)
import Brick.Widgets.Border (borderWithLabel)
import qualified Graphics.Vty as Vty
import qualified Graphics.Vty.CrossPlatform as VtyCross

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.List (sortBy)
import Data.Ord (Down(..), comparing)

-- | Custom event: new aggregation snapshot
newtype AppEvent = NewSnapshot (Map AggKey AggRow)

data Name = MainViewport deriving (Eq, Ord, Show)

type AppState = Map AggKey AggRow

app :: App AppState AppEvent Name
app = App
  { appDraw         = drawUI
  , appChooseCursor = neverShowCursor
  , appHandleEvent  = handleEvent
  , appStartEvent   = return ()
  , appAttrMap      = const $ attrMap [(attrName "header", Vty.withStyle Vty.currentAttr Vty.bold)]
  }

drawUI :: AppState -> [Widget Name]
drawUI st = [borderWithLabel (str " ebpf-net-monitor ") $ renderTable tbl]
  where
    rows = sortBy (comparing (Down . aggByteCount)) (Map.elems st)
    header = [ str "Src IP", str "Dst IP", str "Proto", str "Dir"
             , str "Packets", str "Bytes" ]
    dataRows = map rowToWidgets (take 50 rows)  -- cap at 50 rows
    tbl = table (header : dataRows)

    rowToWidgets r =
      [ str (ipToString (aggSrcIp r))
      , str (ipToString (aggDstIp r))
      , str (showProto (aggProtocol r))
      , str (showDir (aggDirection r))
      , str (show (aggPktCount r))
      , str (show (aggByteCount r))
      ]

    showProto TCP = "TCP"
    showProto UDP = "UDP"
    showProto ICMP = "ICMP"
    showProto (OtherProto n) = show n

    showDir Ingress = "IN"
    showDir Egress  = "OUT"

handleEvent :: BrickEvent Name AppEvent -> EventM Name AppState ()
handleEvent (VtyEvent (Vty.EvKey (Vty.KChar 'q') [])) = halt
handleEvent (VtyEvent (Vty.EvKey Vty.KEsc []))         = halt
handleEvent (AppEvent (NewSnapshot snap))               = put snap
handleEvent _                                           = return ()

-- | Run the brick TUI. Blocks until user quits.
-- Reads AppEvents from the BChan (fed by the Streamly pipeline).
runTUI :: BChan AppEvent -> IO ()
runTUI chan = do
  let buildVty = VtyCross.mkVty Vty.defaultConfig
  initialVty <- buildVty
  void $ customMain initialVty buildVty (Just chan) app Map.empty
```

### Main.hs

```haskell
module Main where

import FFI (withArena, monitorInit, monitorCleanup)
import Stream (eventStream, aggregateStream)
import TUI (runTUI, AppEvent(..))

import Brick.BChan (newBChan, writeBChan)
import Control.Concurrent (forkIO)
import Control.Exception (bracket_, finally)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import qualified Streamly.Data.Stream as S

main :: IO ()
main = do
  args <- getArgs
  ifname <- case args of
    [iface] -> return iface
    _       -> do
      hPutStrLn stderr "Usage: ebpf-net-monitor <interface>"
      exitFailure

  let arenaSize = 4 * 1024 * 1024  -- 4 MB virtual reservation
      pollTimeoutMs = 100           -- 100ms poll timeout

  withArena arenaSize $ \arena -> do
    bracket_ (monitorInit ifname) monitorCleanup $ do
      chan <- newBChan 16

      -- Fork Streamly pipeline: poll → aggregate → push to BChan
      _tid <- forkIO $ do
        let pipeline = aggregateStream (eventStream arena pollTimeoutMs)
        S.mapM_ (writeBChan chan . NewSnapshot) pipeline

      -- Run TUI on main thread (brick needs main thread for signal handling)
      runTUI chan
```

## Build configuration

### cabal.project

```
packages: .
```

### ebpf-net-monitor.cabal

```cabal
cabal-version: 3.0
name:          ebpf-net-monitor
version:       0.1.0
synopsis:      eBPF network packet monitor with Haskell TUI
license:       MIT
build-type:    Simple

executable ebpf-net-monitor
  default-language: Haskell2010
  hs-source-dirs:   src
  main-is:          Main.hs
  other-modules:    FFI
                  , Stream
                  , TUI

  build-depends:
      base         >= 4.16 && < 5
    , streamly      >= 0.10
    , streamly-core >= 0.2
    , brick         >= 2.0
    , vty           >= 6.0
    , vty-unix      >= 0.2
    , vty-crossplatform >= 0.4
    , stm           >= 2.5
    , containers    >= 0.6
    , bytestring    >= 0.11

  c-sources:        cbits/monitor.c
  include-dirs:     cbits
  includes:         monitor.h arena.h
  extra-libraries:  bpf elf z
  cc-options:       -DOOM_COMMIT -Wall -Wextra -O2
  ghc-options:      -Wall -O2 -threaded -rtsopts "-with-rtsopts=-N"
```

### scripts/gen-vmlinux.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

OUT="bpf/vmlinux.h"
BTF="/sys/kernel/btf/vmlinux"

if [ ! -f "$BTF" ]; then
    echo "ERROR: $BTF not found. Kernel must have CONFIG_DEBUG_INFO_BTF=y" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
bpftool btf dump file "$BTF" format c > "$OUT"
echo "Generated $OUT ($(wc -l < "$OUT") lines)"
```

## Build steps

### Prerequisites

- **Linux 6.1+** with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- **clang/llvm** (for BPF compilation, version 14+)
- **libbpf-dev** (headers + shared library)
- **bpftool** (for vmlinux.h generation)
- **libelf-dev**, **zlib1g-dev** (libbpf dependencies)
- **GHC 9.6+** and **cabal-install 3.10+**
- **Root** or `CAP_NET_ADMIN` + `CAP_BPF` capabilities for TC attach

### Build and run

```bash
# 1. Copy arena.h from C-Makefile project
cp /path/to/C-Makefile/include/arena.h cbits/arena.h

# 2. Generate vmlinux.h (requires root or BTF read access)
chmod +x scripts/gen-vmlinux.sh
./scripts/gen-vmlinux.sh

# 3. Build eBPF object file
make -f cbits/Makefile.bpf

# 4. Build Haskell + C userspace (cabal compiles cbits/monitor.c automatically)
cabal build

# 5. Run (requires root for TC hook attachment)
sudo $(cabal list-bin ebpf-net-monitor) eth0
```

### Sanitizer build (development)

Add to `cc-options` in the cabal file for debug builds:
```
cc-options: -DOOM_COMMIT -Wall -Wextra -O0 -g -fsanitize=address,undefined
```
And link with:
```
extra-lib-dirs: ...
ghc-options: -optl-fsanitize=address,undefined
```

## Verification checklist

1. **Build compiles** — `cabal build` succeeds with no errors
2. **Loopback test** — `sudo $(cabal list-bin ebpf-net-monitor) lo` attaches to loopback
3. **ICMP visibility** — `ping -c 3 localhost` in another terminal → TUI shows ICMP rows with 127.0.0.1
4. **TCP visibility** — `curl http://example.com` → TUI shows TCP rows on monitored interface
5. **Clean exit** — press 'q' → TC hooks detached, process exits 0, `tc filter show dev lo ingress` shows no filters
6. **No leaks** — run with `+RTS -s` and confirm stable residency across batches
7. **ASan clean** — sanitizer build shows no errors under `ping` workload

## Implementation order

When building this project from scratch, follow this order:

1. **Scaffolding**: Create directory structure, `cabal.project`, `.cabal` file, `scripts/gen-vmlinux.sh`
2. **Copy arena.h**: Copy from `C-Makefile/include/arena.h` to `cbits/arena.h`
3. **monitor.h**: Write the shared event struct with `_Static_assert`
4. **monitor.bpf.c + Makefile.bpf**: Write the eBPF program, verify it compiles with `make -f cbits/Makefile.bpf`
5. **monitor.c**: Write userspace C with FFI wrappers (`arena_init_ffi`, `arena_release_ffi`, `arena_reset_ffi`, `monitor_init`, `monitor_poll`, `monitor_cleanup`)
6. **FFI.hs**: Foreign imports + Storable instance — verify cabal builds the C
7. **Stream.hs**: Streamly pipeline — can test with `putStrLn . show` instead of TUI
8. **TUI.hs**: brick app — integrate with Stream via BChan
9. **Main.hs**: Wire everything together
10. **Test**: Follow the verification checklist above

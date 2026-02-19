# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build commands

Local dev machine is macOS — cannot build eBPF or link against libbpf. Use the typecheck target for local Haskell validation:

```bash
cabal build lib:typecheck          # type-check all Haskell modules (linker error at end is expected)
make -C test/cbits CC=clang        # build C tests (Linux only)
make -C test/cbits test            # run C tests (Linux only)
```

Full build and test (Linux only, CI does this):

```bash
cabal build exe:ebpf-net-monitor test:tests
cabal test test:tests --test-show-details=direct
```

Run (requires root or CAP_NET_ADMIN + CAP_BPF):

```bash
sudo $(cabal list-bin ebpf-net-monitor) <interface>
```

eBPF bytecode (requires vmlinux.h and clang):

```bash
./scripts/gen-vmlinux.sh           # generate bpf/vmlinux.h from kernel BTF
make -f cbits/Makefile.bpf         # compile bpf/monitor.bpf.o
```

## Build configuration

`cabal.project` sets GHC 9.10 with LLVM backend and clang for C compilation/linking:
- `-fllvm -pgmc clang -pgml clang` — LLVM codegen, clang compiles C and links
- `-optl-no-pie` — disables PIE linking; required because GHC's pre-built cabal-store dependencies are not compiled with -fPIC, causing R_X86_64_32S relocation errors on Ubuntu 24.04 where clang defaults to PIE

CI installs `llvm-15` and symlinks `opt-15`/`llc-15` to `opt`/`llc` because GHC 9.10 requires LLVM 13-15 and Ubuntu 24.04 ships LLVM 18.

The cabal file has three targets:
- `library typecheck` — type-checks all modules with `-fno-code` (no C deps needed, linker failure expected)
- `executable ebpf-net-monitor` — the main binary
- `test-suite tests` — Haskell tests (tasty + HUnit + QuickCheck)

## Architecture

```
C (eBPF kernel + libbpf userspace)  ──FFI──>  Haskell (Streamly pipeline + brick TUI)
```

**Data flow:** eBPF TC hooks capture packets → ring buffer → C `monitor_poll` copies events into arena → Haskell `peek`s via Storable → Streamly aggregates into Map → BChan → brick TUI renders table.

**Memory ownership:** Haskell owns the arena lifecycle via `bracket`. C writes events into the arena during `monitor_poll`. Haskell reads events, then calls `arenaReset`. The arena uses mmap with commit-on-demand (`OOM_COMMIT`), living outside the GHC heap.

**Backpressure chain:** TUI slow → BChan fills → Streamly blocks → `monitor_poll` blocks on `ring_buffer__poll` timeout → no data loss.

### FFI boundary (`src/FFI.hs` ↔ `cbits/monitor.c`)

The shared struct `net_event` (24 bytes, defined in `cbits/monitor.h`) must match the Haskell `Storable NetEvent` instance exactly — same offsets, same padding. A `_Static_assert` in C and explicit offset tests in `test/FFITest.hs` guard this.

FFI safety rules:
- `unsafe`: arena ops (non-blocking, <100ns) — `arena_init_ffi`, `arena_reset_ffi`, `arena_release_ffi`, `arena_used_ffi`
- `safe`: monitor ops (kernel interaction, blocking) — `monitor_init`, `monitor_poll`, `monitor_cleanup`

C returns Arena struct by value, but Haskell FFI can't marshal that. The `_ffi` wrappers in `monitor.c` malloc a heap copy.

### Platform guards

All libbpf code in `monitor.c` is behind `#ifdef __linux__`. On non-Linux: `monitor_init` returns `-ENOSYS`, `monitor_poll` returns NULL. This lets cabal type-check and test arena/struct logic on macOS.

## Testing

34 Haskell tests + 20 C tests. Test files:

- `test/FFITest.hs` — Storable roundtrip, IP string conversion, protocol/direction encoding, arena FFI wrappers
- `test/StreamTest.hs` — pure `updateAgg` aggregation logic (no IO needed)
- `test/cbits/test_monitor.c` — struct layout assertions, arena FFI wrappers, batch allocation, non-Linux stubs

The QuickCheck `Arbitrary Protocol` instance must avoid generating `OtherProto n` where n is a known protocol number (1=ICMP, 6=TCP, 17=UDP), since `toProtocol` canonicalizes those.

## Conventions

- Haskell: explicit export lists, qualified imports for Data.Map.Strict, `{-# UNPACK #-}` on small numeric fields
- C: K&R style, 4-space indent, `_Static_assert` for struct layout, null checks in FFI wrappers
- CC flags: `-Wall -Wextra -Wno-unused-function -Wno-error -O2`
- GHC flags: `-W -O2 -threaded -rtsopts "-with-rtsopts=-N"`
- Do not fail the build on warnings (`-Wno-error` in C, `-W` not `-Werror` in Haskell)
- Do not build on macOS — use `cabal build lib:typecheck` only
- Do not switch ghcup — GHC version is set via `with-compiler: ghc-9.10` in `cabal.project`

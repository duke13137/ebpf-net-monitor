[![Build & Test](https://github.com/duke13137/ebpf-net-monitor/actions/workflows/build.yml/badge.svg)](https://github.com/duke13137/ebpf-net-monitor/actions/workflows/build.yml)

# ebpf-net-monitor

Minimal eBPF network packet monitor. Attaches TC (traffic control) hooks to capture per-packet metadata (src/dst IP, protocol, direction, size), batches events through a zero-copy arena via ring buffer, and streams them into a live terminal dashboard.

**C** for the eBPF TC program and libbpf userspace polling. **Haskell** for stream processing (Streamly) and TUI (brick), connected via FFI with arena-based zero-copy event batching.

Requires Linux 6.1+ with BTF, root or `CAP_NET_ADMIN` + `CAP_BPF`.

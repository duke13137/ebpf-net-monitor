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

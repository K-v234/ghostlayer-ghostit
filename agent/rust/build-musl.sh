
#!/bin/bash

# Ghost IT — musl static build for the Rust eBPF agent

#

# Cross-compiling from a glibc host to musl fails for libbpf-sys with

# missing kernel headers (asm/unistd.h, asm/types.h) -- this must run

# inside a real musl environment (rust:alpine container), not a

# cross-compile from the host.

#

# Real dead ends hit building this, recorded so they aren't

# rediscovered next time:

#   1. Missing -lz: zlib-dev only provides the *shared* lib on Alpine;

#      static linking needs zlib-static specifically.

#   2. Missing -lelf: same issue, needs libelf-static.

#   3. Missing ZSTD_* symbols: libelf.a was built against zstd

#      compression support. Installing zstd-static ALONE doesn't fix

#      this -- libbpf-sys's build script only emits "-lelf -lz" on

#      the link line, it doesn't know libelf transitively needs

#      zstd. Must force it via RUSTFLAGS="-l static=zstd".

set -euo pipefail

cd "$(dirname "$0")"



docker run --rm \

  -v "$(pwd)/../..":/build \

  -w /build/agent/rust \

  -e RUSTFLAGS="-L /usr/lib -l static=zstd" \

  rust:alpine sh -c "

    apk add --no-cache musl-dev linux-headers libbpf-dev elfutils-dev \

      zlib-dev zlib-static libelf-static zstd-static clang llvm make pkgconfig && \

    cargo build --release --target x86_64-unknown-linux-musl

  "



echo "Build complete. Binary at:"

echo "  agent/rust/target/x86_64-unknown-linux-musl/release/ghost-agent"

file target/x86_64-unknown-linux-musl/release/ghost-agent


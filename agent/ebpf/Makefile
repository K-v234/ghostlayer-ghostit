# Ghost IT eBPF Agent — Makefile
# Production build: CO-RE (Compile Once, Run Everywhere) via BTF

CC      := gcc
CLANG   := clang
BPFTOOL := bpftool

ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS  := -Wall -Wextra -O2 -Isrc
BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I. -Isrc \
              -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean run

all: vmlinux.h ghost_agent.bpf.o ghost_agent

# Step 1: extract BTF type info from running kernel
vmlinux.h:
	@echo "[*] Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "[+] vmlinux.h ready"

# Step 2: compile BPF kernel program
ghost_agent.bpf.o: src/ghost_agent.bpf.c src/ghost_agent.h vmlinux.h
	@echo "[*] Compiling BPF kernel program..."
	$(CLANG) $(BPF_CFLAGS) -c src/ghost_agent.bpf.c -o $@
	@echo "[+] ghost_agent.bpf.o ready"

# Step 3: compile userspace loader
ghost_agent: src/ghost_agent.c src/ghost_agent.h
	@echo "[*] Compiling userspace loader..."
	$(CC) $(CFLAGS) src/ghost_agent.c -o $@ -lbpf -lelf -lz
	@echo "[+] ghost_agent binary ready"

# Run: pipe JSON events to terminal (dry-run mode)
run: all
	sudo ./ghost_agent | python3 python/agent.py --dry-run

clean:
	rm -f vmlinux.h ghost_agent.bpf.o ghost_agent

.PHONY: all clean

# A failed/interrupted bpftool dump must not leave a partial vmlinux.h behind.
.DELETE_ON_ERROR:

# `make` must build, not fetch the toolchain, so pin the goal before the include.
.DEFAULT_GOAL := all

# Resolve clang, bpftool and the libbpf headers from yeet's vendored toolchain
# cache (fetched on demand by the `toolchain` target) — no system BPF toolchain
# needed. A `make CLANG=…` / `BPFTOOL=…` override still wins.
include build/toolchain.mk

ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
# PATH fallbacks, used only when toolchain.mk resolved nothing (off-Linux).
CLANG   ?= clang
BPFTOOL ?= bpftool

# Prefer the vendored libbpf headers; fall back to system libbpf-dev on PATH.
LIBBPF_INCLUDE ?= $(if $(BPF_SYSINCLUDE),$(BPF_SYSINCLUDE),/usr/include)

CFLAGS = -O2 -g -Wall -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. -Iinclude -I$(LIBBPF_INCLUDE)

all: usbsnoop.bpf.o

# struct urb, usb_device, … come from the running kernel's BTF (CO-RE).
include/vmlinux.h: | toolchain
	sh build/gen-vmlinux.sh $(BPFTOOL) $@

usbsnoop.bpf.o: usbsnoop.bpf.c include/vmlinux.h | toolchain
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f usbsnoop.bpf.o include/vmlinux.h

.PHONY: all clean

# A failed/interrupted bpftool dump must not leave a partial vmlinux.h
# behind — make would treat the half-written file as up to date and the
# build would fail confusingly downstream. Delete targets on recipe error.
.DELETE_ON_ERROR:

ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
CLANG   ?= clang
BPFTOOL ?= sudo bpftool

# Prefer the bpf headers that ship with libbpf-sys (so this builds without
# system libbpf-dev). Fall back to /usr/include if the libbpf-sys build
# artifact isn't around.
LIBBPF_INCLUDE := $(firstword $(wildcard \
    ../../crates/target/release/build/libbpf-sys-*/out/include) \
    /usr/include)

CFLAGS = -O2 -g -Wall -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. -Iinclude -I$(LIBBPF_INCLUDE)

all: usbsnoop.bpf.o

# struct urb, usb_device, usb_host_endpoint, the usb_device_descriptor and
# the usb_device_speed enum all come from the running kernel's BTF — CO-RE,
# no system linux/usb.h needed.
include/vmlinux.h:
	@mkdir -p include
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

usbsnoop.bpf.o: usbsnoop.bpf.c include/vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f usbsnoop.bpf.o include/vmlinux.h

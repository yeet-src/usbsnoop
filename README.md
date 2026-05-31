# usbsnoop — live USB transfer sniffer from two fentry hooks

![usbsnoop demo](assets/demo.gif)

A real-time, colorized feed of USB traffic **system-wide** — built on the two
universal URB chokepoints every host-controller driver funnels through, so it
works on xHCI/EHCI/OHCI/dwc alike with no per-controller tracepoints and no
`usbmon`. Fully CO-RE portable.

| fentry hook              | what it tells us                                        |
| ------------------------ | ------------------------------------------------------- |
| `usb_submit_urb`         | a transfer was queued (device, endpoint, type, payload) |
| `usb_hcd_giveback_urb`   | it completed (status, bytes moved, latency, payload)    |

An `lru_hash` keyed by the URB pointer stitches the two together: submit stamps
a start time, completion reads it back for the submit→complete latency, then
deletes it. This mirrors `httpbody`'s request/response pairing — **SUBMIT** is
the "request" (what the host sends), **COMPLETE** the "response" (what the
device returns).

Control transfers get their 8-byte SETUP packet decoded into the standard
request name (`GET_DESCRIPTOR`, `SET_CONFIGURATION`, …); data stages render as
text when they look textual and as a hexdump otherwise.

Output is **one line per event** (compact). The first time a device appears it
gets a `▸` legend line (`bus-dev`, `vid:pid`, product, link speed); after that
each row carries only the short `DEV` tag, so the left-hand columns stay aligned
and scannable under heavy traffic. Each row shows time, kind (SUBMIT/CMPLT),
transfer type, `epNdir`, the direction arrow (`←` device→host IN, `→`
host→device OUT), byte counts, status, latency, and the owning kernel driver,
then a `·` and the most useful detail (decoded SETUP, SCSI command, or a short
payload preview). Pass `--hex` for the full multi-line hexdump instead. Hex
bytes are colored by value class (null blue, printable ASCII cyan, whitespace
green, other control magenta, high/non-ASCII yellow) on a TTY; piped output is
plain.

## Use cases

- **Reverse-engineering peripherals** — watch a device enumerate and exchange
  vendor control requests and HID reports live, no hardware sniffer or `usbmon`
  setup. SETUP packets and payloads are decoded as you poke at the device.
- **Driver / firmware debugging** — see exactly which commands your driver or
  app sends a device and what comes back, with submit→complete latency on every
  transfer.
- **Mass-storage / SCSI inspection** — Bulk-Only Transport wrappers decode to
  the SCSI command (`READ(10) lba=… blocks=…`, `WRITE(10)`, `CSW PASS/FAIL`).
- **Catching errors** — `--errors-only` surfaces stalls (`EPIPE`), timeouts,
  babble, and CRC errors across every device at once.
- **Spotting rogue devices** — a freshly plugged device shows what it does the
  instant it attaches; BadUSB-style HID injection surfaces as `INT` reports or
  `SET_REPORT` control writes you didn't trigger.
- **Capture for offline analysis** — `--json` emits NDJSON; pipe to `jq` or a
  file to diff payloads across runs.
- **Performance triage** — on a timed exit you get a per-device rollup and a
  log2 latency histogram to find the slow or chatty devices.

## Install

```sh
curl -fsSL https://yeet.cx | sh
```

Then run it straight from GitHub — yeet fetches the example and builds it for
you, no clone needed:

```sh
yeet run github:yeet-src/usbsnoop
```

## Build

To build from a local checkout instead:

```sh
make
```

Dumps the kernel's BTF to `vmlinux.h` (for `struct urb`, `usb_device`, and the
device descriptor), then compiles. Requires `clang`, `bpftool`, and a kernel
with BTF.

## Run

```sh
yeet run .                              # all devices, 600s
yeet run . -- --secs 30                 # run for 30s
yeet run . -- --vid 0x320f              # one vendor
yeet run . -- --vendor-id 0x046d --product-id 0xc52b # one device by id
yeet run . -- --bus 3 --dev 4           # one device by bus address
yeet run . -- --type control,int        # only these transfer types
yeet run . -- --no-data                 # metadata only, skip payload capture
yeet run . -- --max-data 64             # cap rendered payload at 64 bytes
yeet run . -- --errors-only             # only failed completions (stalls, timeouts)
yeet run . -- --hex                      # full multi-line hexdump per transfer
yeet run . -- --json | jq .             # NDJSON, one object per event
```

**No `sudo`.** The `yeetd` daemon already holds the privilege (`CAP_BPF` +
`CAP_PERFMON`) and reads the URB buffers from kernel memory; the `yeet run`
client just talks to it over its user socket, so you run it as your normal user.
The only thing that still wants root is reading the two kallsyms base addresses
for scatter-gather payloads (see below) — `/proc/kallsyms` redacts addresses for
non-root unless `kptr_restrict` is `0`.

## Flags

| flag           | default | meaning                                              |
| -------------- | ------- | ---------------------------------------------------- |
| `--secs`       | `600`   | how long to run                                      |
| `--vid`, `--vendor-id`  | any | filter by vendor id (hex `0x1d6b` or decimal)    |
| `--pid`, `--product-id` | any | filter by product id                             |
| `--bus`        | any     | filter by bus number                                 |
| `--dev`        | any     | filter by device address                             |
| `--type`       | all     | csv of `iso`, `int`, `control`, `bulk`               |
| `--no-data`    | off     | don't read transfer buffers (metadata only)          |
| `--max-data`   | `4096`  | max bytes of payload rendered per event              |
| `--errors-only`| off     | show only non-OK completions (skips SUBMIT and OK)   |
| `--hex`        | off     | full multi-line hexdump per transfer (compact inline preview otherwise) |
| `--json`       | off     | emit NDJSON (one object per event) instead of the TTY view |
| `--page-offset-base` | off | kernel `page_offset_base` address (hex) — enables SG payload capture (x86-64) |
| `--vmemmap-base`     | off | kernel `vmemmap_base` address (hex) — paired with `--page-offset-base` |

All filtering happens kernel-side, so filtered-out traffic never reaches
userspace.

Each event line ends with the owning kernel driver in brackets
(`[hid_irq_in]`, `[usb_api_blocking_completion]`) — `urb->complete` symbolized
in-kernel via `bpf_snprintf("%ps")`, so no `/proc/kallsyms` lookup is needed.
Mass-storage bulk transfers decode their Bulk-Only Transport wrapper into the
SCSI command (`CBW READ(10) lba=… blocks=…` / `CSW PASS`). On a timed exit
(reaching `--secs`) a per-device summary and a log2 latency histogram print;
a Ctrl-C exit skips it (there is no JS-visible signal hook).

## Scatter-gather payloads

Bulk traffic (mass storage and friends) often hands the stack a `struct
scatterlist` array (`urb->sg`) instead of a single linear `transfer_buffer`, so
the payload lives scattered across pages. usbsnoop walks that array and copies
each segment's bytes, but reaching them means translating a page to its kernel
virtual address — the inverse of x86-64's `page_to_virt`, which needs the
running kernel's `page_offset_base` and `vmemmap_base` (both KASLR-randomized).

The JS isolate can't read `/proc/kallsyms` and the loader has no ksym support,
so you pass the two symbol *addresses* in and the BPF side dereferences them:

```sh
yeet run . -- \
  --page-offset-base 0x$(sudo awk '$3=="page_offset_base"{print $1}' /proc/kallsyms) \
  --vmemmap-base     0x$(sudo awk '$3=="vmemmap_base"{print $1}'     /proc/kallsyms)
```

Without those flags, SG transfers still show full metadata, just no payload
bytes — the prior behavior. This path is **x86-64 only**: on other arches leave
the flags off.

## Limits

- Only the first **16384 bytes** of each transfer are captured (a power of two —
  the verifier read-clamp depends on it). Larger buffers are truncated; the
  header still reports the true `actual/requested` length. Each ring record
  carries a full `data[16384]`, so the 8 MiB ring holds ~512 events.
- Scatter-gather payloads need the `--page-offset-base` / `--vmemmap-base` flags
  above and an x86-64 host; each segment is captured up to a page, and only the
  first 64 segments of a transfer are walked.
- A transfer submitted before usbsnoop attached has no start stamp, so its
  completion shows no latency.
- USB descriptors are little-endian and read directly — correct on the
  little-endian hosts BPF runs on.

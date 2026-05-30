/* vmlinux.h dumped from a recent kernel emits a block of kfunc/ksym
 * prototypes (e.g. bpf_stream_vprintk) that collide with the ones in an
 * older bundled bpf_helpers.h. We call no kfuncs, so suppress that block
 * — bpf_helpers.h supplies every helper we use. */
#define BPF_NO_KFUNC_PROTOTYPES

/* The bpftool-generated vmlinux.h emits forward declarations the kernel
 * BTF dump can't fully resolve, which clang flags under -Wall. Harmless
 * — silence them for this header alone, leaving -Wall live below. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* usbsnoop — sniff USB transfers system-wide off the two universal URB
 * chokepoints every host-controller driver funnels through, regardless of
 * xHCI/EHCI/OHCI/dwc, so it works without per-controller tracepoints:
 *
 *   fentry/usb_submit_urb       → a URB was handed to the stack. Stamp a
 *                                 start time keyed by the urb pointer and,
 *                                 for traffic that already carries a
 *                                 host→device payload (control setup, OUT
 *                                 data stages), stream a SUBMIT event.
 *   fentry/usb_hcd_giveback_urb → the controller finished the URB. Recover
 *                                 the start stamp for the latency, read the
 *                                 final status + actual_length, and stream
 *                                 a COMPLETE event carrying the bytes that
 *                                 actually moved (device→host data on IN,
 *                                 the echoed OUT buffer otherwise).
 *
 * This mirrors httpbody's request/response pairing: SUBMIT is the "request"
 * (what the host sends), COMPLETE the "response" (what the device returns),
 * with the submit→complete gap as latency. The kernel side filters by
 * vendor/product/bus/device/transfer-type so userspace only decodes traffic
 * the operator asked for. Only the first DATA_CAP bytes of each transfer are
 * captured. Scatter-gather URBs (`urb->sg`, no linear `transfer_buffer`) are
 * walked segment by segment, each segment's page resolved to a kernel virtual
 * address (x86-64), provided userspace patched in the page_offset_base /
 * vmemmap_base addresses; absent those, SG transfers surface with metadata
 * but no payload. */

/* Must stay a power of two: capture_buf bounds the read with `n &= DATA_MAX`,
 * which is only a correct length clamp when DATA_MAX is all-ones. Each event
 * record carries a full data[DATA_CAP], so this also sets how many events the
 * ring holds (~512 at 16 KiB in the 8 MiB ring below). */
#define DATA_CAP 16384            /* bytes of transfer payload per event */
#define DATA_MAX (DATA_CAP - 1)   /* cap reads at sizeof-1 so the verifier
                                   * mask can't wrap a full read to zero */

/* Scatter-gather walk bounds. A single sg segment is copied in one read of at
 * most SG_CHUNK bytes; with the `off <= DATA_CAP - SG_CHUNK` guard the verifier
 * sees a constant max for both the destination offset and the length, so their
 * sum provably stays within data[DATA_CAP]. SG_CHUNK is a USB page (the common
 * segment size) so page-sized segments copy whole; a larger segment is clipped
 * to SG_CHUNK. MAX_SG_SEGS bounds the loop — payload past it is truncated. */
#define SG_CHUNK     4096
#define MAX_SG_SEGS  64
#define PAGE_SHIFT   12           /* x86-64 base page */

/* scatterlist.page_link low bits (linux/scatterlist.h): bit0 marks a chain
 * pointer to a continuation array (not a page), bit1 marks the last entry. */
#define SG_CHAIN_BIT 0x1UL
#define SG_END_BIT   0x2UL
#define SG_PTR_MASK  (~0x3UL)

/* `pipe` bit layout (linux/usb.h) — none of these macros land in BTF, so
 * define the handful we use. Direction lives in bit 7, endpoint in bits
 * 15-18, transfer type in bits 30-31. */
#define USB_DIR_IN              0x80
#define PIPE_ISOCHRONOUS        0
#define PIPE_INTERRUPT          1
#define PIPE_CONTROL            2
#define PIPE_BULK               3
#define usb_pipein(p)           ((p) & USB_DIR_IN)
#define usb_pipetype(p)         (((p) >> 30) & 3)
#define usb_pipeendpoint(p)     (((p) >> 15) & 0xf)

#define EVT_SUBMIT   0
#define EVT_COMPLETE 1

/* Filter knobs, patched from userspace after load via the data section.
 * A zero means "any" for the id fields; `filt_types` is a bitmask of
 * `1 << PIPE_*` with zero meaning "all types". */
volatile __u32 enabled    = 1;
volatile __u32 filt_vid   = 0;
volatile __u32 filt_pid   = 0;
volatile __u32 filt_bus   = 0;
volatile __u32 filt_dev   = 0;
volatile __u32 filt_types = 0;
volatile __u32 capture    = 1;  /* read transfer buffers into the event */

/* Kernel addresses of `page_offset_base` and `vmemmap_base`, patched from
 * userspace after it reads them out of /proc/kallsyms (root already required).
 * Resolving a scatter-gather page to a kernel virtual address needs the live
 * values of these KASLR-randomized bases; this kernel's BTF carries no VARs,
 * so a typed __ksym extern won't link — we read the bases via these pointers
 * instead. Zero means "unavailable" (non-x86, or kallsyms restricted), and the
 * SG walk degrades to metadata-only. */
volatile __u64 kva_page_offset = 0;
volatile __u64 kva_vmemmap     = 0;

struct usb_event {
    __u64 ts;          /* ktime ns at the hook */
    __u64 lat_ns;      /* COMPLETE: submit→complete ns; SUBMIT: 0 */
    __u64 urb;         /* urb kernel pointer — pairs SUBMIT with COMPLETE */
    __u32 buf_len;     /* transfer_buffer_length (requested) */
    __u32 actual_len;  /* COMPLETE: bytes transferred; SUBMIT: 0 */
    __u32 data_len;    /* bytes captured into data[] */
    __s32 status;      /* COMPLETE: urb status (0 ok, -errno); SUBMIT: 0 */
    __u16 vid;
    __u16 pid;
    __u8  busnum;
    __u8  devnum;
    __u8  epnum;       /* endpoint number 0-15 */
    __u8  xfer_type;   /* PIPE_* — 0 iso, 1 int, 2 ctrl, 3 bulk */
    __u8  dir_in;      /* 1 = device→host (IN) */
    __u8  kind;        /* EVT_SUBMIT | EVT_COMPLETE */
    __u8  speed;       /* enum usb_device_speed */
    __u8  has_setup;   /* setup[] holds a valid control packet */
    __u8  setup[8];    /* control SETUP packet (control transfers only) */
    char  product[32]; /* device product string, best effort */
    char  driver[40];  /* urb->complete symbolized — the owning driver */
    __u8  data[DATA_CAP];
};

/* clang can drop BTF for a struct only reached through the local pointer
 * `bpf_ringbuf_reserve` hands back. Anchor it in a __used global so the
 * type survives — yeet's ringbuf bind resolves it via `btf_struct`. */
__attribute__((used)) static const struct usb_event __usb_event_anchor;

/* urb pointer → submit ktime. LRU so a missed giveback (device yanked
 * mid-transfer) can't leak the entry. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 65536);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} events SEC(".maps");

struct urb_meta {
    void          *transfer_buffer;
    unsigned char *setup_packet;
    void          *complete;       /* completion callback — symbolized for driver id */
    void          *sg;             /* scatterlist array when transfer_buffer is NULL */
    __u32 num_sgs;
    __u32 buf_len;
    __u16 vid;
    __u16 pid;
    __u8  busnum;
    __u8  devnum;
    __u8  epnum;
    __u8  xfer_type;
    __u8  dir_in;
    __u8  speed;
    char  product[32];  /* read here, not via a stored dev pointer — CO-RE
                         * can't relocate a deref through a member of this
                         * non-kernel struct */
};

static __always_inline int parse_urb(struct urb *urb, struct urb_meta *m)
{
    struct usb_device *dev = BPF_CORE_READ(urb, dev);
    if (!dev)
        return -1;

    unsigned int pipe = BPF_CORE_READ(urb, pipe);
    m->xfer_type = usb_pipetype(pipe);
    m->dir_in    = usb_pipein(pipe) ? 1 : 0;
    m->epnum     = usb_pipeendpoint(pipe);

    /* idVendor/idProduct are __le16; the BPF target is the host CPU, so on
     * the little-endian machines this runs on a direct read is correct. */
    m->vid = BPF_CORE_READ(dev, descriptor.idVendor);
    m->pid = BPF_CORE_READ(dev, descriptor.idProduct);

    m->busnum = BPF_CORE_READ(dev, bus, busnum);
    m->devnum = BPF_CORE_READ(dev, devnum);
    m->speed  = BPF_CORE_READ(dev, speed);

    m->buf_len         = BPF_CORE_READ(urb, transfer_buffer_length);
    m->transfer_buffer = BPF_CORE_READ(urb, transfer_buffer);
    m->setup_packet    = BPF_CORE_READ(urb, setup_packet);
    m->complete        = BPF_CORE_READ(urb, complete);
    m->sg              = BPF_CORE_READ(urb, sg);
    m->num_sgs         = BPF_CORE_READ(urb, num_sgs);

    m->product[0] = '\0';
    char *prod = BPF_CORE_READ(dev, product);
    if (prod)
        bpf_probe_read_kernel_str(m->product, sizeof(m->product), prod);
    return 0;
}

static __always_inline int filter_ok(const struct urb_meta *m)
{
    if (!enabled)
        return 0;
    if (filt_vid && m->vid != filt_vid)
        return 0;
    if (filt_pid && m->pid != filt_pid)
        return 0;
    if (filt_bus && m->busnum != filt_bus)
        return 0;
    if (filt_dev && m->devnum != filt_dev)
        return 0;
    if (filt_types && !(filt_types & (1u << m->xfer_type)))
        return 0;
    return 1;
}

/* Copy up to DATA_MAX bytes from a linear kernel buffer into the event. The
 * barrier+mask keeps the read length both nonzero and bounded by the
 * destination for the verifier — same shape as httpbody's payload load. */
static __always_inline __u32 capture_buf(const void *src, __u32 want, __u8 *dst)
{
    /* No prezero of the full DATA_CAP buffer — at this size clang lowers it
     * to an unsupported memset call, and userspace only ever reads the first
     * `data_len` bytes, so the untouched tail never surfaces. */
    if (!src || want == 0)
        return 0;

    __u32 n = want < DATA_MAX ? want : DATA_MAX;
    barrier_var(n);
    n &= DATA_MAX;
    if (n == 0)
        return 0;
    if (bpf_probe_read_kernel(dst, n, src) < 0)
        return 0;
    return n;
}

/* Resolve a scatterlist page_link to its kernel virtual address, the inverse
 * of x86-64's page_to_virt: pfn = page - vmemmap, va = page_offset + pfn*PAGE.
 * Both bases are KASLR-randomized, read live from the kallsyms addresses
 * patched in by userspace. Returns 0 when the bases are unavailable. */
static __always_inline unsigned long sg_page_kva(unsigned long page_link)
{
    if (!kva_page_offset || !kva_vmemmap)
        return 0;

    unsigned long page = page_link & SG_PTR_MASK;
    if (!page)
        return 0;

    unsigned long page_offset = 0, vmemmap = 0;
    if (bpf_probe_read_kernel(&page_offset, sizeof(page_offset),
                              (const void *)(unsigned long)kva_page_offset) < 0)
        return 0;
    if (bpf_probe_read_kernel(&vmemmap, sizeof(vmemmap),
                              (const void *)(unsigned long)kva_vmemmap) < 0)
        return 0;
    if (!page_offset || !vmemmap || page < vmemmap)
        return 0;

    unsigned long pfn = (page - vmemmap) / sizeof(struct page);
    return page_offset + (pfn << PAGE_SHIFT);
}

/* Walk a scatter-gather URB's segment array, concatenating up to DATA_MAX bytes
 * of payload into the event. Each segment's pages are physically (hence, in the
 * direct map, virtually) contiguous, so a segment is one read at its page's
 * kva + offset. Stops at the segment count, a chain/end marker, the byte
 * budget, or MAX_SG_SEGS — whichever comes first. */
static __always_inline __u32 capture_sg(const void *sg_base, __u32 num_sgs,
                                        __u32 want, __u8 *dst)
{
    if (!sg_base || num_sgs == 0 || want == 0)
        return 0;

    __u32 budget = want < DATA_MAX ? want : DATA_MAX;
    __u32 off = 0;

    for (int i = 0; i < MAX_SG_SEGS; i++) {
        if (i >= (int)num_sgs || off >= budget)
            break;
        /* Reserve a full SG_CHUNK of headroom so the verifier can prove
         * off + n <= DATA_CAP from the two constant maxima below. */
        if (off > DATA_CAP - SG_CHUNK)
            break;

        struct scatterlist se;
        if (bpf_core_read(&se, sizeof(se),
                          (const struct scatterlist *)sg_base + i) < 0)
            break;
        if (se.page_link & SG_CHAIN_BIT)
            break;

        unsigned long kva = sg_page_kva(se.page_link);
        if (kva) {
            __u32 avail = budget - off;
            __u32 n = se.length < avail ? se.length : avail;
            if (n > SG_CHUNK)
                n = SG_CHUNK;
            if (n &&
                bpf_probe_read_kernel(dst + off, n,
                                      (const void *)(kva + se.offset)) == 0)
                off += n;
        }

        if (se.page_link & SG_END_BIT)
            break;
    }
    return off;
}

/* Unified payload capture: a linear transfer_buffer when present, otherwise the
 * scatter-gather segment array. `want` is the meaningful length (requested on
 * OUT, actual_length on COMPLETE). */
static __always_inline __u32 capture_payload(const struct urb_meta *m,
                                             __u32 want, __u8 *dst)
{
    if (m->transfer_buffer)
        return capture_buf(m->transfer_buffer, want, dst);
    return capture_sg(m->sg, m->num_sgs, want, dst);
}

static __always_inline void fill_common(struct usb_event *e,
                                        const struct urb_meta *m,
                                        __u8 kind, __u64 ts, __u64 urb)
{
    e->ts        = ts;
    e->urb       = urb;
    e->kind      = kind;
    e->vid       = m->vid;
    e->pid       = m->pid;
    e->busnum    = m->busnum;
    e->devnum    = m->devnum;
    e->epnum     = m->epnum;
    e->xfer_type = m->xfer_type;
    e->dir_in    = m->dir_in;
    e->speed     = m->speed;
    e->buf_len   = m->buf_len;
    e->lat_ns    = 0;
    e->actual_len = 0;
    e->status    = 0;
    e->has_setup = 0;
    __builtin_memset(e->setup, 0, sizeof(e->setup));
    __builtin_memcpy(e->product, m->product, sizeof(e->product));

    /* Symbolize the completion callback to the owning driver's function name
     * (e.g. usbhid_irq, hub_irq). %ps resolves the kernel pointer in-kernel,
     * so userspace needs no /proc/kallsyms lookup. */
    e->driver[0] = '\0';
    __u64 sargs[1] = { (__u64)(unsigned long)m->complete };
    bpf_snprintf(e->driver, sizeof(e->driver), "%ps", sargs, sizeof(sargs));
}

SEC("fentry/usb_submit_urb")
int BPF_PROG(on_submit, struct urb *urb, unsigned int mem_flags)
{
    if (!enabled)
        return 0;

    struct urb_meta m;
    if (parse_urb(urb, &m) < 0)
        return 0;

    __u64 key = (__u64)(unsigned long)urb;
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&inflight, &key, &ts, BPF_ANY);

    if (!filter_ok(&m))
        return 0;

    /* Only emit a SUBMIT event when there is host→device payload worth
     * showing: a control transfer (always carries an 8-byte setup) or any
     * OUT transfer (the buffer already holds the outgoing data). A bare IN
     * submit has no data yet — stay quiet and let COMPLETE speak. */
    __u8 is_ctrl = (m.xfer_type == PIPE_CONTROL);
    if (m.dir_in && !is_ctrl)
        return 0;

    struct usb_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, &m, EVT_SUBMIT, ts, key);

    if (is_ctrl && m.setup_packet &&
        bpf_probe_read_kernel(e->setup, sizeof(e->setup), m.setup_packet) == 0)
        e->has_setup = 1;

    /* OUT data (incl. a control OUT data stage) is in the buffer now; an IN
     * control transfer's data stage hasn't been filled yet. */
    e->data_len = (capture && !m.dir_in)
        ? capture_payload(&m, m.buf_len, e->data)
        : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/usb_hcd_giveback_urb")
int BPF_PROG(on_complete, struct usb_hcd *hcd, struct urb *urb, int status)
{
    if (!enabled)
        return 0;

    struct urb_meta m;
    if (parse_urb(urb, &m) < 0)
        return 0;

    __u64 key = (__u64)(unsigned long)urb;
    __u64 now = bpf_ktime_get_ns();

    __u64 lat = 0;
    __u64 *tsp = bpf_map_lookup_elem(&inflight, &key);
    if (tsp) {
        lat = now - *tsp;
        bpf_map_delete_elem(&inflight, &key);
    }

    if (!filter_ok(&m))
        return 0;

    __u32 actual = BPF_CORE_READ(urb, actual_length);

    struct usb_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, &m, EVT_COMPLETE, now, key);
    e->lat_ns     = lat;
    e->status     = status;
    e->actual_len = actual;

    /* The data has landed by now: device→host bytes on IN, the still-intact
     * OUT buffer otherwise. Capture what actually moved (actual_length). */
    e->data_len = capture ? capture_payload(&m, actual, e->data) : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

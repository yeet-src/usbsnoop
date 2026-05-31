import { DataSec, LruHashMap, RingBuf } from "yeet:bpf";
import bpf from "./usbsnoop.bpf.o";

/* usbsnoop — stream a live, colorized view of USB transfers system-wide.
 * The BPF side hooks usb_submit_urb / usb_hcd_giveback_urb and does all the
 * filtering (by vendor/product/bus/device/transfer-type), so userspace just
 * decodes each `usb_event`: control SETUP packets are parsed into the
 * standard bRequest names, data stages are rendered as text when they look
 * textual and hex-dumped otherwise. */

/* Globals split across two data sections by their initializer: `enabled`
 * and `capture` default nonzero so they land in `.data`; the `filt_*` knobs
 * default 0 ("any") so the linker parks them in `.bss`. Bind and patch both
 * — a patch to a symbol in the wrong section fails the symbol-table lookup. */
const DATA_SEC = "usbsnoop.data"; /* objname stem; <= 8 chars, no truncation */
const BSS_SEC = "usbsnoop.bss";

const args = (typeof yeet !== "undefined" && yeet.args) || {};
/* yeet normalizes `--kebab-case` flags to snake_case keys on yeet.args
 * (e.g. `--max-data` → args.max_data), so read those forms. */
/* Run until Ctrl-C by default; a numeric --secs sets a fixed duration and
 * prints the per-device summary + latency histogram on that timed exit. */
const rawSecs = args.secs ?? args.s;
const SECS = rawSecs == null ? null : Number(rawSecs);
const MAX_DATA = Number(args.max_data ?? 4096);
const CAPTURE = !parseBool(args.no_data);
const ERRORS_ONLY = parseBool(args.errors_only ?? args.errors);
const JSON_OUT = parseBool(args.json);
/* Default to one line per event with a short inline payload preview; --hex
 * opts into the full multi-line hexdump (legible only at low traffic). */
const HEX = parseBool(args.hex);
const PREVIEW = 12; /* bytes of inline payload shown per event when not --hex */

function parseBool(v) {
  if (v == null) return false;
  if (typeof v === "boolean") return v;
  const s = String(v).trim().toLowerCase();
  return s === "" || s === "1" || s === "true" || s === "yes" || s === "on";
}

/* Accept hex ("0x1d6b", "1d6b") or decimal for the id filters. */
function parseId(v) {
  if (v == null) return 0;
  const s = String(v).trim();
  if (s === "") return 0;
  const n = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, /[a-f]/i.test(s) ? 16 : 10);
  return Number.isFinite(n) ? n & 0xffff : 0;
}

const FILT_VID = parseId(args.vendor_id ?? args.vid);
const FILT_PID = parseId(args.product_id ?? args.pid);
const FILT_BUS = Number(args.bus ?? 0) | 0;
const FILT_DEV = Number(args.dev ?? 0) | 0;

/* Scatter-gather payloads (URBs with `urb->sg`, no linear transfer_buffer)
 * need their pages translated to kernel virtual addresses, which requires the
 * live, KASLR-randomized page_offset_base / vmemmap_base. The JS isolate can't
 * read /proc/kallsyms and the loader has no ksym support, so the operator
 * passes the two symbol *addresses* in and the BPF side dereferences them (see
 * README "Scatter-gather payloads"). Without them, SG transfers still show full
 * metadata, just no payload bytes — the prior behavior. */
function parseAddr(v) {
  if (v == null) return 0n;
  const s = String(v).trim();
  if (s === "") return 0n;
  try {
    return BigInt(/^0x/i.test(s) ? s : /[a-f]/i.test(s) ? `0x${s}` : s);
  } catch {
    return 0n;
  }
}
const KVA_PAGE_OFFSET = parseAddr(args.page_offset_base);
const KVA_VMEMMAP = parseAddr(args.vmemmap_base);

/* --type control,bulk,int,iso → bitmask of (1 << PIPE_*). */
const TYPE_BIT = { iso: 0, isoc: 0, int: 1, interrupt: 1, ctrl: 2, control: 2, bulk: 3 };
const FILT_TYPES = (args.type != null ? String(args.type).split(",") : [])
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)
  .reduce((mask, t) => {
    const bit = TYPE_BIT[t];
    if (bit == null) throw new Error(`unknown --type "${t}" (iso|int|control|bulk)`);
    return mask | (1 << bit);
  }, 0);

/* Color via the platform's tty-aware `style.*` helpers: they emit ANSI on a
 * TTY and pass plain text through when stdout is piped, so the same code
 * renders cleanly either way. The `tty` namespace only exists under a PTY,
 * so its presence is our raw-mode signal below. */
const RAW = typeof tty !== "undefined";
const bold = (s) => style.bold(String(s));
const red = (s) => style.red(String(s));
const grn = (s) => style.green(String(s));
const yel = (s) => style.yellow(String(s));
const blu = (s) => style.blue(String(s));
const mag = (s) => style.magenta(String(s));
const cyan = (s) => style.cyan(String(s));
const dim = (s) => style.dim(String(s));
/* Secondary scaffolding (timestamps, field labels, offsets, separators) in
 * blue — a calm palette color rather than washed-out gray. The driver and
 * truncation markers get their own accents (magenta / yellow) at the call
 * sites for variety. */
const meta = (s) => blu(String(s));

/* Under a raw-mode PTY the kernel doesn't map `\n` → `\r\n`, so rewrite line
 * endings; when piped (no `tty` global) leave them alone. */
function log(msg = "") {
  const s = String(msg);
  console.log(RAW ? s.replace(/\r?\n/g, "\r\n") + "\r" : s);
}

const KIND = { 0: "SUBMIT", 1: "CMPLT " };
const XFER = ["ISO", "INT", "CTRL", "BULK"];
const XFER_COLOR = [mag, blu, cyan, grn];

/* Fixed column widths so SUBMIT and COMPLETE rows line up. Pad the plain
 * text to these, then color — ANSI codes don't count toward terminal
 * width, so coloring after padding keeps the columns aligned. Oversized
 * values (jumbo bulk transfers, rare long errno names) overflow their
 * cell rather than truncate. */
const W_DEV = 5; /* busnum-devnum, e.g. "3-4" (longer overflows) */
const W_EP = 6; /* "ep1in" / "ep15out" */
const W_BYTES = 9; /* "actual/buf_lenB" */
const W_STATUS = 8; /* "OK" / "EINPROGRESS" (long errnos overflow) */
const W_LAT = 7; /* "260.9ms" / "1.23s" */
const SPEED = {
  0: "?",
  1: "low",      /* 1.5 Mbps */
  2: "full",     /* 12 Mbps */
  3: "high",     /* 480 Mbps */
  4: "wireless",
  5: "super",    /* 5 Gbps */
  6: "super+",   /* 10 Gbps */
};

/* Common URB completion statuses (negative errno). 0 is success. */
const STATUS = {
  0: "OK",
  "-2": "ENOENT",
  "-18": "EXDEV(iso)",
  "-19": "ENODEV",
  "-22": "EINVAL",
  "-28": "ENOSPC",
  "-32": "EPIPE(stall)",
  "-62": "ETIME",
  "-71": "EPROTO",
  "-75": "EOVERFLOW(babble)",
  "-84": "EILSEQ(crc)",
  "-104": "ECONNRESET(unlink)",
  "-108": "ESHUTDOWN",
  "-110": "ETIMEDOUT",
  "-115": "EINPROGRESS",
  "-121": "EREMOTEIO(short)",
};

/* Standard control bRequest names (bmRequestType type bits == standard). */
const STD_REQ = {
  0: "GET_STATUS",
  1: "CLEAR_FEATURE",
  3: "SET_FEATURE",
  5: "SET_ADDRESS",
  6: "GET_DESCRIPTOR",
  7: "SET_DESCRIPTOR",
  8: "GET_CONFIGURATION",
  9: "SET_CONFIGURATION",
  10: "GET_INTERFACE",
  11: "SET_INTERFACE",
  12: "SYNCH_FRAME",
};
const DESC_TYPE = {
  1: "DEVICE",
  2: "CONFIG",
  3: "STRING",
  4: "INTERFACE",
  5: "ENDPOINT",
  6: "DEV_QUALIFIER",
  0x21: "HID",
  0x22: "REPORT",
  0x29: "HUB",
};
const REQ_TYPE = ["std", "class", "vendor", "rsvd"];
const REQ_RECIP = ["device", "interface", "endpoint", "other"];

function hhmmss() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${ms}`;
}

function hex4(n) {
  return (n & 0xffff).toString(16).padStart(4, "0");
}

function latInfo(ns) {
  if (ns == null) return null;
  const n = Number(ns);
  if (!Number.isFinite(n) || n <= 0) return null;
  const ms = n / 1e6;
  const col = ms < 1 ? grn : ms < 50 ? yel : red;
  const text = ms < 1 ? `${(n / 1e3).toFixed(0)}us` : ms < 1000 ? `${ms.toFixed(1)}ms` : `${(ms / 1000).toFixed(2)}s`;
  return { text, col };
}

/* char[] comes back char-flagged as a JS string; trim at the first NUL. */
function cstr(v) {
  if (v == null) return "";
  if (typeof v === "string") {
    const nul = v.indexOf("\0");
    return nul >= 0 ? v.slice(0, nul) : v;
  }
  let s = "";
  for (const b of v) {
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
}

/* __u8[] arrives as a Uint8Array (or string when char-flagged); normalize
 * and trim to the kernel-reported length. */
function bytes(raw, len) {
  let u8;
  if (raw == null) u8 = new Uint8Array(0);
  else if (typeof raw === "string") {
    u8 = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) u8[i] = raw.charCodeAt(i) & 0xff;
  } else if (raw instanceof Uint8Array) u8 = raw;
  else u8 = new Uint8Array(raw);
  const n = Math.min(Number(len ?? u8.length), u8.length);
  return u8.subarray(0, n);
}

/* Decode an 8-byte control SETUP packet (USB 2.0 §9.3) into a one-liner. */
function decodeSetup(s) {
  if (s.length < 8) return meta("(short setup)");
  const bmRequestType = s[0];
  const bRequest = s[1];
  const wValue = s[2] | (s[3] << 8);
  const wIndex = s[4] | (s[5] << 8);
  const wLength = s[6] | (s[7] << 8);

  const dirIn = (bmRequestType & 0x80) !== 0;
  const type = REQ_TYPE[(bmRequestType >> 5) & 3];
  const recip = REQ_RECIP[bmRequestType & 0x1f] ?? `recip${bmRequestType & 0x1f}`;

  let reqName;
  if (type === "std") {
    reqName = STD_REQ[bRequest] ?? `req 0x${bRequest.toString(16)}`;
  } else {
    reqName = `req 0x${bRequest.toString(16).padStart(2, "0")}`;
  }

  /* For GET/SET_DESCRIPTOR the high byte of wValue is the descriptor type
   * and the low byte the index — spell it out, it's the common case. */
  let extra = "";
  if (type === "std" && (bRequest === 6 || bRequest === 7)) {
    const dt = (wValue >> 8) & 0xff;
    const di = wValue & 0xff;
    extra = `  ${meta(`${DESC_TYPE[dt] ?? `type 0x${dt.toString(16)}`}#${di}`)}`;
  }

  /* Pad the request name and the type/recip/dir field to fixed widths so the
   * wValue/wIndex/wLength columns line up across consecutive SETUP lines. */
  const tr = `${type}/${recip} ${dirIn ? "IN" : "OUT"}`;
  return (
    `${bold(reqName.padEnd(17))} ${meta(tr.padEnd(19))} ` +
    `${meta("wValue=")}${cyan(`0x${hex4(wValue)}`)} ` +
    `${meta("wIndex=")}${cyan(`0x${hex4(wIndex)}`)} ` +
    `${meta("wLength=")}${yel(String(wLength))}${extra}`
  );
}

const GRAYDOT = mag(".");

/* Render a data buffer: text when it reads textual, otherwise a hexdump.
 * Truncated at MAX_DATA either way. */
function renderData(buf) {
  if (buf.length === 0) return "";

  let printable = 0;
  for (const b of buf) {
    if ((b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
  }
  const textual = buf.length >= 4 && printable / buf.length > 0.85;

  if (textual) {
    let s = "";
    const limit = Math.min(buf.length, MAX_DATA);
    for (let i = 0; i < limit; i++) s += String.fromCharCode(buf[i]);
    s = s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, ".");
    if (buf.length > limit) s += yel(`…(${buf.length - limit} more)`);
    return `${meta('  "')}${s}${meta('"')}`;
  }

  let out = "";
  const limit = Math.min(buf.length, MAX_DATA);
  for (let i = 0; i < limit; i += 16) {
    let hex = "";
    let asc = "";
    let width = 0;
    for (let j = 0; j < 16 && i + j < limit; j++) {
      const b = buf[i + j];
      const col = byteCol(b);
      hex += `${col(b.toString(16).padStart(2, "0"))} `;
      width += 3;
      asc += b >= 0x20 && b < 0x7f ? col(String.fromCharCode(b)) : GRAYDOT;
    }
    const pad = " ".repeat(Math.max(0, 48 - width));
    out += `  ${meta(i.toString(16).padStart(4, "0"))}  ${hex}${pad} ${asc}\n`;
  }
  if (buf.length > limit) out += `  ${yel(`…(${buf.length - limit} more bytes)`)}\n`;
  return out.trimEnd();
}

function statusInfo(status) {
  const s = Number(status) || 0;
  const name = STATUS[String(s)] ?? `errno ${s}`;
  if (s === 0) return { text: "OK", col: grn };
  if (s === -115 || s === -121) return { text: name, col: yel };
  return { text: name, col: red };
}

/* urb->complete is symbolized kernel-side via %ps; a null/unresolved
 * callback comes back as "0x0…" or "(null)" — treat those as no driver. */
function driverName(e) {
  const d = cstr(e.driver);
  if (!d || d === "(null)" || /^0x0*$/.test(d)) return "";
  return d;
}

function u32be(b, o) {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
function u32le(b, o) {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

/* SCSI opcodes carried over USB Mass Storage Bulk-Only Transport. */
const SCSI_OP = {
  0x00: "TEST_UNIT_READY",
  0x03: "REQUEST_SENSE",
  0x12: "INQUIRY",
  0x1a: "MODE_SENSE(6)",
  0x1b: "START_STOP_UNIT",
  0x1e: "PREVENT_ALLOW_REMOVAL",
  0x23: "READ_FORMAT_CAPACITIES",
  0x25: "READ_CAPACITY(10)",
  0x28: "READ(10)",
  0x2a: "WRITE(10)",
  0x2f: "VERIFY(10)",
  0x35: "SYNCHRONIZE_CACHE",
  0x88: "READ(16)",
  0x8a: "WRITE(16)",
  0x9e: "READ_CAPACITY(16)",
  0xa0: "REPORT_LUNS",
};
const CBW_SIG = 0x43425355; /* 'USBC' little-endian */
const CSW_SIG = 0x53425355; /* 'USBS' little-endian */

/* Decode a Bulk-Only Transport wrapper: the 31-byte Command Block Wrapper
 * (host→device, carries the SCSI CDB) or the 13-byte Command Status Wrapper
 * (device→host). Returns null when the buffer isn't one. */
function decodeScsi(buf) {
  if (buf.length === 31 && u32le(buf, 0) === CBW_SIG) {
    const dataLen = u32le(buf, 8);
    const dirIn = (buf[12] & 0x80) !== 0;
    const lun = buf[13] & 0x0f;
    const cbLen = buf[14] & 0x1f;
    const op = buf[15];
    const name = SCSI_OP[op] ?? `op 0x${op.toString(16).padStart(2, "0")}`;

    /* READ/WRITE/VERIFY(10) carry a 32-bit big-endian LBA at CDB[2] and a
     * 16-bit block count at CDB[7]; CDB starts at buf[15]. */
    let extra = "";
    if ((op === 0x28 || op === 0x2a || op === 0x2f) && cbLen >= 10) {
      const lba = u32be(buf, 17);
      const blocks = (buf[22] << 8) | buf[23];
      extra = meta(`  lba=${lba} blocks=${blocks}`);
    }
    return `${bold("CBW")} ${name} ${meta(`lun=${lun} ${dirIn ? "IN" : "OUT"} ${dataLen}B`)}${extra}`;
  }
  if (buf.length === 13 && u32le(buf, 0) === CSW_SIG) {
    const residue = u32le(buf, 8);
    const st = buf[12];
    const stName = st === 0 ? grn("PASS") : st === 1 ? red("FAIL") : yel("PHASE_ERR");
    return `${bold("CSW")} ${stName} ${meta(`residue=${residue}B`)}`;
  }
  return null;
}

function hexOf(buf) {
  let s = "";
  for (const b of buf) s += b.toString(16).padStart(2, "0");
  return s;
}

/* Color a byte by value class (hexyl-style) so structure pops out of a dump:
 * null blue, printable ASCII cyan, whitespace green, other control magenta,
 * high/non-ASCII yellow. */
function byteCol(b) {
  if (b === 0x00) return meta;
  if (b === 0x20 || (b >= 0x21 && b <= 0x7e)) return cyan;
  if (b === 0x09 || b === 0x0a || b === 0x0b || b === 0x0c || b === 0x0d) return grn;
  if (b < 0x20 || b === 0x7f) return mag;
  return yel;
}

/* A compact one-line payload preview: the first `n` bytes space-separated and
 * colored, with a `+NB` marker when there is more. Keeps high-traffic output
 * to a single line per event. */
function previewHex(buf, n) {
  const limit = Math.min(buf.length, n);
  let s = "";
  for (let i = 0; i < limit; i++) {
    const b = buf[i];
    s += (i ? " " : "") + byteCol(b)(b.toString(16).padStart(2, "0"));
  }
  if (buf.length > limit) s += yel(` +${buf.length - limit}B`);
  return s;
}

/* Per-device and overall rollups, printed by printSummary at the timed
 * teardown. Latency feeds a log2-µs histogram so it stays bounded. */
const stats = { total: 0, bytes: 0, errors: 0, dev: new Map(), lat: new Map() };

/* Devices already announced in a legend line, so each is described once. */
const seenDevices = new Set();

function recordStat(e) {
  stats.total++;
  const key = `${e.busnum}-${e.devnum}`;
  let d = stats.dev.get(key);
  if (!d) {
    d = {
      prod: cstr(e.product),
      vidpid: `${hex4(e.vid)}:${hex4(e.pid)}`,
      n: 0, bytes: 0, errors: 0, latSum: 0, latN: 0, latMax: 0,
    };
    stats.dev.set(key, d);
  }
  d.n++;
  if (e.kind !== 1) return;

  const act = Number(e.actual_len) || 0;
  d.bytes += act;
  stats.bytes += act;
  if ((Number(e.status) || 0) !== 0) {
    d.errors++;
    stats.errors++;
  }
  const ns = Number(e.lat_ns) || 0;
  if (ns > 0) {
    d.latSum += ns;
    d.latN++;
    if (ns > d.latMax) d.latMax = ns;
    const bucket = Math.max(0, Math.floor(Math.log2(ns / 1e3)));
    stats.lat.set(bucket, (stats.lat.get(bucket) ?? 0) + 1);
  }
}

function emitJson(e, prod, driver, data) {
  const obj = {
    ts: hhmmss(),
    kind: KIND[e.kind]?.trim() ?? e.kind,
    dev: `${e.busnum}-${e.devnum}`,
    vid: hex4(e.vid),
    pid: hex4(e.pid),
    xfer: XFER[e.xfer_type] ?? e.xfer_type,
    ep: e.epnum,
    dir: e.dir_in ? "in" : "out",
    buf_len: e.buf_len,
  };
  if (e.kind === 1) {
    obj.actual_len = e.actual_len;
    obj.status = Number(e.status) || 0;
    const ns = Number(e.lat_ns) || 0;
    if (ns > 0) obj.lat_ns = ns;
  }
  if (prod) obj.product = prod;
  if (driver) obj.driver = driver;
  if (e.has_setup) obj.setup = hexOf(bytes(e.setup, 8));
  if (data.length) obj.data = hexOf(data);
  console.log(JSON.stringify(obj));
}

function onEvent(e) {
  /* --errors-only keeps just failed completions (SUBMIT and OK drop out). */
  if (ERRORS_ONLY && !(e.kind === 1 && (Number(e.status) || 0) !== 0)) return;

  recordStat(e);

  const prod = cstr(e.product);
  const driver = driverName(e);
  const data = bytes(e.data, e.data_len);

  if (JSON_OUT) {
    emitJson(e, prod, driver, data);
    return;
  }

  const kind = KIND[e.kind] ?? "?";
  const xfer = XFER[e.xfer_type] ?? "?";
  const xcol = XFER_COLOR[e.xfer_type] ?? meta;
  const arrow = e.dir_in ? mag("←") : cyan("→");
  const dev = `${e.busnum}-${e.devnum}`;
  const vidpid = `${hex4(e.vid)}:${hex4(e.pid)}`;
  const ep = `ep${e.epnum}${e.dir_in ? "in" : "out"}`;
  const speed = SPEED[e.speed] ?? "?";
  const kcol = e.kind === 0 ? blu : grn;

  /* SUBMIT shows the requested length; COMPLETE the actual/requested pair. */
  const bytesText = e.kind === 0 ? `${e.buf_len}B` : `${e.actual_len}/${e.buf_len}B`;

  let statusCell;
  let latCell;
  if (e.kind === 0) {
    statusCell = meta("req".padEnd(W_STATUS));
    latCell = " ".repeat(W_LAT);
  } else {
    const st = statusInfo(e.status);
    statusCell = st.col(st.text.padEnd(W_STATUS));
    const lat = latInfo(e.lat_ns);
    latCell = lat ? lat.col(lat.text.padStart(W_LAT)) : " ".repeat(W_LAT);
  }

  /* Device identity (vid:pid, product, speed) is printed once in a legend
   * the first time a device appears, so event rows stay narrow and the
   * left-hand columns line up for scanning. The short DEV tag is the key. */
  if (!seenDevices.has(dev)) {
    seenDevices.add(dev);
    log(
      `${grn("▸")} ${bold(dev)}  ${cyan(vidpid)}  ${prod || meta("?")}` +
        `  ${yel(speed)}`,
    );
  }

  const line = [
    dim(hhmmss()),
    kcol(kind),
    bold(dev.padStart(W_DEV)),
    xcol(xfer.padEnd(4)),
    cyan(ep.padEnd(W_EP)),
    arrow,
    bytesText.padStart(W_BYTES),
    statusCell,
    latCell,
    driver ? mag(driver) : "",
  ].join(" ");

  const setup = e.has_setup ? bytes(e.setup, 8) : null;
  const scsi = data.length && e.xfer_type === 3 ? decodeScsi(data) : null;

  if (HEX) {
    /* Verbose: event line, then setup/SCSI/hexdump on their own lines. */
    log(line.trimEnd());
    if (setup) log(`  ${decodeSetup(setup)}`);
    if (scsi) log(`  ${scsi}`);
    else if (data.length) {
      const rendered = renderData(data);
      if (rendered) log(rendered);
    }
    return;
  }

  /* Compact (default): fold the most useful detail onto the event line so a
   * busy bus stays one-line-per-event. Setup decode wins over a SCSI wrapper
   * wins over a raw payload preview. */
  let detail = "";
  if (setup) detail = decodeSetup(setup);
  else if (scsi) detail = scsi;
  else if (data.length) detail = previewHex(data, PREVIEW);
  log(detail ? `${line.trimEnd()}  ${meta("·")} ${detail}` : line.trimEnd());
}

/* Column legend, printed once under the banner. Widths mirror the cells in
 * onEvent so the labels sit over their columns. */
function printHeader() {
  const h = [
    "TIME".padEnd(12),
    "KIND".padEnd(6),
    "DEV".padStart(W_DEV),
    "TYPE".padEnd(4),
    "EP".padEnd(W_EP),
    " ",
    "BYTES".padStart(W_BYTES),
    "STATUS".padEnd(W_STATUS),
    "LAT".padStart(W_LAT),
    "DRIVER",
  ].join(" ");
  log(bold(meta(h)));
}

function fmtBytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1048576).toFixed(1)}MB`;
}

function fmtNs(ns) {
  if (!ns) return "0";
  const ms = ns / 1e6;
  return ms < 1 ? `${(ns / 1e3).toFixed(0)}us` : ms < 1000 ? `${ms.toFixed(1)}ms` : `${(ms / 1000).toFixed(2)}s`;
}

/* Printed once at the timed teardown. There is no JS-visible SIGINT hook,
 * so a Ctrl-C exit skips this — let the run reach --secs for the rollup. */
function printSummary() {
  if (JSON_OUT) return;

  log("");
  log(bold("── summary ──"));
  const rows = [...stats.dev.entries()].sort((a, b) => b[1].n - a[1].n);
  for (const [key, d] of rows) {
    const avg = d.latN ? d.latSum / d.latN : 0;
    log(
      `${meta(key.padStart(W_DEV))} ${bold(d.vidpid)} ${String(d.n).padStart(7)} ev  ` +
        `${fmtBytes(d.bytes).padStart(9)}  ` +
        `${d.errors ? red(`${d.errors} err`) : meta("0 err")}  ` +
        `${meta(`avg ${fmtNs(avg)}  max ${fmtNs(d.latMax)}`)}  ${meta(d.prod)}`,
    );
  }
  log(meta(`total ${stats.total} events  ${fmtBytes(stats.bytes)}  ${stats.errors} errors`));

  if (stats.lat.size) {
    log("");
    log(bold("completion latency  ") + meta("(µs, log2 buckets)"));
    const max = Math.max(...stats.lat.values());
    const keys = [...stats.lat.keys()].sort((a, b) => a - b);
    for (const k of keys) {
      const lo = 2 ** k;
      const hi = 2 ** (k + 1);
      const cnt = stats.lat.get(k);
      const bar = "█".repeat(Math.max(1, Math.round((cnt / max) * 32)));
      log(`${meta(`${String(lo).padStart(8)}–${String(hi).padEnd(9)}`)}${grn(bar)} ${meta(cnt)}`);
    }
  }
}

try {
  const control = await bpf
    .bind("inflight", { kind: "lru_hash_map" })
    .bind("events", { kind: "ringbuf", btf_struct: "usb_event" })
    .bind(DATA_SEC, { kind: "data" })
    .bind(BSS_SEC, { kind: "data" })
    .start();

  const knobs = new DataSec(control, DATA_SEC);
  const filt = new DataSec(control, BSS_SEC);
  const events = new RingBuf(control, "events");
  new LruHashMap(control, "inflight"); /* validated, written kernel-side */

  await filt.patch({
    filt_vid: FILT_VID,
    filt_pid: FILT_PID,
    filt_bus: FILT_BUS,
    filt_dev: FILT_DEV,
    filt_types: FILT_TYPES,
    kva_page_offset: KVA_PAGE_OFFSET,
    kva_vmemmap: KVA_VMEMMAP,
  });
  await knobs.patch({ capture: CAPTURE ? 1 : 0 });

  const filters = [];
  if (FILT_VID) filters.push(`vid=${hex4(FILT_VID)}`);
  if (FILT_PID) filters.push(`pid=${hex4(FILT_PID)}`);
  if (FILT_BUS) filters.push(`bus=${FILT_BUS}`);
  if (FILT_DEV) filters.push(`dev=${FILT_DEV}`);
  if (FILT_TYPES) {
    const names = XFER.filter((_, i) => FILT_TYPES & (1 << i)).join(",");
    filters.push(`type=${names}`);
  }
  if (ERRORS_ONLY) filters.push("errors-only");
  /* JSON mode emits pure NDJSON — no human banner to keep the stream clean. */
  if (!JSON_OUT) {
    log(
      `${bold("usbsnoop")} — watching usb_submit_urb / usb_hcd_giveback_urb ` +
        `${SECS == null ? "until interrupted" : `for ${SECS}s`}  ${meta(`(${filters.length ? filters.join(" ") : "all devices"}${CAPTURE ? "" : ", no-data"})`)}`,
    );
    log(`${meta("Ctrl-C to stop. URB buffers are read from kernel memory by yeetd.")}`);
    if (CAPTURE && (!KVA_PAGE_OFFSET || !KVA_VMEMMAP)) {
      log(
        meta(
          "Scatter-gather payloads off — pass --page-offset-base/--vmemmap-base " +
            "(from /proc/kallsyms) to capture them. See README.",
        ),
      );
    }
    log("");
    printHeader();
  }

  const sub = await events.subscribe(
    (rec) => onEvent(rec.usb_event ?? rec),
    (err) => console.error("ringbuf error:", err),
  );

  /* Don't block top-level on the run duration. An unresolved top-level
   * await keeps the module in the "evaluating" state, and console output
   * is only flushed to a non-TTY sink once evaluation completes — so
   * `yeet run | cat` would print nothing until exit. Let top-level
   * resolve here (the live subscription, and the teardown timer when one is
   * set, keep the isolate alive) so events stream as they arrive. */
  if (SECS != null) {
    setTimeout(async () => {
      try {
        await knobs.patch({ enabled: 0 });
        await sub.unsubscribe();
        await control.stop();
        printSummary();
      } catch (err) {
        console.error(err);
      }
    }, SECS * 1000);
  }
} catch (err) {
  console.error(err);
}

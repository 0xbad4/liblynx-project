# Protocol: Transmission Control Protocol (`TCP`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `TCP`](#5-class-tcp)
- [6. Checksum Algorithm](#6-checksum-algorithm)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l4/tcp/tcp.hpp`,
  `include/lynx/protocols/l4/tcp/hdrs.hpp`,
  `include/lynx/protocols/l4/tcp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Segment`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 9293 — Transmission Control Protocol
  (TCP)](https://www.rfc-editor.org/rfc/rfc9293) (the current base
  specification, obsoleting the original RFC 793)

## 2. Overview

`TCP` implements the base TCP header (options are not separately parsed).
It requires a valid `underlayer_` (`IPv4` or `IPv6`, set automatically by
`operator/`) at checksum-computation time, since the TCP checksum covers a
pseudo-header derived from the enclosing IP layer.

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if Data Offset > 5)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrTCP` struct (packed, `include/lynx/protocols/l4/tcp/hdrs.hpp`):

```cpp
LYNX_PACKED HdrTCP {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;      // [7:4] header len in 32b words (min 5)  [3:0] reserved+NS
    uint8_t  flags;         // CWR ECE URG ACK PSH RST SYN FIN
    uint16_t window;
    uint16_t checksum;      // pseudo-header checksum — auto-computed
    uint16_t urg_ptr;

    [[nodiscard]] uint8_t  hdr_len()  const noexcept;
    [[nodiscard]] bool     flag(uint8_t f) const noexcept;
    [[nodiscard]] uint32_t hdr_bytes()const noexcept;
    void set_data_off(uint8_t words) noexcept;
};
```

`src_port`, `dst_port`, `seq`, `ack`, `window`, `checksum`, and `urg_ptr`
are stored in host byte order in `hdr_`, and swapped to/from network byte
order in `serialize()` / `dissect()`.

## 4. Constants

Defined in `include/lynx/protocols/l4/tcp/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IP_PROTO_TCP` | `6` | IP protocol number for TCP. |
| `TCP_HDR_LEN` | `20` | Base header length, no options. |
| `TCP_FLAG_FIN` | `0x001` | FIN flag. |
| `TCP_FLAG_SYN` | `0x002` | SYN flag. |
| `TCP_FLAG_RST` | `0x004` | RST flag. |
| `TCP_FLAG_PSH` | `0x008` | PSH flag. |
| `TCP_FLAG_ACK` | `0x010` | ACK flag. |
| `TCP_FLAG_URG` | `0x020` | URG flag. |
| `TCP_FLAG_ECE` | `0x040` | ECE flag. |
| `TCP_FLAG_CWR` | `0x080` | CWR flag. |
| `TCP_FLAG_NS` | `0x100` | Nonce Sum, [RFC 3540](https://www.rfc-editor.org/rfc/rfc3540) — occupies the high nibble of the `data_off` byte, distinct from the low-byte classic 8 flags. |
| `TCP_FLAG_SYN_ACK` | `SYN \| ACK` | Common combination. |
| `TCP_FLAG_FIN_ACK` | `FIN \| ACK` | Common combination. |
| `TCP_FLAG_RST_ACK` | `RST \| ACK` | Common combination. |

> **Note:** `include/lynx/protocols/l4/tcp/const.hpp` also defines the SCTP
> header-size `consteval` constants `SCTP_HDR_LEN` and
> `SCTP_CHUNK_HDR_LEN` alongside the TCP constants. These are duplicated
> (with identical values) in `include/lynx/protocols/l4/sctp/const.hpp` —
> see [sctp.md](sctp.md) for the canonical SCTP constant reference.

## 5. Class `TCP`

### Constructors

| Constructor | Description |
|---|---|
| `TCP()` | Default — zero-initialized header (`data_off = 0`, not `5`; set explicitly or via `set_data_off()` before serializing a hand-built header). |
| `explicit TCP(const hdrs::HdrTCP& h)` | Constructs directly from a pre-populated `HdrTCP`. |
| `TCP(uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window, uint16_t urg_ptr = 0, uint8_t hdr_words = 5)` | Constructs from explicit field values; sets `data_off` via `set_data_off(5)` internally (the `hdr_words` parameter is currently accepted but not itself passed to `set_data_off()` — the header length is always initialized to 5 32-bit words / 20 bytes by this constructor). |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (byte-order-swapped) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < TCP_HDR_LEN` or if the computed `hdr_len() * 4` is out of range. `load_` is set to the bytes beyond the (possibly options-extended) header. |
| `hdr_size() const override` | Returns `hdr_.hdr_len() * 4` — the data offset converted from 32-bit words to bytes. |
| `hdr() override` | Returns `HdrTCP*`. |
| `patch_checksum() override` | Computes the TCP checksum over a pseudo-header + TCP header + payload — see [§6](#6-checksum-algorithm). |
| `proto() const` | Returns `IP_PROTO_TCP` (`6`). |
| `swap_hdr_byte_order(HdrTCP&) const` | Internal helper — swaps `src_port`, `dst_port`, `seq`, `ack`, `window`, `checksum`, `urg_ptr` in place. |

## 6. Checksum Algorithm

`TCP::patch_checksum()` requires a valid `underlayer_` — the `IPv4` or
`IPv6` object this `TCP` was composed with via `operator/`
(`ip / tcp`). If no underlayer is set, it fails with
`Status::MissingLayer`.

Behavior branches on `underlayer_->ethertype()`:

- **IPv4** (`ETH_TYPE_IPV4`): builds a 12-byte IPv4 pseudo-header
  (`src_ip(4) | dst_ip(4) | zero(1) | proto=6(1) | tcp_len(2)`), followed
  by the TCP header (checksum field zeroed) and payload, then computes
  `utils::inet_checksum()` over the concatenation.
- **IPv6** (`ETH_TYPE_IPV6`): builds a 40-byte IPv6 pseudo-header
  (`src_ip(16) | dst_ip(16) | tcp_len(4) | zero(3) | next_hdr=6(1)`),
  followed by the TCP header and payload, then computes
  `utils::inet_checksum()` over the concatenation.
- **Any other underlayer**: fails with `Status::NotImplemented`. The
  source marks this branch with a `// HERE: add support for other
  protocols` comment, indicating this is an intentional extension point.

## 7. Example

Crafting a TCP SYN packet:

```cpp
proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
proto::TCP   tcp(12345, 80, 1234567890, 0, constants::TCP_FLAG_SYN, 65535);

ip4 / tcp;   // TCP::patch_checksum() runs here — ip4 becomes tcp.underlayer_

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured TCP segment:

```cpp
if (ip4->hdr()->proto == constants::IP_PROTO_TCP) {
    auto tcp = ip4->as<proto::TCP>();
    if (tcp && tcp->ok()) {
        if (tcp->hdr()->flags & constants::TCP_FLAG_SYN) { /* ... */ }
        auto app_data = tcp->load();   // application payload span
    }
}
```

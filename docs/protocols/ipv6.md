# Protocol: Internet Protocol version 6 (`IPv6`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `IPv6`](#5-class-ipv6)
- [6. Example](#6-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l3/ip/ipv6.hpp`,
  `include/lynx/protocols/l3/ip/hdrs.hpp`,
  `include/lynx/protocols/l3/ip/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Packet`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 8200 — Internet Protocol, Version 6 (IPv6)
  Specification](https://www.rfc-editor.org/rfc/rfc8200)

## 2. Overview

`IPv6` implements the fixed 40-byte IPv6 header. Unlike IPv4, IPv6 carries
**no header checksum** — this was a deliberate simplification introduced
by the IPv6 specification (originally RFC 2460, superseded by RFC 8200),
relying on checksums at the link layer and transport layer instead.
Accordingly, `IPv6` does not override `patch_checksum()` — the base
no-op implementation applies.

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                     Source Address (16 bytes)                +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                  Destination Address (16 bytes)              +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrIPv6` struct (packed, `include/lynx/protocols/l3/ip/hdrs.hpp`):

```cpp
LYNX_PACKED HdrIPv6 {
    uint32_t ver_tc_fl;     // [31:28] version=6  [27:20] traffic class  [19:0] flow label
    uint16_t payload_len;   // length of payload after this header
    uint8_t  next_hdr;      // next header type (same values as IPv4 proto)
    uint8_t  hop_limit;     // TTL equivalent (default 64)
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
};
```

Sub-byte accessors provided on `HdrIPv6`:

| Accessor | Description |
|---|---|
| `version()` | Returns bits `[31:28]` of `ver_tc_fl`. |
| `traffic_cls()` | Returns bits `[27:20]` of `ver_tc_fl`. |
| `flow_label()` | Returns bits `[19:0]` of `ver_tc_fl`. |
| `set_ver_tc_fl(ver, tc, fl)` | Packs `ver_tc_fl`. |

`ver_tc_fl` and `payload_len` are stored in host byte order in `hdr_`, and
swapped to/from network byte order in `serialize()` / `dissect()`.
`payload_len` is computed automatically at serialize time from
`load_.size()` — it does not need to be, and should not be, set manually.

## 4. Constants

Defined in `include/lynx/protocols/l3/ip/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IPV6_HDR_LEN` | `40` | Fixed header length. |
| `IPV6_VERSION` | `6` | Expected value of `version()`. |
| `IPV6_HOP_DEF` | `64` | Sensible default hop limit. |
| `IPV6_PROTO_NONXT` | `59` | "No Next Header" value (RFC 2460 / RFC 8200). |

## 5. Class `IPv6`

### Constructors

| Constructor | Description |
|---|---|
| `IPv6()` | Default — sets `version = 6`, all other `ver_tc_fl` bits `0`; `payload_len = 0` (computed at serialize time); `next_hdr = IPV6_PROTO_NONXT`; `hop_limit = IPV6_HOP_DEF`. |
| `explicit IPv6(const hdrs::HdrIPv6& h)` | Constructs directly from a pre-populated `HdrIPv6`. |
| `IPv6(uint32_t vtc_flow, uint16_t payload_len, uint8_t next_header, uint8_t hop_limit, const uint8_t src[16], const uint8_t dst[16])` | Constructs from explicit field values. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (byte-order-swapped, with `payload_len` recomputed from `load_.size()`) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len)` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < IPV6_HDR_LEN` or if `version() != 6`. `load_` is set to the bytes beyond the fixed 40-byte header. **Note:** unlike other protocol classes, `IPv6::dissect()` is not declared `override` in the source — it still satisfies the base contract because the signature matches, but this is inconsistent with the rest of the codebase. |
| `hdr_size() const override` | Returns `IPV6_HDR_LEN` (`40`), unconditionally — extension headers, if present in a captured packet, are not separately parsed and would remain part of `load_`. |
| `hdr() override` | Returns `HdrIPv6*`. |
| `ethertype() const override` | Returns `ETH_TYPE_IPV6` (`0x86DD`). |
| `dst() const override` | Returns `hdr_.dst_ip`. |

> `IPv6` does not override `patch_checksum()` — no header checksum exists
> for IPv6. Transport-layer checksums that require the IPv6 pseudo-header
> (`TCP`, `UDP`, `ICMPv6`) look up their `underlayer_` and branch on
> `ethertype() == ETH_TYPE_IPV6` to compute the correct pseudo-header —
> see [tcp.md](tcp.md), [udp.md](udp.md), and [icmpv6.md](icmpv6.md).

## 6. Example

Crafting an IPv6 + TCP packet:

```cpp
proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV6);
proto::IPv6  ip6(0x60000000, 20, constants::IP_PROTO_TCP, 64, src_ipv6, dst_ipv6);
proto::TCP   tcp(5000, 443, 100, 0, constants::TCP_FLAG_SYN, 65535);

ip6 / tcp;
eth / ip6;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured IPv6 packet:

```cpp
if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV6) {
    auto ip6 = eth->as<proto::IPv6>();
    if (ip6 && ip6->ok()) {
        switch (ip6->hdr()->next_hdr) {
            case constants::IP_PROTO_TCP:    { auto tcp    = ip6->as<proto::TCP>();    break; }
            case constants::IP_PROTO_UDP:    { auto udp    = ip6->as<proto::UDP>();    break; }
            case constants::IP_PROTO_ICMPV6: { auto icmpv6 = ip6->as<proto::ICMPv6>(); break; }
            // ...
        }
    }
}
```

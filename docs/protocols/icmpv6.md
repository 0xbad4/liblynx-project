# Protocol: Internet Control Message Protocol version 6 (`ICMPv6`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `ICMPv6`](#5-class-icmpv6)
- [6. Checksum Algorithm](#6-checksum-algorithm)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l4/icmp/icmpv6.hpp`,
  `include/lynx/protocols/l4/icmp/hdrs.hpp`,
  `include/lynx/protocols/l4/icmp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct, shared
  with `ICMP`), `lynx::constants` (constants)
- Base class: [`Segment`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 4443 — Internet Control Message Protocol (ICMPv6) for the
  Internet Protocol Version 6 (IPv6)
  Specification](https://www.rfc-editor.org/rfc/rfc4443)

## 2. Overview

`ICMPv6` reuses the same `HdrICMP` structure as `ICMP` (see
[icmp.md](icmp.md)) — the wire layout is identical between ICMPv4 and
ICMPv6. The distinguishing behavior of `ICMPv6` is its checksum, which —
unlike plain ICMP — **does** require an IPv6 pseudo-header, per RFC 4443
§2.3, since the checksum in ICMPv6 covers the source/destination
addresses to protect against certain routing misdelivery attacks that
IPv6 alone (having no header checksum, see [ipv6.md](ipv6.md)) cannot
detect.

`ICMPv6` covers ICMP message types used both for classic error/echo
messages and for Neighbor Discovery Protocol (NDP), per the type
constants listed below.

## 3. Wire Format

Identical to [ICMP](icmp.md#3-wire-format) — see `HdrICMP` in
`include/lynx/protocols/l4/icmp/hdrs.hpp`. `ICMPv6` interprets `type` and
`code` per its own constant range (`128`+ for echo, `133`–`136` for NDP)
rather than ICMPv4's (`0`–`11`).

## 4. Constants

Defined in `include/lynx/protocols/l4/icmp/const.hpp` (shared file with
ICMPv4):

| Constant | Value | Description |
|---|---|---|
| `IP_PROTO_ICMPV6` | `58` | IPv6 `next_hdr` value for ICMPv6. |
| `ICMPV6_HDR_LEN` | `8` | Fixed header length — same layout as ICMPv4. |
| `ICMPV6_DST_UNREACH` | `1` | Destination Unreachable. |
| `ICMPV6_TIME_EXCEED` | `3` | Time Exceeded. |
| `ICMPV6_ECHO_REQUEST` | `128` | Echo Request. |
| `ICMPV6_ECHO_REPLY` | `129` | Echo Reply. |
| `ICMPV6_RS` | `133` | Router Solicitation (NDP). |
| `ICMPV6_RA` | `134` | Router Advertisement (NDP). |
| `ICMPV6_NS` | `135` | Neighbor Solicitation (NDP). |
| `ICMPV6_NA` | `136` | Neighbor Advertisement (NDP). |

> NDP messages (types `133`–`136`) carry option TLVs in their payload
> (e.g. Source/Target Link-Layer Address, Prefix Information). `lynx`
> does not currently provide a dedicated TLV parser for NDP options —
> they are accessible as raw bytes via `icmpv6.load()` and must be parsed
> manually, or via `as<Raw>()`.

## 5. Class `ICMPv6`

### Constructors

| Constructor | Description |
|---|---|
| `ICMPv6()` | Default — zero-initialized header. |
| `ICMPv6(uint8_t type, uint8_t code, uint16_t id = 0, uint16_t seq = 0)` | Constructs with `type`, `code`, `checksum = 0`, and `rest` packed from `id`/`seq` via `set_id_seq()`. Convenient for Echo Request/Reply; for NDP messages, `rest` and any trailing options must be set separately (e.g. via `set_load()`). |
| `explicit ICMPv6(const hdrs::HdrICMP& h)` | Constructs directly from a pre-populated `HdrICMP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (byte-order-swapped) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < ICMPV6_HDR_LEN`. `load_` is set to the bytes beyond the fixed 8-byte header. |
| `hdr_size() const override` | Returns `ICMPV6_HDR_LEN` (`8`). |
| `hdr() override` | Returns `HdrICMP*`. |
| `patch_checksum() override` | Computes the checksum over an IPv6 pseudo-header + header + `load_` — see [§6](#6-checksum-algorithm). Requires a valid `underlayer_`. |
| `proto() const override` | Returns `IP_PROTO_ICMPV6` (`58`). |
| `swap_hdr_byte_order(HdrICMP&) const` | Internal helper — swaps `rest` and `checksum` in place. |

## 6. Checksum Algorithm

`ICMPv6::patch_checksum()` requires a valid `underlayer_` (set
automatically by `operator/` when composed as `ip6 / icmpv6`). If no
underlayer is set, it fails with `Status::MissingLayer`.

Steps (per RFC 4443 §2.3, referencing the IPv6 pseudo-header defined in
RFC 8200 §8.1):

1. Build a byte-order-swapped wire copy of the header with `checksum`
   zeroed.
2. Build a 40-byte IPv6 pseudo-header:
   `src_ip(16) | dst_ip(16) | icmp6_len(4, big-endian) | zero(3) | next_hdr=58(1)`,
   read from the `IPv6` `underlayer_`.
3. Concatenate the pseudo-header with the wire ICMPv6 header and
   `load_`.
4. Compute `utils::inet_checksum()` over the concatenation and store the
   result into `hdr_.checksum`.

Unlike `ICMP` (IPv4), `ICMPv6::patch_checksum()` currently only supports
an `IPv6` underlayer — there is no equivalent IPv4 branch, since ICMPv6
is by definition carried over IPv6.

## 7. Example

Crafting an ICMPv6 Echo Request:

```cpp
proto::IPv6   ip6(0x60000000, 8, constants::IP_PROTO_ICMPV6, 255, src_ipv6, dst_ipv6);
proto::ICMPv6 icmpv6(constants::ICMPV6_ECHO_REQUEST, 0, 5000, 1);

ip6 / icmpv6;

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV6);
eth / ip6;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured ICMPv6 message:

```cpp
if (ip6->hdr()->next_hdr == constants::IP_PROTO_ICMPV6) {
    auto icmpv6 = ip6->as<proto::ICMPv6>();
    if (icmpv6 && icmpv6->ok()) {
        switch (icmpv6->hdr()->type) {
            case constants::ICMPV6_ECHO_REQUEST: /* ... */ break;
            case constants::ICMPV6_NS:           /* neighbor solicitation */ break;
        }
    }
}
```

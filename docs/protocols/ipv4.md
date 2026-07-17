# Protocol: Internet Protocol version 4 (`IPv4`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `IPv4`](#5-class-ipv4)
- [6. Example](#6-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l3/ip/ipv4.hpp`,
  `include/lynx/protocols/l3/ip/hdrs.hpp`,
  `include/lynx/protocols/l3/ip/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Packet`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 791 — Internet
  Protocol](https://www.rfc-editor.org/rfc/rfc791)

## 2. Overview

`IPv4` implements the IPv4 header, including support for the variable
Internet Header Length (IHL) field (options are not separately parsed but
are preserved as part of the header size calculation). `IPv4` is the only
protocol class in the library that carries its own checksum
(`patch_checksum()` computes the standard IPv4 header checksum).

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |  DSCP |ECN|          Total Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if IHL > 5)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrIPv4` struct (packed, `include/lynx/protocols/l3/ip/hdrs.hpp`):

```cpp
LYNX_PACKED HdrIPv4 {
    uint8_t  ver_ihl;       // [7:4] version=4  [3:0] ihl (header len in 32b words)
    uint8_t  dscp_ecn;      // [7:2] dscp       [1:0] ecn
    uint16_t total_len;     // total length: header + payload
    uint16_t id;            // identification (fragmentation)
    uint16_t flags_frag;    // [15:13] flags  [12:0] fragment offset
    uint8_t  ttl;           // hop limit (default 64)
    uint8_t  proto;         // next protocol (6 TCP / 17 UDP / 1 ICMP)
    uint16_t checksum;      // header checksum — auto-computed
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
    // options follow if ihl > 5 (rarely used)
};
```

Sub-byte accessors provided on `HdrIPv4`:

| Accessor | Description |
|---|---|
| `version()` | Returns bits `[7:4]` of `ver_ihl`. |
| `ihl()` | Returns bits `[3:0]` of `ver_ihl` — header length in 32-bit words. |
| `dscp()` | Returns bits `[7:2]` of `dscp_ecn`. |
| `ecn()` | Returns bits `[1:0]` of `dscp_ecn`. |
| `ip_flags()` | Returns bits `[15:13]` of `flags_frag` (DF/MF). |
| `frag_off()` | Returns bits `[12:0]` of `flags_frag`. |
| `hdr_len()` | Returns `ihl() * 4` — header length in bytes. |
| `set_ver_ihl(ver, ihl_words)` | Packs `ver_ihl`. |
| `set_dscp_ecn(dscp, ecn)` | Packs `dscp_ecn`. |
| `set_flags_frag(flags, offset)` | Packs `flags_frag`. |

`total_len`, `id`, `flags_frag`, and `checksum` are stored in host byte
order in `hdr_`, and swapped to/from network byte order in `serialize()` /
`dissect()`.

## 4. Constants

Defined in `include/lynx/protocols/l3/ip/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IP_PROTO_IPV6` | `41` | IPv6 encapsulation. |
| `IP_PROTO_RAW` | `255` | Raw / unspecified. |
| `IPV4_HDR_LEN` | `20` | Base header size, no options. |
| `IPV4_MAX_LEN` | `65535` | Maximum total IP datagram length. |
| `IPV4_VERSION` | `4` | Expected value of `version()`. |
| `IPV4_TTL_DEF` | `64` | Sensible default TTL. |
| `IPV4_BROADCAST` | `0xFFFFFFFF` | `255.255.255.255` (host byte order). |
| `IPV4_LOOPBACK` | `0x7F000001` | `127.0.0.1` (host byte order). |
| `IPV4_ANY` | `0x00000000` | `0.0.0.0` (host byte order). |

> These IPv4 special addresses are stored in host byte order — call
> `htonl()` before assigning to a `sockaddr_in` field directly.

Additional IP protocol number constants used by `IPv4::hdr()->proto` are
defined alongside each L4 protocol; see:
[tcp.md](tcp.md) (`IP_PROTO_TCP = 6`),
[udp.md](udp.md) (`IP_PROTO_UDP = 17`),
[icmp.md](icmp.md) (`IP_PROTO_ICMP = 1`),
[igmp.md](igmp.md) (`IP_PROTO_IGMP`),
[sctp.md](sctp.md) (`IP_PROTO_SCTP = 132`).

## 5. Class `IPv4`

### Constructors

| Constructor | Description |
|---|---|
| `IPv4()` | Default — sets `version=4`, `ihl=5` (20 bytes, no options), `DF=1`/`MF=0`/`frag_offset=0`, `ttl = IPV4_TTL_DEF`, `proto = 0` (caller must set), `checksum = 0` (patched post-serialize). |
| `explicit IPv4(const hdrs::HdrIPv4& h)` | Constructs directly from a pre-populated `HdrIPv4`. |
| `IPv4(const uint8_t src[4], const uint8_t dst[4], uint8_t proto, uint16_t total_len = 0, uint16_t id = 0, uint16_t flags_frag = 0, uint8_t ttl = 64, uint8_t dscp_ecn = 0)` | Constructs from explicit field values, with sensible defaults for most fields. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (byte-order-swapped) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < IPV4_HDR_LEN`, if `version() != 4`, or if the computed `hdr_len()` is out of range (`< IPV4_HDR_LEN` or `> len`). `load_` is set to the bytes beyond the (possibly options-extended) header. |
| `hdr_size() const override` | Returns `hdr_.hdr_len()`, clamped to at least `IPV4_HDR_LEN`. |
| `hdr() override` | Returns `HdrIPv4*`. |
| `ethertype() const override` | Returns `ETH_TYPE_IPV4` (`0x0800`). |
| `dst() const override` | Returns `hdr_.dst_ip`. |
| `patch_checksum() override` | Computes the standard IPv4 header checksum (RFC 1071 one's-complement sum, via `utils::inet_checksum()`) over the header (with `checksum` field zeroed), covering exactly `hdr_len()` bytes to correctly account for any options. |
| `swap_hdr_byte_order(HdrIPv4&) const` | Internal helper — swaps `total_len`, `id`, `flags_frag`, `checksum` in place. |

## 6. Example

Crafting an IPv4 + TCP packet:

```cpp
proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP, 0, 1234, 0, 64);
proto::TCP   tcp(3345, 4444, 1000, 0, constants::TCP_FLAG_SYN, 65535);

ip4 / tcp;   // TCP's patch_checksum() runs here, using ip4 as underlayer_

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;   // IPv4's own patch_checksum() runs here

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Sending directly via `Interface::write(Packet&)` (source MAC and
destination MAC resolved automatically per
[`LYNX_SRC_MAC_POLICY` / `LYNX_DST_MAC_POLICY`](../API.md#43-confighpp--compile-time-configuration)):

```cpp
IPv4 ip;
__builtin_memcpy(ip.hdr()->dst_ip, dst, 4);
ip.hdr()->proto = constants::IP_PROTO_TCP;

TCP tcp;
tcp.hdr()->dst_port = 80;
tcp.hdr()->flags    = constants::TCP_FLAG_SYN;

ip / tcp;
iface.send(ip);
```

Dissecting a captured IPv4 packet:

```cpp
if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV4) {
    auto ip4 = eth->as<proto::IPv4>();
    if (ip4 && ip4->ok()) {
        switch (ip4->hdr()->proto) {
            case constants::IP_PROTO_TCP: { auto tcp = ip4->as<proto::TCP>(); break; }
            case constants::IP_PROTO_UDP: { auto udp = ip4->as<proto::UDP>(); break; }
            // ...
        }
    }
}
```

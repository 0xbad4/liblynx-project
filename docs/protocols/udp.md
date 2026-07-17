# Protocol: User Datagram Protocol (`UDP`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `UDP`](#5-class-udp)
- [6. Checksum Algorithm](#6-checksum-algorithm)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l4/udp/udp.hpp`,
  `include/lynx/protocols/l4/udp/hdrs.hpp`,
  `include/lynx/protocols/l4/udp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Segment`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 768 — User Datagram
  Protocol](https://www.rfc-editor.org/rfc/rfc768)

## 2. Overview

`UDP` implements the fixed 8-byte UDP header. As with `TCP`, it requires a
valid `underlayer_` (`IPv4` or `IPv6`) at checksum-computation time.
Unlike TCP's checksum, which is optional under some circumstances in
IPv4, `lynx` always computes and sets the UDP checksum, and forces a
computed value of exactly `0` to `0xFFFF` on the wire (since `0` is
reserved to mean "no checksum computed" in a UDP/IPv4 datagram).

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Length             |           Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrUDP` struct (packed, `include/lynx/protocols/l4/udp/hdrs.hpp`):

```cpp
LYNX_PACKED HdrUDP {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;        // header + payload length
    uint16_t checksum;      // optional in IPv4 / mandatory in IPv6 — auto-computed
};
```

All fields are stored in host byte order in `hdr_`, and swapped to/from
network byte order in `serialize()` / `dissect()`.

## 4. Constants

Defined in `include/lynx/protocols/l4/udp/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IP_PROTO_UDP` | `17` | IP protocol number for UDP. |
| `UDP_HDR_LEN` | `8` | Fixed header length. |

## 5. Class `UDP`

### Constructors

| Constructor | Description |
|---|---|
| `UDP()` | Default — zero-initialized header. There is no explicit-field constructor for `UDP`; set `hdr()->src_port`, `hdr()->dst_port`, etc. directly after construction. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (byte-order-swapped) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < UDP_HDR_LEN`. `load_` is set to the bytes beyond the fixed 8-byte header — note that, unlike `TCP`, `dissect()` does not independently validate `hdr_.length` against `len`; it always uses `hdr_size()` (`UDP_HDR_LEN`) directly to compute the payload offset. |
| `hdr_size() const override` | Returns `UDP_HDR_LEN` (`8`). |
| `hdr() override` | Returns `HdrUDP*`. |
| `patch_checksum() override` | Computes the UDP checksum over a pseudo-header + UDP header + payload — see [§6](#6-checksum-algorithm). |
| `proto() const` | Returns `IP_PROTO_UDP` (`17`). |
| `swap_hdr_byte_order(HdrUDP&) const` | Internal helper — swaps all four fields in place. |

## 6. Checksum Algorithm

`UDP::patch_checksum()` requires a valid `underlayer_`. If none is set, it
fails with `Status::MissingLayer`.

Behavior branches on `underlayer_->ethertype()`:

- **IPv4** (`ETH_TYPE_IPV4`): builds a 12-byte IPv4 pseudo-header
  (`src_ip(4) | dst_ip(4) | zero(1) | proto=17(1) | udp_len(2)`), followed
  by the UDP header (checksum field left as-is prior to computation,
  matching the wire copy semantics) and payload, computes
  `utils::inet_checksum()` over the concatenation, and remaps a result of
  `0` to `0xFFFF` (checksum is technically optional in IPv4, but `lynx`
  always computes it).
- **IPv6** (`ETH_TYPE_IPV6`): builds a 40-byte IPv6 pseudo-header
  (`src_ip(16) | dst_ip(16) | udp_len(4) | zero(3) | next_hdr=17(1)`),
  followed by the UDP header and payload, computes
  `utils::inet_checksum()` over the concatenation, and likewise remaps `0`
  to `0xFFFF` — for IPv6 the checksum is **mandatory**, per RFC 8200.
- **Any other underlayer**: fails with `Status::NotImplemented`. The
  source marks this branch with a `// HERE: add support for other
  protocols` comment, indicating this is an intentional extension point.

## 7. Example

Crafting a UDP packet:

```cpp
proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_UDP);
proto::UDP   udp;
udp.hdr()->src_port = htons(5353);
udp.hdr()->dst_port = htons(53);

ip4 / udp;

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured UDP datagram:

```cpp
if (ip4->hdr()->proto == constants::IP_PROTO_UDP) {
    auto udp = ip4->as<proto::UDP>();
    if (udp && udp->ok()) {
        auto payload = udp->load();
    }
}
```

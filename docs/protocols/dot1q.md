# Protocol: 802.1Q VLAN Tagging (`Dot1Q`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `Dot1Q`](#5-class-dot1q)
- [6. Example](#6-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l2/eth/dot1q.hpp`,
  `include/lynx/protocols/l2/eth/hdrs.hpp`,
  `include/lynx/protocols/l2/eth/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Frame`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- Standard: [IEEE 802.1Q](https://standards.ieee.org/ieee/802.1Q/6844/) —
  VLAN tagging is defined by an IEEE standard, not an IETF RFC.

## 2. Overview

`Dot1Q` implements an 802.1Q VLAN-tagged Ethernet frame header: the
standard Ethernet destination/source MAC pair, followed by a 4-byte VLAN
tag (`TPID` + `TCI`), followed by the inner ethertype identifying the
encapsulated payload.

Like `Ether`, `Dot1Q` carries no checksum — the FCS is appended by the NIC
and is not written by `serialize()`.

## 3. Wire Format

18-byte total header:

```
[ dst_mac(6) | src_mac(6) | tpid(2)=0x8100 | tci(2) | ethertype(2) ]
```

`TCI` (Tag Control Information, 2 bytes) breakdown:

```
 15  14  13  12  11 ......................... 0
+---+---+---+---+---------------------------+
|      PCP      |DEI|        VLAN ID          |
+---+---+---+---+---------------------------+
```

| Field | Bits | Description |
|---|---|---|
| `pcp` | `[15:13]` | Priority Code Point — 3-bit 802.1p QoS priority. |
| `dei` | `[12]` | Drop Eligible Indicator — 1 bit. |
| `vlan_id` | `[11:0]` | VLAN identifier, `0`–`4094`. |

`HdrDot1Q` struct (packed, `include/lynx/protocols/l2/eth/hdrs.hpp`):

```cpp
LYNX_PACKED HdrDot1Q {
    uint8_t   dst_mac[6];
    uint8_t   src_mac[6];
    uint16_t tpid;          // always 0x8100 — confirms this is a tag
    uint16_t tci;           // pcp(3b) | dei(1b) | vid(12b)

    [[nodiscard]] uint8_t  pcp()    const noexcept;
    [[nodiscard]] bool     dei()    const noexcept;
    [[nodiscard]] uint16_t vlan_id()const noexcept;

    static uint16_t make_tci(uint8_t pcp, bool dei, uint16_t vid) noexcept;

    uint16_t ethertype;     // inner payload protocol
};
```

`tpid`, `tci`, and `ethertype` are stored in host byte order in `hdr_`,
and are converted to/from network byte order in `serialize()` /
`dissect()` via the internal `swap_hdr_byte_order()` helper.

## 4. Constants

Defined in `include/lynx/protocols/l2/eth/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `ETH_TYPE_VLAN` | `0x8100` | TPID value confirming an 802.1Q tag is present. |
| `DOT1Q_HDR_LEN` | `18` | Total header length: `eth(14) + tpid(2) + tci(2)`. |
| `DOT1Q_TAG_LEN` | `4` | Length of just the inserted tag (`tpid` + `tci`). |

## 5. Class `Dot1Q`

### Constructors

| Constructor | Description |
|---|---|
| `Dot1Q()` | Default — zero-initialized header. |
| `explicit Dot1Q(const hdrs::HdrDot1Q& h)` | Constructs directly from a pre-populated `HdrDot1Q`. |
| `Dot1Q(const uint8_t dst[6], const uint8_t src[6], uint16_t tpid, uint16_t tci, uint16_t ethertype)` | Constructs from explicit field values. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (with `tpid`, `tci`, `ethertype` swapped to network byte order) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`, converting the multi-byte fields to host byte order, and sets `load_` to the remaining bytes. Sets `Status::MalformedPacket` if `len < sizeof(HdrDot1Q)` or if the parsed `tpid` is not `0x8100`. |
| `hdr_size() const override` | Returns `sizeof(HdrDot1Q)` (`18`). |
| `hdr() override` | Returns `HdrDot1Q*`. |
| `type() const override` | Returns `FrameType::Dot1Q`. |
| `swap_hdr_byte_order(HdrDot1Q&) const` | Internal helper — swaps `tpid`, `tci`, and `ethertype` in place. |

## 6. Example

Crafting a VLAN-tagged frame (VLAN ID `100`, priority `5`):

```cpp
uint16_t tci = lynx::hdrs::HdrDot1Q::make_tci(5, false, 100);

proto::Dot1Q dot1q(dst_mac, src_mac, constants::ETH_TYPE_VLAN, tci, constants::ETH_TYPE_IPV4);
proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
proto::TCP   tcp(8080, 80, 5000, 0, constants::TCP_FLAG_SYN | constants::TCP_FLAG_ACK, 32768);

ip4 / tcp;
dot1q / ip4;

if (dot1q.ok() && iface.ok())
    iface.write(dot1q);
```

Dissecting a captured VLAN-tagged frame:

```cpp
iface.capture([](const proto::RawFrame& raw) {
    if (raw.type() != proto::FrameType::Dot1Q)
        return io::RecvAction::Continue;

    auto dot1q = raw.as<proto::Dot1Q>();
    if (!dot1q || !dot1q->ok()) return io::RecvAction::Continue;

    std::cout << "VLAN ID: " << dot1q->hdr()->vlan_id() << "\n";

    if (dot1q->hdr()->ethertype == constants::ETH_TYPE_IPV4) {
        auto ip4 = dot1q->as<proto::IPv4>();
        // ...
    }
    return io::RecvAction::Continue;
});
```

# Protocol: Ethernet II (`Ether`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `Ether`](#5-class-ether)
- [6. `RawFrame`](#6-rawframe)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l2/eth/eth.hpp`,
  `include/lynx/protocols/l2/eth/hdrs.hpp`,
  `include/lynx/protocols/l2/eth/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Frame`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 894 — A Standard for the Transmission of IP Datagrams over
  Ethernet Networks](https://www.rfc-editor.org/rfc/rfc894) (Ethernet II
  framing as used by `lynx` is otherwise governed by the IEEE 802.3
  standard, which is not published as an IETF RFC)

## 2. Overview

`Ether` implements the standard Ethernet II frame header: a 14-byte header
consisting of the destination MAC, source MAC, and a 16-bit ethertype
field identifying the encapsulated payload protocol.

`Ether` carries no checksum of its own — the Frame Check Sequence (FCS) is
appended by the network interface card (NIC) on transmit and is not part
of the header `lynx` writes.

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Destination MAC (6 bytes)                +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Source MAC (6 bytes)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          EtherType (2 bytes)                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrEth` struct (packed, `include/lynx/protocols/l2/eth/hdrs.hpp`):

```cpp
LYNX_PACKED HdrEth {
    uint8_t  dst_mac[6];  // destination MAC address
    uint8_t  src_mac[6];  // source MAC address
    uint16_t ethertype;   // payload protocol (0x0800 IPv4 / 0x86DD IPv6 / 0x0806 ARP)
};
```

`ethertype` is stored in **host byte order** in `hdr_`; it is converted to
network byte order only in the wire copy produced during `serialize()`,
and converted back to host byte order immediately after `dissect()`.

## 4. Constants

Defined in `include/lynx/protocols/l2/eth/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `ETH_HDR_LEN` | `14` | Header length: `dst(6) + src(6) + type(2)`. |
| `ETH_MIN_LEN` | `60` | Minimum frame payload length, excluding FCS. |
| `ETH_MAX_LEN` | `1514` | Maximum standard frame length, excluding FCS. |
| `ETH_JUMBO_LEN` | `9014` | Maximum jumbo frame length, excluding FCS. |
| `ETH_TYPE_IPV4` | `0x0800` | Internet Protocol v4. |
| `ETH_TYPE_ARP` | `0x0806` | Address Resolution Protocol. |
| `ETH_TYPE_IPV6` | `0x86DD` | Internet Protocol v6. |
| `ETH_TYPE_VLAN` | `0x8100` | 802.1Q VLAN tag (`Dot1Q` TPID) — see [dot1q.md](dot1q.md). |
| `MAC_BROADCAST` | `ff:ff:ff:ff:ff:ff` | Broadcast MAC address. |
| `MAC_ZERO` | `00:00:00:00:00:00` | All-zeros sentinel, used for an unset/invalid MAC. |

## 5. Class `Ether`

### Constructors

| Constructor | Description |
|---|---|
| `Ether()` | Default — zero-initialized header. |
| `explicit Ether(const hdrs::HdrEth& h)` | Constructs directly from a pre-populated `HdrEth`. |
| `Ether(const uint8_t dst[6], const uint8_t src[6], uint16_t ethertype)` | Constructs from explicit destination MAC, source MAC, and ethertype. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (with `ethertype` swapped to network byte order) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`, converting `ethertype` to host byte order, and sets `load_` to the remaining bytes. Sets `Status::MalformedPacket` if `len < sizeof(HdrEth)`. |
| `hdr_size() const override` | Returns `sizeof(HdrEth)` (`14`). |
| `hdr() override` | Returns `HdrEth*`. |
| `type() const override` | Returns `FrameType::Eth`. |

## 6. `RawFrame`

Defined in `include/lynx/protocols/l2/frame.hpp`, namespace `lynx::proto`.

`RawFrame` is **not** a `Frame` or `ProtocolBaseObject` subclass — it is a
lightweight, pure byte carrier and type classifier, and it is the object
`Interface::capture()` passes to the caller's callback for every received
frame.

`RawFrame::dissect()` peeks at the ethertype field (offset 12) of the raw
bytes to classify the frame as `FrameType::Eth` or `FrameType::Dot1Q`,
without performing any further parsing. The underlying slab is wrapped
with a no-op deleter — the receive loop (or whatever caller owns the
slab) retains ownership of the memory for as long as it is alive.

| Member | Signature | Description |
|---|---|---|
| `dissect()` | `void dissect(const uint8_t* data, uint32_t len) noexcept` | Classifies the frame type by peeking at the ethertype field. Sets `Status::MalformedPacket` if `len < ETH_HDR_LEN`. |
| `type()` | `[[nodiscard]] FrameType type() const noexcept` | Returns the classified `FrameType`. |
| `as<T>()` | `template<typename T> [[nodiscard]] std::unique_ptr<T> as() const noexcept` | Allocates a `T` (which must derive from `Frame`) and dissects it, zero-copy, from the raw slab. Returns `nullptr` if the slab is empty. |
| `data()` | `[[nodiscard]] const uint8_t* data() const noexcept` | Direct pointer to the raw bytes, for logging or hex dumps. |
| `len()` | `[[nodiscard]] uint32_t len() const noexcept` | Length of the raw frame in bytes. |
| `bytes()` | `[[nodiscard]] const_view_t bytes() const noexcept` | Span view over the raw frame bytes. |

> **Implementation note:** the current classifier in `RawFrame::dissect()`
> only distinguishes plain Ethernet II from 802.1Q-tagged frames; the
> source comments this as a `TODO` for broader L2 frame classification
> (e.g. `Dot11`), noting that Wi-Fi monitor-mode frames would need to be
> distinguished by interface mode rather than by ethertype.

## 7. Example

Crafting an Ethernet frame carrying an IPv4/TCP payload:

```cpp
proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP, 0, 1234, 0, 64);
proto::TCP   tcp(3345, 4444, 1000, 0, constants::TCP_FLAG_SYN, 65535);

ip4 / tcp;
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured frame:

```cpp
iface.capture([](const proto::RawFrame& raw) {
    if (raw.type() != proto::FrameType::Eth)
        return io::RecvAction::Continue;

    auto eth = raw.as<proto::Ether>();
    if (!eth || !eth->ok()) return io::RecvAction::Continue;

    if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV4) {
        auto ip4 = eth->as<proto::IPv4>();
        // ...
    }
    return io::RecvAction::Continue;
});
```

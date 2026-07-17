# Protocol: Address Resolution Protocol (`ARP`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `ARP`](#5-class-arp)
- [6. Example](#6-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l3/arp/arp.hpp`,
  `include/lynx/protocols/l3/arp/hdrs.hpp`,
  `include/lynx/protocols/l3/arp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Packet`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 826 — An Ethernet Address Resolution
  Protocol](https://www.rfc-editor.org/rfc/rfc826)

## 2. Overview

`ARP` implements the Address Resolution Protocol as used to resolve an
IPv4 address to a MAC address over Ethernet. `lynx` currently supports
only the fixed Ethernet + IPv4 combination (`hlen == 6`, `plen == 4`);
`dissect()` explicitly rejects any other address-length combination.

ARP carries no checksum and no variable-length payload — it has a fixed
28-byte header and no `load_`. `ARP::set_load()` is overridden to be a
no-op that records `Status::NotImplemented`, and `ARP::as<T>()` always
returns `nullptr`, reflecting that ARP has no next layer.

`ARP::is_broadcast()` always returns `true` — `Interface` therefore always
sets the destination MAC to broadcast (`ff:ff:ff:ff:ff:ff`) when sending an
`ARP` packet directly through `Interface::write(Packet&)`, and `ARP::dst()`
always returns `nullptr` since ARP has no IPv4 destination to resolve via
ARP itself.

## 3. Wire Format

Fixed 28-byte header for Ethernet + IPv4:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Hardware Type (htype)|      Protocol Type (ptype)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Hw Addr Len  | Proto Addr Len|       Operation (oper)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Sender Hardware Address (sha, 6 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Sender Protocol Address (spa, 4 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Target Hardware Address (tha, 6 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Target Protocol Address (tpa, 4 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrARP` struct (packed, `include/lynx/protocols/l3/arp/hdrs.hpp`):

```cpp
LYNX_PACKED HdrARP {
    uint16_t htype;   // hardware type (0x0001 Ethernet)
    uint16_t ptype;   // protocol type (0x0800 IPv4)
    uint8_t  hlen;    // hardware address length (6 for MAC)
    uint8_t  plen;    // protocol address length (4 for IPv4)
    uint16_t oper;    // operation (1 request / 2 reply)
    uint8_t  sha[6];  // sender hardware address
    uint8_t  spa[4];  // sender protocol address
    uint8_t  tha[6];  // target hardware address
    uint8_t  tpa[4];  // target protocol address
};
```

`htype`, `ptype`, and `oper` are the only multi-byte fields; they are
stored in host byte order in `hdr_` and swapped to/from network byte order
in `serialize()` / `dissect()`. `hlen` and `plen` are single bytes and
require no swap.

## 4. Constants

Defined in `include/lynx/protocols/l3/arp/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `ARP_HRD_ETHER` | `0x0001` | Hardware address space: Ethernet. |
| `ARP_PRO_IPV4` | `0x0800` | Protocol address space: IPv4 (same value as `ETH_TYPE_IPV4`). |
| `ARP_OP_REQUEST` | `1` | Operation: "who has `<ip>`? tell `<src>`". |
| `ARP_OP_REPLY` | `2` | Operation: "`<ip>` is at `<mac>`". |
| `ARP_HLEN_ETH` | `6` | Fixed MAC address length. |
| `ARP_PLEN_IPV4` | `4` | Fixed IPv4 address length. |
| `ARP_DEFAULT_OP` | `ARP_OP_REQUEST` | Default operation. |
| `ARP_HDR_LEN` | `28` | Fixed header length for Ethernet + IPv4. |

## 5. Class `ARP`

### Constructors

| Constructor | Description |
|---|---|
| `ARP()` | Default — populates `htype = ARP_HRD_ETHER`, `ptype = ETH_TYPE_IPV4`, `hlen = ARP_HLEN_ETH`, `plen = ARP_PLEN_IPV4`, `oper = ARP_OP_REQUEST`. |
| `explicit ARP(const hdrs::HdrARP& h)` | Constructs directly from a pre-populated `HdrARP`. |
| `ARP(uint16_t hrd, uint16_t pro, uint8_t hln, uint8_t pln, uint16_t op, const uint8_t sha[6], const uint8_t spa[4], const uint8_t tha[6], const uint8_t tpa[4])` | Constructs from all fields explicitly. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header, with `htype`/`ptype`/`oper` swapped to network byte order. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`, swapping multi-byte fields to host byte order. Sets `Status::MalformedPacket` if `len < ARP_HDR_LEN` or if `hlen`/`plen` do not match the fixed Ethernet+IPv4 values. |
| `hdr_size() const override` | Returns `ARP_HDR_LEN` (`28`). |
| `hdr() override` | Returns `HdrARP*`. |
| `ethertype() const override` | Returns `ETH_TYPE_ARP` (`0x0806`). |
| `dst() const override` | Always returns `nullptr` — ARP has no separate routable destination for MAC resolution purposes. |
| `is_broadcast() const` | Always returns `true`. |
| `as<T>() const` | Always returns `nullptr` — ARP has no next layer. |
| `set_load(const_view_t)` | Overridden to be a no-op; sets `Status::NotImplemented` — ARP has no payload. |
| `swap_hdr_byte_order(HdrARP&) const` | Internal helper — swaps `htype`, `ptype`, `oper` in place. |

## 6. Example

Crafting an ARP request ("who has `192.168.1.1`? tell `192.168.1.100`"):

```cpp
proto::Ether eth(dst_mac /* broadcast */, src_mac, constants::ETH_TYPE_ARP);
proto::ARP   arp(
    constants::ARP_HRD_ETHER,
    constants::ARP_PRO_IPV4,
    6, 4,
    constants::ARP_OP_REQUEST,
    src_mac,     // sender hardware address
    sender_ip,   // sender protocol address
    zero_mac,    // target hardware address (unknown)
    target_ip    // target protocol address
);

eth / arp;
if (eth.ok() && iface.ok())
    iface.write(eth);
```

Crafting an ARP reply:

```cpp
proto::Ether eth(target_mac, src_mac, constants::ETH_TYPE_ARP);
proto::ARP   arp(
    constants::ARP_HRD_ETHER, constants::ARP_PRO_IPV4, 6, 4,
    constants::ARP_OP_REPLY,
    src_mac, sender_ip,
    target_mac, target_ip
);

eth / arp;
if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured ARP frame:

```cpp
if (eth->hdr()->ethertype == constants::ETH_TYPE_ARP) {
    auto arp = eth->as<proto::ARP>();
    if (arp && arp->ok()) {
        // arp->hdr()->oper, sha, spa, tha, tpa ...
    }
}
```

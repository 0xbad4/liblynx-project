# Protocol: Internet Control Message Protocol (`ICMP`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `ICMP`](#5-class-icmp)
- [6. Checksum Algorithm](#6-checksum-algorithm)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l4/icmp/icmp.hpp`,
  `include/lynx/protocols/l4/icmp/hdrs.hpp`,
  `include/lynx/protocols/l4/icmp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Segment`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 792 — Internet Control Message
  Protocol](https://www.rfc-editor.org/rfc/rfc792)

## 2. Overview

`ICMP` implements the IPv4 ICMP header, shared between all ICMP message
types (Echo Request/Reply, Destination Unreachable, Time Exceeded, etc.).
The 4-byte "rest of header" field is interpreted generically as an
identifier + sequence number pair (valid for Echo messages) via the
`id()` / `seq()` accessors, and is otherwise left to the caller to
interpret according to the message `type`.

Unlike `TCP`/`UDP`, `ICMP`'s checksum covers only the header and the
`load_` payload — it does **not** use an IP pseudo-header, and therefore
`ICMP::patch_checksum()` does not require an `underlayer_` to be set.

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Rest of Header (varies by Type)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrICMP` struct (packed, `include/lynx/protocols/l4/icmp/hdrs.hpp`) —
shared verbatim between `ICMP` and `ICMPv6`:

```cpp
LYNX_PACKED HdrICMP {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;      // host byte order — bswapped in serialize() / dissect()

    [[nodiscard]] uint16_t id()  const noexcept;  // high 16 bits of rest
    [[nodiscard]] uint16_t seq() const noexcept;  // low 16 bits of rest
    void set_id_seq(uint16_t id, uint16_t seq) noexcept;
};
```

`checksum` and `rest` are stored in host byte order in `hdr_`, and swapped
to/from network byte order in `serialize()` / `dissect()`.

## 4. Constants

Defined in `include/lynx/protocols/l4/icmp/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IP_PROTO_ICMP` | `1` | IP protocol number for ICMP (IPv4). |
| `ICMP_HDR_LEN` | `8` | Fixed header length: `type(1)+code(1)+chk(2)+rest(4)`. |
| `ICMP_ECHO_REPLY` | `0` | Echo Reply. |
| `ICMP_DST_UNREACH` | `3` | Destination Unreachable. |
| `ICMP_REDIRECT` | `5` | Redirect. |
| `ICMP_ECHO_REQUEST` | `8` | Echo Request. |
| `ICMP_TIME_EXCEED` | `11` | Time Exceeded. |
| `ICMP_UNREACH_NET` | `0` | Destination Unreachable code: net unreachable. |
| `ICMP_UNREACH_HOST` | `1` | Destination Unreachable code: host unreachable. |
| `ICMP_UNREACH_PROTO` | `2` | Destination Unreachable code: protocol unreachable. |
| `ICMP_UNREACH_PORT` | `3` | Destination Unreachable code: port unreachable. |
| `ICMP_UNREACH_NEEDFRAG` | `4` | Destination Unreachable code: fragmentation needed (path MTU discovery). |
| `ICMP_TIMEX_TTL` | `0` | Time Exceeded code: TTL expired in transit. |
| `ICMP_TIMEX_FRAG` | `1` | Time Exceeded code: fragment reassembly timeout. |

See [icmpv6.md § Constants](icmpv6.md#4-constants) for the ICMPv6-specific
type values, which are also defined in this same constants file.

## 5. Class `ICMP`

### Constructors

| Constructor | Description |
|---|---|
| `ICMP()` | Default — zero-initialized header. |
| `ICMP(uint8_t type, uint8_t code, uint16_t id = 0, uint16_t seq = 0)` | Constructs with `type`, `code`, `checksum = 0`, and `rest` packed from `id`/`seq` via `set_id_seq()`. Convenient for Echo Request/Reply; for other message types, `id`/`seq` may be left at `0` and `rest` reinterpreted by the caller as needed for that message type. |
| `explicit ICMP(const hdrs::HdrICMP& h)` | Constructs directly from a pre-populated `HdrICMP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (byte-order-swapped) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < ICMP_HDR_LEN`. `load_` is set to the bytes beyond the fixed 8-byte header. |
| `hdr_size() const override` | Returns `ICMP_HDR_LEN` (`8`). |
| `hdr() override` | Returns `HdrICMP*`. |
| `patch_checksum() override` | Computes the checksum over the header + `load_` — see [§6](#6-checksum-algorithm). |
| `proto() const` | Returns `IP_PROTO_ICMP` (`1`). |
| `swap_hdr_byte_order(HdrICMP&) const` | Internal helper — swaps `rest` and `checksum` in place. |

## 6. Checksum Algorithm

`ICMP::patch_checksum()` requires **no underlayer** — unlike TCP/UDP,
ICMP's checksum covers only its own header and payload, with no IP
pseudo-header:

1. Build a byte-order-swapped wire copy of the header with `checksum`
   zeroed.
2. Concatenate the wire header with `load_` into a stack buffer.
3. Compute `utils::inet_checksum()` over the concatenation and store the
   result into `hdr_.checksum`.

## 7. Example

Crafting an ICMP Echo Request (ping):

```cpp
proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_ICMP);
proto::ICMP  icmp(constants::ICMP_ECHO_REQUEST, 0, 1234, 1);  // id=1234, seq=1

ip4 / icmp;

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Crafting an ICMP Destination Unreachable (host unreachable):

```cpp
proto::ICMP icmp(constants::ICMP_DST_UNREACH, constants::ICMP_UNREACH_HOST, 0, 0);
ip4 / icmp;
```

Dissecting a captured ICMP message:

```cpp
if (ip4->hdr()->proto == constants::IP_PROTO_ICMP) {
    auto icmp = ip4->as<proto::ICMP>();
    if (icmp && icmp->ok()) {
        switch (icmp->hdr()->type) {
            case constants::ICMP_ECHO_REQUEST:
                std::cout << "Echo Request id=" << icmp->hdr()->id()
                          << " seq=" << icmp->hdr()->seq() << "\n";
                break;
            case constants::ICMP_ECHO_REPLY: /* ... */ break;
        }
    }
}
```

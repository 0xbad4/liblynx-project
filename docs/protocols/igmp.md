# Protocol: Internet Group Management Protocol (`IGMP`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `IGMP`](#5-class-igmp)
- [6. Checksum Algorithm](#6-checksum-algorithm)
- [7. Known Implementation Issues](#7-known-implementation-issues)
- [8. Example](#8-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l4/igmp/igmp.hpp`,
  `include/lynx/protocols/l4/igmp/hdrs.hpp`,
  `include/lynx/protocols/l4/igmp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header struct),
  `lynx::constants` (constants)
- Base class: [`Segment`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 2236 — Internet Group Management Protocol, Version
  2](https://www.rfc-editor.org/rfc/rfc2236) (the type values supported
  cover IGMPv1, IGMPv2, and the IGMPv3 report code point defined in
  [RFC 3376](https://www.rfc-editor.org/rfc/rfc3376))

## 2. Overview

`IGMP` implements the base 8-byte IGMPv1/v2-style header used for
multicast group membership queries, reports, and leave messages. It rides
directly over IPv4 (`proto = 2`). Its checksum covers the header and
payload only, with no pseudo-header — similar to `ICMP`.

## 3. Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      | Max Resp Time |           Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Group Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`HdrIGMP` struct (packed, `include/lynx/protocols/l4/igmp/hdrs.hpp`):

```cpp
// rides over IPv4 (protocol=2). used for multicast group management
LYNX_PACKED HdrIGMP {
    uint8_t  type;          // 0x11 query / 0x16 v2 report / 0x17 leave / 0x22 v3 report
    uint8_t  max_resp;      // max response time (queries only, 0 otherwise)
    uint16_t checksum;      // standard internet checksum — auto-computed
    uint8_t  group_addr[4]; // multicast group (0.0.0.0 for general query)
};
```

`checksum` is the only multi-byte field and is stored in host byte order
in `hdr_`, swapped to/from network byte order in `serialize()` /
`dissect()`.

## 4. Constants

Defined in `include/lynx/protocols/l4/igmp/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IGMP_HDR_LEN` | `8` | Fixed header length: `type(1)+resp(1)+chk(2)+grp(4)`. |
| `IGMP_QUERY` | `0x11` | Membership query (v1/v2/v3). |
| `IGMP_V2_REPORT` | `0x16` | IGMPv2 membership report. |
| `IGMP_V2_LEAVE` | `0x17` | IGMPv2 leave group. |
| `IGMP_V3_REPORT` | `0x22` | IGMPv3 membership report. |

## 5. Class `IGMP`

### Constructors

| Constructor | Description |
|---|---|
| `IGMP()` | Default — zero-initialized header. |
| `IGMP(uint8_t type, uint8_t maxr, const uint8_t gaddr[4])` | Constructs with `type`, intended max-response time `maxr`, `checksum = 0`, and `group_addr` copied from `gaddr`. **See [§7](#7-known-implementation-issues) — the `maxr` parameter is not currently stored into `max_resp`.** |
| `explicit IGMP(const hdrs::HdrIGMP& h)` | Constructs directly from a pre-populated `HdrIGMP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (with `checksum` swapped to network byte order) followed by `load_`, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`, converting `checksum` to host byte order. Sets `Status::MalformedPacket` if `len < IGMP_HDR_LEN` or if `hdr_size()` is out of range. `load_` is set to the bytes beyond the fixed 8-byte header. |
| `hdr_size() const override` | Returns `IGMP_HDR_LEN` (`8`). |
| `hdr() override` | Returns `HdrIGMP*`. |
| `patch_checksum() override` | Computes the checksum over the header + `load_` (no pseudo-header) — see [§6](#6-checksum-algorithm). |
| `proto() const` | Returns `constants::IP_PROTO_IGMP`. **See [§7](#7-known-implementation-issues) — this constant is referenced but not defined anywhere in the current codebase.** |

## 6. Checksum Algorithm

`IGMP::patch_checksum()` requires no underlayer:

1. Zero `hdr_.checksum`.
2. Concatenate the header with `load_` into a stack buffer.
3. Compute `utils::inet_checksum()` over the concatenation and store the
   result into `hdr_.checksum`.

## 7. Known Implementation Issues

These are documented here, without modification, per the requirement to
omit nothing from the current state of the codebase:

- **`constants::IP_PROTO_IGMP` is undefined.** `IGMP::proto()` and both
  bundled examples (`src/examples/craft.cpp`, `src/examples/capture.cpp`)
  reference `constants::IP_PROTO_IGMP`, but no `const.hpp` file in the
  repository defines this symbol (compare with `IP_PROTO_TCP` in
  `l4/tcp/const.hpp`, `IP_PROTO_UDP` in `l4/udp/const.hpp`,
  `IP_PROTO_ICMP` in `l4/icmp/const.hpp`, all of which are defined
  alongside their respective protocol). The conventional value, per
  IANA's protocol numbers registry, would be `2`. Any translation unit
  that references `constants::IP_PROTO_IGMP` without separately defining
  it will fail to compile.
- **The `IGMP(uint8_t type, uint8_t maxr, const uint8_t gaddr[4])`
  constructor does not store `maxr`.** Its body reads:
  ```cpp
  IGMP(uint8_t type, uint8_t maxr, const uint8_t gaddr[4]) {
      hdr_.type = type;
      hdr_.type = maxr;   // duplicate assignment — likely intended: hdr_.max_resp = maxr;
      hdr_.checksum = 0;
      std::memcpy(hdr_.group_addr, gaddr, 4);
  }
  ```
  The second assignment overwrites `hdr_.type` with `maxr` a second time
  rather than assigning to `hdr_.max_resp`, so `max_resp` is left at its
  default-initialized value and `type` ends up holding whatever value was
  passed as `maxr`. Callers who need a specific `max_resp` value on a
  query message should set `hdr()->max_resp` directly after construction
  as a workaround.

## 8. Example

Crafting an IGMPv2 Membership Report:

```cpp
proto::IPv4 ip4(src_ip, dst_ip, /* IP_PROTO_IGMP, see §7 */ 2);
proto::IGMP igmp(constants::IGMP_V2_REPORT, 0, group_addr);
igmp.hdr()->type = constants::IGMP_V2_REPORT;  // work around the constructor issue in §7

ip4 / igmp;

proto::Ether eth(dst_mac /* IGMP multicast MAC */, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured IGMP message:

```cpp
if (ip4->hdr()->proto == 2 /* IGMP, see §7 */) {
    auto igmp = ip4->as<proto::IGMP>();
    if (igmp && igmp->ok()) {
        switch (igmp->hdr()->type) {
            case constants::IGMP_QUERY:     /* ... */ break;
            case constants::IGMP_V2_REPORT: /* ... */ break;
            case constants::IGMP_V2_LEAVE:  /* ... */ break;
            case constants::IGMP_V3_REPORT: /* ... */ break;
        }
    }
}
```

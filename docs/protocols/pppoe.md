# Protocol: PPP over Ethernet (`PPPoE`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `PPPoE`](#5-class-pppoe)
- [6. Discovery TLV Tags](#6-discovery-tlv-tags)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l2/pppoe/pppoe.hpp`,
  `include/lynx/protocols/l2/pppoe/hdrs.hpp`,
  `include/lynx/protocols/l2/pppoe/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header structs),
  `lynx::constants` (constants)
- Base class: [`Frame`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 2516 — A Method for Transmitting PPP Over
  Ethernet](https://www.rfc-editor.org/rfc/rfc2516)

> **Provisional support.** Per the project [CHANGELOG](../README.md#6-changelog),
> PPPoE has not been extensively tested in this release and is provided
> as-is.

## 2. Overview

`PPPoE` implements the PPPoE header, used to tunnel PPP frames (see
[ppp.md](ppp.md)) over an Ethernet segment — the mechanism typically used
by DSL and fiber ISPs to authenticate and establish sessions over what is
physically an Ethernet or Ethernet-like access network.

PPPoE frames come in two families, distinguished by `code`:

- **Discovery** frames (`PADI`, `PADO`, `PADR`, `PADS`, `PADT`) — used to
  discover an Access Concentrator and establish a session, carrying
  TLV-encoded tags as payload.
- **Session** frames (`code = PPPOE_CODE_SESSION`) — carry an
  encapsulated PPP frame as payload, once a session has been established.

`PPPoE` carries no checksum of its own.

## 3. Wire Format

6-byte header, sitting directly after the Ethernet header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VER  | TYPE  |     Code      |          Session ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length            |     Payload (PPP or TLV tags)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```cpp
LYNX_PACKED HdrPPPoE {
    uint8_t  ver_type;      // PPPOE_VER_TYPE — always 0x11
    uint8_t  code;          // PPPOE_CODE_*
    uint16_t session_id;    // 0x0000 during discovery, assigned by server in PADS
    uint16_t length;        // payload length — computed in serialize()

    [[nodiscard]] uint8_t version() const noexcept;   // (ver_type >> 4) & 0x0F
    [[nodiscard]] uint8_t type()    const noexcept;   //  ver_type       & 0x0F
    [[nodiscard]] bool is_session()   const noexcept; // code == PPPOE_CODE_SESSION
    [[nodiscard]] bool is_discovery() const noexcept; // code != PPPOE_CODE_SESSION
};
```

`session_id` and `length` are stored in host byte order in `hdr_`, and
swapped to/from network byte order in `serialize()` / `dissect()`.
`length` reflects only the payload size, not the total frame size — it
does not include the 6-byte `HdrPPPoE` itself. It is computed
automatically at serialize time from `load_.size()` and should not be
set manually.

### Discovery TLV Tags

```
[ TYPE:2 | LENGTH:2 (excludes this header) | VALUE:LENGTH ]
```

```cpp
LYNX_PACKED PPPoETag {
    uint16_t     type   = 0;
    uint16_t     length = 0;
    const_view_t value{};
};
```

Multiple tags are packed back to back within the discovery frame's
payload; walk them by advancing past `sizeof(HdrPPPoETag) + length` bytes
per tag until the payload ends. Unlike `HdrBaseTLV`
(used by PPP LCP/IPCP/IPv6CP options — see [ppp.md](ppp.md)), `length` in
a PPPoE tag does **not** include the 4-byte tag header itself.

## 4. Constants

Defined in `include/lynx/protocols/l2/pppoe/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `PPPOE_ETHERTYPE_DISC` | `0x8863` | Ethertype for discovery frames. |
| `PPPOE_ETHERTYPE_SESSION` | `0x8864` | Ethertype for session frames. |
| `PPPOE_VER_TYPE` | `0x11` | Fixed value — version=1 (high nibble), type=1 (low nibble). |
| `PPPOE_CODE_SESSION` | `0x00` | Session data. |
| `PPPOE_CODE_PADI` | `0x09` | PPPoE Active Discovery Initiation. |
| `PPPOE_CODE_PADO` | `0x07` | PPPoE Active Discovery Offer. |
| `PPPOE_CODE_PADR` | `0x19` | PPPoE Active Discovery Request. |
| `PPPOE_CODE_PADS` | `0x65` | PPPoE Active Discovery Session-confirmation. |
| `PPPOE_CODE_PADT` | `0xA7` | PPPoE Active Discovery Terminate. |
| `PPPOE_TAG_EOL` | `0x0000` | End-Of-List. |
| `PPPOE_TAG_SVC_NAME` | `0x0101` | Service-Name. |
| `PPPOE_TAG_AC_NAME` | `0x0102` | AC-Name (Access Concentrator name). |
| `PPPOE_TAG_HOST_UNIQ` | `0x0103` | Host-Uniq (arbitrary caller-chosen bytes echoed back by the AC). |
| `PPPOE_TAG_AC_COOKIE` | `0x0104` | AC-Cookie (replay protection). |
| `PPPOE_TAG_VENDOR` | `0x0105` | Vendor-Specific. |
| `PPPOE_TAG_SVC_ERR` | `0x0201` | Service-Name-Error. |
| `PPPOE_TAG_AC_ERR` | `0x0202` | AC-System-Error. |
| `PPPOE_TAG_GENERIC_ERR` | `0x0203` | Generic-Error. |
| `PPPOE_HDR_LEN` | `6` | Fixed header length: `ver_type(1)+code(1)+session_id(2)+length(2)`. |

> **Implementation note:** `include/lynx/protocols/l2/pppoe/hdrs.hpp`
> contains `#include "const.hpp` — the closing double-quote on this
> `#include` directive is missing in the current source. Depending on
> the preprocessor/compiler, this may still be accepted (some compilers
> tolerate an unterminated string in this position by treating the
> trailing newline as an implicit terminator with a warning) or may
> produce a hard compilation error. This is noted here for completeness,
> without modification, per the requirement to omit nothing from the
> current state of the codebase.

## 5. Class `PPPoE`

### Constructors

| Constructor | Description |
|---|---|
| `PPPoE()` | Default — `ver_type = PPPOE_VER_TYPE`, `code = PPPOE_CODE_SESSION`, `session_id = 0x0000`, `length = 0` (computed in `serialize()`). |
| `explicit PPPoE(const hdrs::HdrPPPoE& h)` | Constructs directly from a pre-populated `HdrPPPoE`. |
| `PPPoE(uint8_t code, uint16_t session_id)` | Constructs with explicit `code`/`session_id`; `ver_type = PPPOE_VER_TYPE`, `length = 0`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (`session_id` and `length` swapped to network byte order; `length` computed from `load_.size()`) followed by `load_`. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`, converting `session_id`/`length` to host byte order. Sets `Status::MalformedPacket` if `len < PPPOE_HDR_LEN` or if `version() != 1` or `type() != 1`. Sets `Status::TruncatedPayload` if the declared `length` exceeds the remaining bytes. `load_` is clamped to `hdr_.length` bytes — the declared payload size. |
| `hdr_size() const override` | Returns `PPPOE_HDR_LEN` (`6`). |
| `hdr() override` | Returns `HdrPPPoE*`. |
| `ethertype() const` | Returns `PPPOE_ETHERTYPE_SESSION` if `is_session()`, else `PPPOE_ETHERTYPE_DISC`. |
| `patch_checksum() override` | No-op — PPPoE carries no checksum field. |
| `type() const override` | Returns `FrameType::PPPoE`. |
| `is_session()` / `is_discovery()` | Test `hdr_.code`. |
| `tlv_reset()` | Resets the internal tag cursor (`tlv_pos_ = 0`). |
| `tlv_next()` | See [§6](#6-discovery-tlv-tags). |
| `tlv_add(type, value, value_size)` | See [§6](#6-discovery-tlv-tags). |

## 6. Discovery TLV Tags

Tag walking and appending is only meaningful on discovery frames
(`PADI`/`PADO`/`PADR`/`PADS`/`PADT`) — both `tlv_next()` and `tlv_add()`
are no-ops (returning an empty tag, or `false`, respectively) when called
on a session frame.

### Reading Tags

```cpp
pppoe.tlv_reset();
while (true) {
    auto tag = pppoe.tlv_next();
    if (tag.value.empty() && tag.length == 0 && tag.type == 0) break;

    switch (tag.type) {
        case constants::PPPOE_TAG_SVC_NAME: /* tag.value is the service name string */ break;
        case constants::PPPOE_TAG_AC_NAME:  /* tag.value is the AC name string */ break;
    }
}
```

`tlv_next()` returns an empty `PPPoETag{}` and stops advancing if the
next tag's 4-byte header would exceed `load_`, or if the declared
`length` would extend past the end of `load_`.

### Writing Tags

`tlv_add(type, value, value_size)` appends one TLV tag to `load_`,
following the same ownership model as
[`base_add_option()`](ppp.md#option-ownership) (a fresh, owned `Buffer`
is allocated and existing bytes copied forward whenever the current
buffer is unowned or lacks capacity — borrowed capture-slab bytes are
never modified in place):

```cpp
PPPoE padi(constants::PPPOE_CODE_PADI, 0x0000);
const uint8_t svc_name[] = "internet";
padi.tlv_add(constants::PPPOE_TAG_SVC_NAME, svc_name, sizeof(svc_name) - 1);
```

## 7. Example

Crafting a PADI (discovery initiation) frame:

```cpp
proto::Ether eth(dst_mac /* broadcast */, src_mac, constants::PPPOE_ETHERTYPE_DISC);
proto::PPPoE padi(constants::PPPOE_CODE_PADI, 0x0000);

const uint8_t svc_name[] = "";  // empty = any service
padi.tlv_add(constants::PPPOE_TAG_SVC_NAME, svc_name, 0);

eth / padi;
if (eth.ok() && iface.ok())
    iface.write(eth);
```

Crafting and sending a PPP frame over an established PPPoE session:

```cpp
proto::Ether eth(dst_mac, src_mac, constants::PPPOE_ETHERTYPE_SESSION);
proto::PPPoE pppoe(constants::PPPOE_CODE_SESSION, session_id);
proto::PPP   ppp;
ppp.hdr()->protocol = constants::PPP_PROTO_IP;

ppp / ip4;
pppoe / ppp;
eth / pppoe;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Dissecting a captured PPPoE frame:

```cpp
if (eth->hdr()->ethertype == constants::PPPOE_ETHERTYPE_SESSION ||
    eth->hdr()->ethertype == constants::PPPOE_ETHERTYPE_DISC) {

    auto pppoe = eth->as<proto::PPPoE>();
    if (pppoe && pppoe->ok()) {
        if (pppoe->is_session()) {
            auto ppp = pppoe->as<proto::PPP>();
            // ppp->hdr()->is_ipv4(), is_lcp(), etc.
        } else {
            pppoe->tlv_reset();
            auto tag = pppoe->tlv_next();
            // discovery TLV tags
        }
    }
}
```

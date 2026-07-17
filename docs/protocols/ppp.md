# Protocol: Point-to-Point Protocol (`PPP`) and Subprotocols

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. PPP — Point-to-Point Protocol](#3-ppp--point-to-point-protocol)
- [4. LCP / NCP Common Header](#4-lcp--ncp-common-header)
- [5. LCP — Link Control Protocol](#5-lcp--link-control-protocol)
- [6. PAP — Password Authentication Protocol](#6-pap--password-authentication-protocol)
- [7. CHAP — Challenge Handshake Authentication Protocol](#7-chap--challenge-handshake-authentication-protocol)
- [8. IPCP — IP Control Protocol](#8-ipcp--ip-control-protocol)
- [9. IPv6CP — IPv6 Control Protocol](#9-ipv6cp--ipv6-control-protocol)
- [10. Constants](#10-constants)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l2/ppp/ppp.hpp`,
  `include/lynx/protocols/l2/ppp/hdrs.hpp`,
  `include/lynx/protocols/l2/ppp/const.hpp`,
  `include/lynx/protocols/l2/ppp/tlv_base.hpp`,
  `include/lynx/protocols/l2/ppp/lcp/lcp.hpp`,
  `include/lynx/protocols/l2/ppp/lcp/pap.hpp`,
  `include/lynx/protocols/l2/ppp/lcp/chap.hpp`,
  `include/lynx/protocols/l2/ppp/ncp/ipcp.hpp`,
  `include/lynx/protocols/l2/ppp/ncp/ipv6cp.hpp`
- Namespace: `lynx::proto` (classes), `lynx::hdrs` (header structs),
  `lynx::constants` (constants)
- RFCs:
  - PPP: [RFC 1661 — The Point-to-Point
    Protocol](https://www.rfc-editor.org/rfc/rfc1661)
  - LCP: [RFC 1661 §4](https://www.rfc-editor.org/rfc/rfc1661)
  - PAP: [RFC 1334 — PPP Authentication
    Protocols](https://www.rfc-editor.org/rfc/rfc1334)
  - CHAP: [RFC 1994 — PPP Challenge Handshake Authentication Protocol
    (CHAP)](https://www.rfc-editor.org/rfc/rfc1994)
  - IPCP: [RFC 1332 — The PPP Internet Protocol Control Protocol
    (IPCP)](https://www.rfc-editor.org/rfc/rfc1332)
  - IPv6CP: [RFC 5072 — IP Version 6 over PPP](https://www.rfc-editor.org/rfc/rfc5072)

> **Provisional support.** Per the project [CHANGELOG](../README.md#6-changelog),
> PPP and its subprotocols have not been extensively tested in this
> release and are provided as-is.

## 2. Overview

PPP is a data-link-layer (L2) protocol used to establish direct
connections between two nodes — typically over serial, dial-up, or
tunneled links such as PPPoE (see [pppoe.md](pppoe.md)). `lynx` models PPP
as a thin 4-byte framing header (`PPP`) carrying one of several
subprotocols selected by its `protocol` field:

| PPP `protocol` value | Subprotocol | Class |
|---|---|---|
| `0x0021` | IPv4 payload | dissect as `IPv4` directly |
| `0x0057` | IPv6 payload | dissect as `IPv6` directly |
| `0xC021` | Link Control Protocol | `LCP` |
| `0xC023` | Password Authentication Protocol | `PAP` |
| `0xC223` | Challenge Handshake Authentication Protocol | `CHAP` |
| `0x8021` | IP Control Protocol (NCP) | `IPCP` |
| `0x8057` | IPv6 Control Protocol (NCP) | `IPv6CP` |

`LCP`, `IPCP`, and `IPv6CP` all share an identical 4-byte header layout
(`code`, `id`, `length`) and TLV-encoded option format, implemented once
in the shared `TLVProtocolBaseClass` (`tlv_base.hpp`) and inherited by all
three via multiple inheritance alongside `ProtocolBaseObject`.

None of the classes documented in this file compute or carry a checksum
— PPP's Frame Check Sequence (FCS) is handled at the serial/modem
transport level, outside anything `lynx` writes.

## 3. PPP — Point-to-Point Protocol

Base class: [`Frame`](../API.md#common-base-classes) →
[`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)

### Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Address    |    Control    |            Protocol           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```cpp
LYNX_PACKED HdrPPP {
    uint8_t address;   // always 0xFF (all-stations) on standard point-to-point links
    uint8_t control;   // always 0x03 (unnumbered information)
    uint16_t protocol; // PPP_PROTO_* — identifies the encapsulated payload

    [[nodiscard]] bool is_ipv4()    const noexcept;
    [[nodiscard]] bool is_ipv6()    const noexcept;
    [[nodiscard]] bool is_lcp()     const noexcept;
    [[nodiscard]] bool is_ipcp()    const noexcept;
    [[nodiscard]] bool is_ipv6cp()  const noexcept;
    [[nodiscard]] bool is_pap()     const noexcept;
    [[nodiscard]] bool is_chap()    const noexcept;
    [[nodiscard]] bool is_ccp()     const noexcept;
};
```

`protocol` is stored in host byte order in `hdr_`, and swapped to/from
network byte order in `serialize()` / `dissect()`.

### Header Compression (ACFC / PFC)

LCP negotiation may compress the PPP header:

| Form | Length | Condition |
|---|---|---|
| Full (uncompressed) | 4 bytes | `address(1) + control(1) + protocol(2)` |
| ACFC (Address/Control Field Compression) | 2 bytes | address + control stripped |
| PFC (Protocol Field Compression) | 3 bytes | protocol's high byte dropped when it is `0x00` |
| Both active | 1 byte | both compressions applied |

`PPP::dissect()` detects ACFC by inspecting `data[0]`: if it equals
`PPP_ADDRESS` (`0xFF`), the full header is present; otherwise, the
address/control bytes are assumed absent and `data[0]` is treated as the
high byte of a (possibly PFC-compressed) protocol field. **PFC detection
is not separately implemented** — `dissect()`'s ACFC branch always reads
a full 2-byte protocol field via `PPP_HDR_LEN_ACFC` (`2` bytes); a
frame with *both* ACFC and PFC active (1-byte total header) is not
correctly handled by the current implementation.

### Constructors

| Constructor | Description |
|---|---|
| `PPP()` | Default — `address = PPP_ADDRESS`, `control = PPP_CONTROL`, `protocol = PPP_PROTO_IP` (caller overrides before chaining if a different payload is intended). |
| `explicit PPP(const hdrs::HdrPPP& h)` | Constructs directly from a pre-populated `HdrPPP`. |
| `PPP(uint8_t address, uint8_t control, uint16_t protocol)` | Constructs from explicit field values. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the full 4-byte header (protocol swapped to network byte order) followed by `load_`. Always emits the uncompressed form — `lynx` does not currently craft ACFC/PFC-compressed frames. |
| `dissect(const uint8_t* data, uint32_t len) override` | See [Header Compression](#header-compression-acfc--pfc) above. Sets `Status::MalformedPacket` if `len < PPP_HDR_LEN_MIN` (`1`), or if the detected form's minimum length is not met. |
| `hdr_size() const override` | Returns `sizeof(HdrPPP)` (`4`) — the uncompressed size, regardless of the form actually parsed by `dissect()`. |
| `hdr() override` | Returns `HdrPPP*`. |
| `dst_mac()` / `src_mac()` | Both return `nullptr` — PPP is a point-to-point link with no MAC addressing. |
| `ethertype() const` | Returns `0` — PPP is not an Ethernet-layer protocol; dispatch is by `hdr()->protocol`, not ethertype. |
| `patch_checksum() override` | No-op — the PPP FCS is appended at the serial/modem level, outside `lynx`. |
| `type() const override` | Returns `FrameType::PPP`. |

### Example

```cpp
PPP ppp;
ppp.hdr()->protocol = constants::PPP_PROTO_IP;
ppp / ip4;   // encapsulate an IPv4 packet inside PPP
```

```cpp
auto ppp = pppoe->as<PPP>();     // when pppoe->is_session()
if (ppp->hdr()->is_ipv4()) {
    auto ip = ppp->as<IPv4>();
} else if (ppp->hdr()->is_lcp()) {
    auto lcp = ppp->as<LCP>();
}
```

## 4. LCP / NCP Common Header

`HdrLCP` (packed) is shared by `LCP`, `IPCP`, and `IPv6CP` (and, per the
source comments, is the intended structure for future `CCP`/`ECP`
support — see [§10](#10-constants)):

```cpp
LYNX_PACKED HdrLCP {
    uint8_t  code;      // PPP_CODE_* — message type
    uint8_t  id;        // identifier echoed in replies to correlate request/reply
    uint16_t length;    // total length including this header and all data
                        // computed by serialize() — do not set manually
};
```

`HdrPAP`, `HdrCHAP`, `HdrIPCP`, and `HdrIPv6CP` are each declared as an
empty struct inheriting `HdrLCP` (`LYNX_PACKED HdrPAP : HdrLCP {};`,
etc.) — they exist purely as distinct C++ types for overload/template
dispatch (`as<PAP>()` vs. `as<CHAP>()`), not because the wire layout
differs.

### TLV Option Format (LCP / IPCP / IPv6CP)

Options in Configure-Request / Configure-Ack / Configure-Nak /
Configure-Reject messages are encoded as TLVs:

```
[ TYPE:1 | LENGTH:1 (includes this 2-byte header) | VALUE:(LENGTH-2) ]
```

```cpp
LYNX_PACKED HdrBaseTLV {
    uint8_t type;
    uint8_t length;      // total option length in bytes (includes type + length)
    const_view_t value;  // option data — length is (length - 2) bytes
};
```

`HdrLCPOpt`, `HdrIPCPOpt`, and `HdrIPv6CPOpt` are each a distinct type
wrapping `HdrBaseTLV` (for the same dispatch reasons as above).

`TLVProtocolBaseClass` (`include/lynx/protocols/l2/ppp/tlv_base.hpp`)
implements the shared option-walking and option-appending logic, used
identically by `LCP`, `IPCP`, and `IPv6CP`:

| Method | Description |
|---|---|
| `tlv_reset()` | Resets the internal option cursor (`tlv_pos_ = 0`). |
| `base_tlv_next(const_view_t& load_)` (protected) | Reads the next TLV option at `tlv_pos_` within `load_`, validates its declared `length` fits, and advances `tlv_pos_` past it. Returns an empty `HdrBaseTLV{}` if no more options fit. Each subclass exposes this through its own `tlv_next()`, returning its own option type (`HdrLCPOpt`, `HdrIPCPOpt`, `HdrIPv6CPOpt`) via implicit construction from the common base. |
| `base_add_option(type, value, value_size, load_, load_buf_)` (protected) | Appends one option TLV to `load_`. See [ownership note](#option-ownership) below. Exposed by each subclass as `add_option(type, value, value_size)` via the `INCLUDE_ADD_OPTION` macro. |

#### Option Ownership

`base_add_option()` follows the general capture/edit/resend ownership
model described in
[API.md § Memory Model](../API.md#memory-model-capture-edit-resend):
if `load_` is not already backed by an owned `load_buf_` (i.e. it is
still a borrowed view into a capture slab), or the existing buffer lacks
capacity, a fresh `Buffer` is allocated, the existing bytes are copied
into it, and the option is appended there — the original borrowed bytes
are left completely untouched.

```cpp
LCP lcp(constants::PPP_CODE_CONF_REQ, 1);
const uint8_t mru_val[] = { 0x05, 0xDC };  // 1500, big-endian
lcp.add_option(constants::LCP_OPT_MRU, mru_val, 2);
```

## 5. LCP — Link Control Protocol

Base class: `ProtocolBaseObject`, `TLVProtocolBaseClass`
PPP protocol field: `0xC021`

LCP establishes, configures, authenticates, and terminates PPP links. It
is exchanged before any network-layer traffic and must reach the
"opened" state before IPCP or IPv6CP negotiation can begin.

### Constructors

| Constructor | Description |
|---|---|
| `LCP()` | Default — `code = PPP_CODE_CONF_REQ`, `id = 0`, `length = 0` (computed in `serialize()`). |
| `LCP(uint8_t code, uint8_t id)` | Constructs with explicit `code`/`id`; `length = 0`. |
| `explicit LCP(const hdrs::HdrLCP& h)` | Constructs directly from a pre-populated `HdrLCP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (`length` computed as `hdr_size() + load_.size()`, swapped to network byte order) followed by `load_`. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < sizeof(HdrLCP)` or if the parsed `length` is smaller than the header itself. Clamps `load_` to the bytes actually present, handling truncated captures. |
| `hdr_size() const override` | Returns `sizeof(HdrLCP)` (`4`). |
| `hdr() override` | Returns `HdrLCP*`. |
| `patch_checksum() override` | No-op. |
| `tlv_next()` | Returns the next `HdrLCPOpt` — see [§4](#4-lcp--ncp-common-header). |
| `add_option(type, value, value_size)` | Appends an option TLV — see [§4](#4-lcp--ncp-common-header). |

### Example

```cpp
LCP lcp(constants::PPP_CODE_CONF_REQ, 1);
const uint8_t mru[] = { constants::LCP_OPT_MRU, 4,
    static_cast<uint8_t>(constants::PPP_DEFAULT_MRU >> 8),
    static_cast<uint8_t>(constants::PPP_DEFAULT_MRU & 0xFF) };
lcp / Raw(mru, sizeof(mru));

PPP ppp(constants::PPP_ADDRESS, constants::PPP_CONTROL, constants::PPP_PROTO_LCP);
ppp / lcp;
```

```cpp
auto lcp = ppp->as<LCP>();   // when ppp->hdr()->is_lcp()
if (lcp->hdr()->code == constants::PPP_CODE_ECHO_REQ) { /* ... */ }
```

## 6. PAP — Password Authentication Protocol

Base class: `ProtocolBaseObject`
PPP protocol field: `0xC023`

PAP performs plaintext authentication — credentials are sent in the
clear. It has been superseded by CHAP and EAP in modern deployments but
remains common in legacy ISP and DSL environments.

### Message Bodies

PAP has no fixed-size value fields — every field is a length-prefixed
byte string. `dissect()` only sets `load_` to the raw body bytes; it does
not parse these bodies. Two accessors are provided instead:

- `get_auth_req_creds()` — for `PAP_CODE_AUTH_REQ`, returns a
  `PAPAuthRequest { peer_id, passwd }` view, each a `std::span<const uint8_t>`
  into `load_`. Returns an all-empty struct if the packet is not an
  auth-request, or if the length-prefixed sections do not fit within
  `load_`.
- `get_auth_response_msg()` — for `PAP_CODE_AUTH_ACK` /
  `PAP_CODE_AUTH_NAK`, returns the entire `load_` as the response message.

### Constructors

| Constructor | Description |
|---|---|
| `PAP()` | Default — `code = PAP_CODE_AUTH_REQ`, `id = 0`, `length = 0`. |
| `PAP(uint8_t code, uint8_t id)` | Constructs with explicit `code`/`id`. |
| `explicit PAP(const hdrs::HdrPAP& h)` | Constructs directly from a pre-populated `HdrPAP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (`length` computed) followed by `load_`. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < sizeof(HdrPAP)`. |
| `hdr_size() const override` | Returns `sizeof(HdrPAP)` (`4`). |
| `hdr() override` | Returns `HdrPAP*`. |
| `patch_checksum() override` | No-op. |
| `is_auth_request()` | `true` if `code == PAP_CODE_AUTH_REQ`. |
| `is_auth_response()` | `true` if `code == PAP_CODE_AUTH_ACK` or `PAP_CODE_AUTH_NAK`. |
| `get_auth_req_creds()` | See [Message Bodies](#message-bodies) above. |
| `get_auth_response_msg()` | See [Message Bodies](#message-bodies) above. |
| `set_auth_req_creds(peer_id, peer_id_size, password, password_len)` | Builds and stores a length-prefixed `peer-id-len \| peer-id \| passwd-len \| passwd` body. **See implementation note below.** |
| `set_auth_response_msg(msg, msg_len)` | Stores `msg` as the entire response body, via `set_message()`. |

> **Implementation note:** `set_auth_req_creds()`'s guard condition reads
> `if (!is_auth_request() || !is_auth_response())`, which — since a
> packet cannot simultaneously satisfy both `is_auth_request()` and
> `is_auth_response()` — evaluates to `true` unconditionally, so the
> function always returns immediately without setting any credentials
> regardless of the packet's actual code. The guard was likely intended
> as `if (!is_auth_request())`. Callers who need to build a PAP
> Authenticate-Request body should construct it manually and pass it via
> the base `set_load()` instead, as a workaround.

### Example

```cpp
// authenticate-request body: id-len(1B) | id | pw-len(1B) | pw
const uint8_t user[] = "admin";
const uint8_t pass[] = "secret";
uint8_t body[1 + sizeof(user)-1 + 1 + sizeof(pass)-1];
body[0] = sizeof(user) - 1;
std::memcpy(body + 1, user, sizeof(user)-1);
body[sizeof(user)] = sizeof(pass) - 1;
std::memcpy(body + sizeof(user) + 1, pass, sizeof(pass)-1);

PAP pap(constants::PAP_CODE_AUTH_REQ, 1);
pap / Raw(body, sizeof(body));   // set_auth_req_creds() has the issue noted above — use set_load()/operator/ instead
```

```cpp
auto pap = ppp->as<PAP>();   // when ppp->hdr()->is_pap()
if (pap->hdr()->code == constants::PAP_CODE_AUTH_REQ) {
    // peer-id and password are in pap->load() as raw bytes
}
```

## 7. CHAP — Challenge Handshake Authentication Protocol

Base class: `ProtocolBaseObject`
PPP protocol field: `0xC223`

CHAP performs a three-way handshake: the authenticator sends a
Challenge, the peer responds with a Response (a hash of id + secret +
challenge value — commonly MD5, per RFC 1994), and the authenticator
verifies it and sends Success or Failure.

### Message Bodies

- `get_challenge_response()` — for `CHAP_CODE_CHALLENGE` /
  `CHAP_CODE_RESPONSE`, returns a `CHAPChallengeResponse { value, name }`
  view: `value` is the hash (length determined by a leading value-size
  byte — 16 bytes for MD5), `name` is the remaining bytes. Returns an
  all-empty struct if the packet is neither a challenge nor a response,
  or if the length-prefixed value does not fit within `load_`.
- `get_message()` — for `CHAP_CODE_SUCCESS` / `CHAP_CODE_FAILURE`,
  returns the entire `load_` as the message string.

### Constructors

| Constructor | Description |
|---|---|
| `CHAP()` | Default — `code = CHAP_CODE_CHALLENGE`, `id = 0`, `length = 0`. |
| `CHAP(uint8_t code, uint8_t id)` | Constructs with explicit `code`/`id`. |
| `explicit CHAP(const hdrs::HdrCHAP& h)` | Constructs directly from a pre-populated `HdrCHAP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (`length` computed) followed by `load_`. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < sizeof(HdrCHAP)`. |
| `hdr_size() const override` | Returns `sizeof(HdrCHAP)` (`4`). |
| `hdr() override` | Returns `HdrCHAP*`. |
| `patch_checksum() override` | No-op. |
| `is_challenge()` / `is_response()` / `is_success()` / `is_failure()` | Test `hdr_.code` against the corresponding `CHAP_CODE_*` constant. |
| `get_challenge_response()` | See [Message Bodies](#message-bodies-1) above. |
| `get_message()` | See [Message Bodies](#message-bodies-1) above. |
| `set_challenge_response(value, value_size, name, name_size)` | Builds and stores a `value-size \| value \| name` body. Requires `is_challenge()` or `is_response()`; otherwise fails with `Status::InvalidState`. |
| `set_message(message, size)` | Stores `message` as the entire body. Requires `is_success()` or `is_failure()`; otherwise fails with `Status::InvalidState`. |

### Example

```cpp
uint8_t body[1 + 16 + name_len];
body[0] = 16;  // MD5 hash length
std::memcpy(body + 1, challenge_hash, 16);
std::memcpy(body + 17, name, name_len);

CHAP chap(constants::CHAP_CODE_CHALLENGE, 1);
chap / Raw(body, sizeof(body));
```

```cpp
auto chap = ppp->as<CHAP>();   // when ppp->hdr()->is_chap()
if (chap->hdr()->code == constants::CHAP_CODE_CHALLENGE) {
    auto cr = chap->get_challenge_response();
    // cr.value — challenge hash, cr.name — authenticator name
}
```

## 8. IPCP — IP Control Protocol

Base class: `ProtocolBaseObject`, `TLVProtocolBaseClass`
PPP protocol field: `0x8021`

IPCP negotiates IPv4 parameters over a PPP link — most commonly the
local IP address (`IPCP_OPT_ADDR`) and DNS servers (`IPCP_OPT_DNS1` /
`IPCP_OPT_DNS2`). IPCP shares the exact same 4-byte header layout as LCP
— the class exists as a distinct type purely so `as<IPCP>()` and
`as<LCP>()` dispatch correctly based on the PPP protocol field.

### Constructors

| Constructor | Description |
|---|---|
| `IPCP()` | Default — `code = PPP_CODE_CONF_REQ`, `id = 0`, `length = 0`. |
| `IPCP(uint8_t code, uint8_t id)` | Constructs with explicit `code`/`id`. |
| `explicit IPCP(const hdrs::HdrLCP& h)` | Constructs directly from a pre-populated `HdrLCP` (IPCP reuses this type rather than defining a separate `HdrIPCP` constructor overload). |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (`length` computed) followed by `load_`. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < sizeof(HdrLCP)`. |
| `hdr_size() const override` | Returns `sizeof(HdrLCP)` (`4`). |
| `hdr() override` | Returns `HdrLCP*`. |
| `patch_checksum() override` | No-op. |
| `tlv_next()` | Returns the next `HdrIPCPOpt`. |
| `add_option(type, value, value_size)` | Appends an option TLV. |

### Example

```cpp
// IPCP_OPT_ADDR: type(1B) | length(1B) | ip(4B)
const uint8_t addr_opt[] = { constants::IPCP_OPT_ADDR, 6, 0,0,0,0 };
IPCP ipcp(constants::PPP_CODE_CONF_REQ, 1);
ipcp / Raw(addr_opt, sizeof(addr_opt));

PPP ppp(constants::PPP_ADDRESS, constants::PPP_CONTROL, constants::PPP_PROTO_IPCP);
ppp / ipcp;
```

```cpp
auto ipcp = ppp->as<IPCP>();   // when ppp->hdr()->is_ipcp()
```

## 9. IPv6CP — IPv6 Control Protocol

Base class: `ProtocolBaseObject`, `TLVProtocolBaseClass`
PPP protocol field: `0x8057`

IPv6CP negotiates IPv6 parameters. Its primary option is the 8-byte
interface identifier (`IPV6CP_OPT_IFACE_ID`), used to form the IPv6
link-local address. Same header layout as LCP and IPCP.

### Constructors

| Constructor | Description |
|---|---|
| `IPv6CP()` | Default — `code = PPP_CODE_CONF_REQ`, `id = 0`, `length = 0`. |
| `IPv6CP(uint8_t code, uint8_t id)` | Constructs with explicit `code`/`id`. |
| `explicit IPv6CP(const hdrs::HdrIPv6CP& h)` | Constructs directly from a pre-populated `HdrIPv6CP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes the header (`length` computed) followed by `load_`. |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < sizeof(HdrIPv6CP)`. |
| `hdr_size() const override` | Returns `sizeof(HdrIPv6CP)` (`4`). |
| `hdr() override` | Returns `HdrIPv6CP*`. |
| `patch_checksum() override` | No-op. |
| `tlv_next()` | Returns the next `HdrIPv6CPOpt`. |
| `add_option(type, value, value_size)` | Appends an option TLV. |

### Example

```cpp
auto ipv6cp = ppp->as<IPv6CP>();   // when ppp->hdr()->is_ipv6cp()
```

## 10. Constants

Defined in `include/lynx/protocols/l2/ppp/const.hpp`:

### Header Length Variants

| Constant | Value | Description |
|---|---|---|
| `PPP_HDR_LEN` | `4` | Full uncompressed header. |
| `PPP_HDR_LEN_ACFC` | `2` | Address+control stripped. |
| `PPP_HDR_LEN_PFC` | `3` | Protocol compressed to 1 byte. |
| `PPP_HDR_LEN_MIN` | `1` | Both compressions active. |
| `PPP_HDR_LEN_MAX` | `4` | Maximum (uncompressed) header length. |
| `PPP_ADDRESS` | `0xFF` | All-stations address (uncompressed form). |
| `PPP_CONTROL` | `0x03` | Unnumbered information (uncompressed form). |

### PPP Protocol Numbers

| Constant | Value | Description |
|---|---|---|
| `PPP_PROTO_IP` | `0x0021` | IPv4 payload. |
| `PPP_PROTO_IPV6` | `0x0057` | IPv6 payload. |
| `PPP_PROTO_IPX` | `0x002B` | Novell IPX payload. |
| `PPP_PROTO_BRIDGING` | `0x0031` | Bridged PDU. |
| `PPP_PROTO_MPLS_UC` | `0x0281` | MPLS unicast. |
| `PPP_PROTO_MPLS_MC` | `0x0283` | MPLS multicast. |
| `PPP_PROTO_LCP` | `0xC021` | Link Control Protocol. |
| `PPP_PROTO_PAP` | `0xC023` | Password Authentication Protocol. |
| `PPP_PROTO_LQR` | `0xC025` | Link Quality Report. |
| `PPP_PROTO_CHAP` | `0xC223` | Challenge Handshake Authentication Protocol. |
| `PPP_PROTO_EAP` | `0xC227` | Extensible Authentication Protocol. |
| `PPP_PROTO_IPCP` | `0x8021` | IPv4 Control Protocol. |
| `PPP_PROTO_IPV6CP` | `0x8057` | IPv6 Control Protocol. |
| `PPP_PROTO_IPXCP` | `0x802B` | IPX Control Protocol. |
| `PPP_PROTO_MPLSCP` | `0x8281` | MPLS Control Protocol. |
| `PPP_PROTO_CCP` | `0x80FD` | Compression Control Protocol. |
| `PPP_PROTO_ECP` | `0x8053` | Encryption Control Protocol. |

### LCP / NCP Shared Codes

The first 11 codes are identical for LCP, IPCP, IPv6CP, CCP, and ECP.
`PPP_CODE_PROTO_REJ`, `PPP_CODE_ECHO_REQ`, `PPP_CODE_ECHO_REP`, and
`PPP_CODE_DISCARD` are LCP-only — IPCP/IPv6CP/CCP/ECP do not define
them.

| Constant | Value | Description |
|---|---|---|
| `PPP_CODE_CONF_REQ` | `1` | Configure-Request. |
| `PPP_CODE_CONF_ACK` | `2` | Configure-Ack. |
| `PPP_CODE_CONF_NAK` | `3` | Configure-Nak. |
| `PPP_CODE_CONF_REJ` | `4` | Configure-Reject. |
| `PPP_CODE_TERM_REQ` | `5` | Terminate-Request. |
| `PPP_CODE_TERM_ACK` | `6` | Terminate-Ack. |
| `PPP_CODE_CODE_REJ` | `7` | Code-Reject. |
| `PPP_CODE_PROTO_REJ` | `8` | Protocol-Reject (LCP only). |
| `PPP_CODE_ECHO_REQ` | `9` | Echo-Request (LCP only). |
| `PPP_CODE_ECHO_REP` | `10` | Echo-Reply (LCP only). |
| `PPP_CODE_DISCARD` | `11` | Discard-Request (LCP only). |

### LCP Option Types

| Constant | Value | Description |
|---|---|---|
| `LCP_OPT_MRU` | `1` | Maximum Receive Unit (2-byte value). |
| `LCP_OPT_ACCM` | `2` | Async-Control-Character-Map (4-byte value). |
| `LCP_OPT_AUTH` | `3` | Authentication protocol (2-byte proto + optional data). |
| `LCP_OPT_QUALITY` | `4` | Link quality monitoring. |
| `LCP_OPT_MAGIC` | `5` | Magic number (4-byte value). |
| `LCP_OPT_PFC` | `7` | Protocol Field Compression. |
| `LCP_OPT_ACFC` | `8` | Address/Control Field Compression. |
| `LCP_OPT_FCS_ALT` | `9` | FCS alternatives. |

### IPCP Option Types

| Constant | Value | Description |
|---|---|---|
| `IPCP_OPT_ADDRS` | `1` | IP addresses (deprecated). |
| `IPCP_OPT_COMPRESS` | `2` | IP compression protocol. |
| `IPCP_OPT_ADDR` | `3` | IP address (4 bytes). |
| `IPCP_OPT_DNS1` | `129` | Primary DNS server. |
| `IPCP_OPT_DNS2` | `131` | Secondary DNS server. |

### IPv6CP Option Types

| Constant | Value | Description |
|---|---|---|
| `IPV6CP_OPT_IFACE_ID` | `1` | Interface identifier (8 bytes). |
| `IPV6CP_OPT_COMPRESS` | `2` | IPv6 compression protocol. |

### PAP Code Values

| Constant | Value | Description |
|---|---|---|
| `PAP_CODE_AUTH_REQ` | `1` | Authenticate-Request. |
| `PAP_CODE_AUTH_ACK` | `2` | Authenticate-Ack. |
| `PAP_CODE_AUTH_NAK` | `3` | Authenticate-Nak. |

### CHAP Code Values

| Constant | Value | Description |
|---|---|---|
| `CHAP_CODE_CHALLENGE` | `1` | Challenge. |
| `CHAP_CODE_RESPONSE` | `2` | Response. |
| `CHAP_CODE_SUCCESS` | `3` | Success. |
| `CHAP_CODE_FAILURE` | `4` | Failure. |

### CCP / ECP

The header layout, codes, and TLV format for CCP (Compression Control
Protocol) and ECP (Encryption Control Protocol) are identical to
LCP/IPCP (`PPP_CODE_*` and `HdrLCP` apply directly). CCP and ECP differ
only in the algorithm identifiers carried inside their configuration
option values, which are vendor-specific and are explicitly out of scope
for this version of the library — no dedicated `CCP` or `ECP` class
exists yet.

### Defaults

| Constant | Value | Description |
|---|---|---|
| `PPP_DEFAULT_MRU` | `1500` | Suggested default Maximum Receive Unit, in bytes. |
| `PPP_DEFAULT_ACCM` | `0xFFFFFFFF` | Suggested default Async-Control-Character-Map (escape all control characters). |

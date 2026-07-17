# Protocol: Stream Control Transmission Protocol (`SCTP`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Wire Format](#3-wire-format)
- [4. Constants](#4-constants)
- [5. Class `SCTP`](#5-class-sctp)
- [6. Checksum Algorithm](#6-checksum-algorithm)
- [7. Chunk Walking and Construction](#7-chunk-walking-and-construction)
- [8. Example](#8-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/l4/sctp/sctp.hpp`,
  `include/lynx/protocols/l4/sctp/hdrs.hpp`,
  `include/lynx/protocols/l4/sctp/const.hpp`
- Namespace: `lynx::proto` (class), `lynx::hdrs` (header structs),
  `lynx::constants` (constants)
- Base class: [`Segment`](../API.md#common-base-classes) →
  [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
- RFC: [RFC 4960 — Stream Control Transmission
  Protocol](https://www.rfc-editor.org/rfc/rfc4960)

> **Provisional support.** Per the project [CHANGELOG](../README.md#6-changelog),
> SCTP has not been extensively tested in this release and is provided
> as-is.

## 2. Overview

`SCTP` implements the 12-byte SCTP common header, plus a lazy, on-demand
chunk walker/builder for the variable-length chunk sequence that follows
it. Individual chunk *bodies* (e.g. `HdrSCTPData`, `HdrSCTPInit`) are not
automatically parsed from a chunk's raw value bytes — the caller
interprets `chunk.value` according to `chunk.type`, casting/copying into
`hdrs::HdrSCTPData` or `hdrs::HdrSCTPInit` as appropriate.

Unlike every other checksummed protocol in the library, SCTP's checksum
is **CRC-32c** (Castagnoli polynomial), not the RFC 1071 one's-complement
sum used by IPv4/TCP/UDP/ICMP/ICMPv6/IGMP, and it covers the **entire**
SCTP packet (common header + all chunks) rather than requiring an IP
pseudo-header.

## 3. Wire Format

### Common Header (12 bytes, fixed)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Verification Tag                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Checksum (CRC-32c)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```cpp
LYNX_PACKED HdrSCTP {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t vtag;       // verification tag — agreed during INIT handshake
    uint32_t checksum;   // CRC-32c over entire SCTP packet, zeroed during calc
};
```

### Chunk Header (4 bytes, fixed) + Type-Specific Fixed Fields

Every chunk begins with a 4-byte header, followed by chunk-type-specific
fixed fields (for `DATA` and `INIT`/`INIT-ACK`), followed by variable data
or optional TLV parameters:

```cpp
LYNX_PACKED HdrSCTPChunk {
    uint8_t      type;    // SCTP_CHUNK_*
    uint8_t      flags;   // chunk-type-specific — e.g. SCTP_DATA_FLAG_* for DATA
    uint16_t     length;  // total chunk length, INCLUDING this 4-byte header, un-padded
    const_view_t value{}; // chunk-type-specific body, excludes the 4-byte header

    [[nodiscard]] uint32_t padded_length() const noexcept;  // rounds length up to a multiple of 4
};

// DATA chunk fixed fields (follow HdrSCTPChunk)
LYNX_PACKED HdrSCTPData {
    uint32_t tsn;           // transmission sequence number
    uint16_t stream_id;
    uint16_t stream_seq;    // stream sequence number — ignored if unordered
    uint32_t payload_proto; // payload protocol identifier (often 0 = unspecified)
    // user data follows, length = chunk.length - sizeof(HdrSCTPChunk) - sizeof(HdrSCTPData)
};

// INIT / INIT-ACK chunk fixed fields (follow HdrSCTPChunk)
LYNX_PACKED HdrSCTPInit {
    uint32_t init_tag;      // becomes the verification tag for this direction
    uint32_t a_rwnd;        // advertised receiver window credit
    uint16_t out_streams;   // number of outbound streams requested
    uint16_t in_streams;    // number of inbound streams supported
    uint32_t init_tsn;      // initial transmission sequence number
    // optional parameters (TLV) follow for INIT-ACK (state cookie, etc.)
};
```

On the wire, each chunk is padded to a 4-byte boundary with zero bytes;
the `length` field itself always reflects the **un-padded** size.

## 4. Constants

Defined in `include/lynx/protocols/l4/sctp/const.hpp`:

| Constant | Value | Description |
|---|---|---|
| `IP_PROTO_SCTP` | `132` | IP protocol number for SCTP. |
| `SCTP_HDR_LEN` | `12` | Common header length (`consteval`). |
| `SCTP_CHUNK_HDR_LEN` | `4` | Chunk header length (`consteval`). |
| `SCTP_CHUNK_DATA` | `0` | Payload data. |
| `SCTP_CHUNK_INIT` | `1` | Association initiation. |
| `SCTP_CHUNK_INIT_ACK` | `2` | Initiation acknowledgment. |
| `SCTP_CHUNK_SACK` | `3` | Selective acknowledgment. |
| `SCTP_CHUNK_HEARTBEAT` | `4` | Heartbeat request. |
| `SCTP_CHUNK_HEARTBEAT_ACK` | `5` | Heartbeat acknowledgment. |
| `SCTP_CHUNK_ABORT` | `6` | Association abort. |
| `SCTP_CHUNK_SHUTDOWN` | `7` | Graceful shutdown. |
| `SCTP_CHUNK_SHUTDOWN_ACK` | `8` | Shutdown acknowledgment. |
| `SCTP_CHUNK_ERROR` | `9` | Operation error. |
| `SCTP_CHUNK_COOKIE_ECHO` | `10` | Cookie echo (association setup). |
| `SCTP_CHUNK_COOKIE_ACK` | `11` | Cookie acknowledgment. |
| `SCTP_CHUNK_SHUTDOWN_COMPLETE` | `14` | Shutdown handshake complete. |
| `SCTP_DATA_FLAG_E` | `0x01` | DATA chunk: ending fragment. |
| `SCTP_DATA_FLAG_B` | `0x02` | DATA chunk: beginning fragment. |
| `SCTP_DATA_FLAG_U` | `0x04` | DATA chunk: unordered delivery. |
| `SCTP_DEFAULT_OUT_STREAMS` | `10` | Suggested default for `HdrSCTPInit::out_streams`. |
| `SCTP_DEFAULT_IN_STREAMS` | `65535` | Suggested default for `HdrSCTPInit::in_streams`. |
| `SCTP_DEFAULT_RWND` | `106496` | Suggested default advertised receiver window (104 KiB). |
| `SCTP_CRC32C_POLY` | `0x1EDC6F41` | CRC-32c (Castagnoli) polynomial, matching `utils::crc32c()`. |
| `SCTP_CRC32C_INIT` | `0xFFFFFFFF` | CRC-32c initial register value. |

> `SCTP_HDR_LEN` and `SCTP_CHUNK_HDR_LEN` are also separately (and
> identically) defined in `include/lynx/protocols/l4/tcp/const.hpp` — see
> the note in [tcp.md § Constants](tcp.md#4-constants). This file is the
> canonical location for these two constants.

## 5. Class `SCTP`

### Constructors

| Constructor | Description |
|---|---|
| `SCTP()` | Default — `src_port = dst_port = vtag = checksum = 0`. |
| `explicit SCTP(const hdrs::HdrSCTP& h)` | Constructs directly from a pre-populated `HdrSCTP`. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | **Recomputes the checksum unconditionally** by calling `patch_checksum()` internally (via a `const_cast`) before writing — this guarantees that any single call to `serialize()` always produces a wire-correct packet, even if the caller never called `patch_checksum()` directly. Then writes the byte-order-swapped header followed by `load_` (the chunk sequence). |
| `dissect(const uint8_t* data, uint32_t len) override` | Parses `data` into `hdr_`. Sets `Status::MalformedPacket` if `len < SCTP_HDR_LEN`. `load_` is set to the bytes beyond the 12-byte header — individual chunks are **not** parsed here; they are walked lazily via `chunk_next()`. |
| `hdr_size() const override` | Returns `SCTP_HDR_LEN` (`12`). |
| `hdr() override` | Returns `HdrSCTP*`. |
| `proto() const override` | Returns `IP_PROTO_SCTP` (`132`). |
| `patch_checksum() override` | Computes CRC-32c over the entire packet (header + `load_`) — see [§6](#6-checksum-algorithm). |
| `swap_hdr_byte_order(HdrSCTP&) const` | Internal helper — swaps `src_port`, `dst_port`, `vtag`, `checksum` in place. |
| `chunk_reset()` | Resets the internal chunk cursor (`chunk_pos_ = 0`) to walk the chunk sequence from the start. |
| `chunk_next()` | See [§7](#7-chunk-walking-and-construction). |
| `add_chunk()` | See [§7](#7-chunk-walking-and-construction). |

## 6. Checksum Algorithm

Because `serialize()` always calls `patch_checksum()` first, calling
`patch_checksum()` manually before `serialize()` is optional — but it is
still useful, for example, if the checksum value itself needs to be
inspected before the packet is actually serialized/sent.

1. Zero `hdr_.checksum`.
2. Allocate a temporary `Buffer` sized `sizeof(HdrSCTP) + load_.size()`.
3. Build a byte-order-swapped wire copy of the header with `checksum`
   zeroed, write it into the temporary buffer, then append `load_`
   (the raw chunk sequence, already in wire format since chunks are
   built directly in network byte order — see [§7](#7-chunk-walking-and-construction)).
4. Compute `utils::crc32c()` over the entire temporary buffer and store
   the result into `hdr_.checksum`.

`utils::crc32c()` (see [API.md § Checksum Functions](../API.md#checksum-functions))
implements CRC-32c using the Castagnoli polynomial
(`SCTP_CRC32C_POLY = 0x1EDC6F41`) via a precomputed lookup table — this
is a structurally different algorithm from `utils::inet_checksum()`
(RFC 1071 one's-complement sum), which every other protocol in the
library uses.

## 7. Chunk Walking and Construction

SCTP chunks are not eagerly parsed at `dissect()` time — `load_` is left
as an opaque span of chunk bytes, and chunks are walked lazily on demand,
following the same pattern used elsewhere in the library for TLV-style
variable-length data (PPP LCP/IPCP/IPv6CP options, PPPoE discovery tags).

### Reading Chunks

```cpp
sctp.chunk_reset();
while (true) {
    auto chunk = sctp.chunk_next();
    if (chunk.value.empty() && chunk.length == 0) break;  // no more chunks

    switch (chunk.type) {
        case constants::SCTP_CHUNK_DATA: {
            hdrs::HdrSCTPData data_hdr;
            std::memcpy(&data_hdr, chunk.value.data(), sizeof(data_hdr));
            // user data begins at chunk.value.data() + sizeof(HdrSCTPData)
            break;
        }
        case constants::SCTP_CHUNK_INIT: {
            hdrs::HdrSCTPInit init_hdr;
            std::memcpy(&init_hdr, chunk.value.data(), sizeof(init_hdr));
            break;
        }
    }
}
```

`chunk_next()` advances the internal cursor by `padded_length()`
(4-byte-aligned) on each call, regardless of the un-padded `length`
value, matching the wire layout. It returns an empty (`{}`) chunk, and
sets `Status::MalformedPacket`, if the next chunk header would exceed
`load_`, if the declared `length` is shorter than the 4-byte chunk header
itself, or if the declared `length` would extend past the end of
`load_`.

### Writing Chunks

`add_chunk(type, flags, value, value_size)` appends one chunk to `load_`,
growing the backing `Buffer` (with 256 bytes of headroom for subsequent
chunks) as needed, zero-padding the chunk to a 4-byte boundary as
required by the wire format. The `length` field itself is written
**un-padded**, per RFC 4960 §3.2.

```cpp
SCTP sctp;
sctp.hdr()->src_port = htons(5000);
sctp.hdr()->dst_port = htons(9);
sctp.hdr()->vtag     = 0;   // 0 during INIT — no association exists yet

hdrs::HdrSCTPInit init{};
init.init_tag     = htonl(0x12345678);
init.a_rwnd       = htonl(constants::SCTP_DEFAULT_RWND);
init.out_streams  = htons(constants::SCTP_DEFAULT_OUT_STREAMS);
init.in_streams   = htons(constants::SCTP_DEFAULT_IN_STREAMS);
init.init_tsn     = htonl(1);

sctp.add_chunk(constants::SCTP_CHUNK_INIT, 0,
               reinterpret_cast<const uint8_t*>(&init), sizeof(init));
```

## 8. Example

Crafting and sending an SCTP INIT chunk over IPv4:

```cpp
proto::IPv4 ip4(src_ip, dst_ip, constants::IP_PROTO_SCTP);
proto::SCTP sctp;
sctp.hdr()->src_port = htons(5000);
sctp.hdr()->dst_port = htons(9);

sctp.add_chunk(constants::SCTP_CHUNK_INIT, 0, init_bytes, init_len);

ip4 / sctp;    // serialize() recomputes the CRC-32c checksum automatically

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

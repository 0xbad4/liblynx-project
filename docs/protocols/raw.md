# Protocol: Raw Bytes (`Raw`)

## Table of Contents

- [1. Reference](#1-reference)
- [2. Overview](#2-overview)
- [3. Class `Raw`](#3-class-raw)
- [4. Example](#4-example)

---

## 1. Reference

- Defined in: `include/lynx/protocols/raw.hpp`
- Namespace: `lynx::proto`
- Base class: [`ProtocolBaseObject`](../API.md#3-protocolbaseobject-class)
  directly (not `Frame`, `Packet`, or `Segment`)

## 2. Overview

`Raw` is the fallback "next layer" for any protocol whose payload does
not need further structured dissection — application data at the end of
a `TCP`/`UDP` stream, an unrecognized ethertype or IP protocol number, or
arbitrary bytes the caller wants to attach as a packet's final payload
during crafting.

`Raw` has no header of its own (`hdr_size()` always returns `0`,
`hdr()` always returns `nullptr`) — it is a thin, zero-copy view over a
byte range, plus two convenience accessors (`bytes()`, `payload()`) for
safe, bounds-checked access without direct pointer arithmetic.

## 3. Class `Raw`

### Constructors

| Constructor | Description |
|---|---|
| `Raw()` | Default. |
| `Raw(const uint8_t* data, uint32_t len)` | Constructs directly from a raw pointer and length — the crafting path. Sets both the internal `data_`/`size_` and `load_` (via `set_load()`). |
| `explicit Raw(std::span<const uint8_t> data)` | Constructs from a `std::span` — equivalent to the pointer/length constructor. |

### Methods

| Method | Description |
|---|---|
| `serialize(Buffer& buf) const override` | Writes `load_` verbatim, if non-empty. |
| `dissect(const uint8_t* data, uint32_t len) override` | Sets `data_`/`size_`/`load_` to view `data` for `len` bytes. No-op (returns immediately) if `data` is null or `len == 0`. |
| `hdr_size() const override` | Always returns `0`. |
| `hdr() override` | Always returns `nullptr`. |
| `bytes()` | `[[nodiscard]] const_view_t bytes() const noexcept` — a safe, bounds-checked span over the entire raw byte range, for callers who want a view without manual pointer arithmetic. |
| `payload(size_t offset)` | `[[nodiscard]] const_view_t payload(size_t offset) const noexcept` — a span over the bytes starting at `offset`. Returns an empty span if `offset >= size_`. |

## 4. Example

Attaching an application payload to a TCP segment:

```cpp
const uint8_t data[] = "GET / HTTP/1.1\r\n\r\n";
proto::Raw payload(data, sizeof(data) - 1);

proto::IPv4 ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
proto::TCP  tcp(12345, 80, 1000, 0, constants::TCP_FLAG_ACK | constants::TCP_FLAG_PSH, 65535);

ip4 / tcp / payload;   // chain right-to-left: tcp's load becomes payload's serialized bytes

proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
eth / ip4;

if (eth.ok() && iface.ok())
    iface.write(eth);
```

Reading unrecognized payload bytes during dissection:

```cpp
if (ip4->hdr()->proto != constants::IP_PROTO_TCP &&
    ip4->hdr()->proto != constants::IP_PROTO_UDP) {
    auto raw = ip4->as<proto::Raw>();
    if (raw && raw->ok()) {
        auto all_bytes = raw->bytes();
    }
}
```

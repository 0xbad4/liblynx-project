# lynx — Error Handling

## Table of Contents

- [1. Overview](#1-overview)
- [2. The Error Type](#2-the-error-type)
- [3. Error Codes](#3-error-codes)
- [4. How to Handle Errors in the Project](#4-how-to-handle-errors-in-the-project)

---

## 1. Overview

Defined in: `include/lynx/core/error.hpp`
Namespace: `lynx`

`lynx` uses a single, flat enumeration (`Status`) for every error condition
in the library — there are no per-class error namespaces. This design
allows errors to compose cleanly across layers: an error raised deep inside
a socket primitive (`Interface`), a `Packet`, a protocol layer, or a
`Buffer` is represented identically and can be inspected through the same
`BaseObject` interface (see [API.md § BaseObject Class](API.md#1-baseobject-class)).

`lynx` does not throw C++ exceptions and does not use per-call return
codes for error reporting. Instead, every class that can fail derives from
`BaseObject`, which records at most one error per object instance
(first-error-wins — see [API.md § Error Policy](API.md#error-policy-first-error-wins)).

## 2. The Error Type

```cpp
struct Error {
    Status      type = Status::Ok;
    const char* msg  = nullptr;     // static string — never freed
};
```

`Error` is a plain, stateless `{ type, msg }` value, used primarily as a
return value by the free socket helper functions in
`include/lynx/net/platform/linux/socket.hpp` (see
[platforms/linux.md](platforms/linux.md)). It carries no methods beyond
construction and the following accessors:

| Method | Signature | Description |
|---|---|---|
| `ok()` | `[[nodiscard]] bool ok() const noexcept` | `true` when `type == Status::Ok`. |
| `what()` | `[[nodiscard]] const char* what() const noexcept` | Human-readable message: prefers the specific `msg` if set and non-empty, otherwise falls back to `status_str(type)`. |
| `Error::make()` | `[[nodiscard]] static Error make(Status s, const char* m) noexcept` | Factory helper constructing `{ s, m }`. |
| `Error::none()` | `[[nodiscard]] static Error none() noexcept` | Factory helper constructing `{ Status::Ok, nullptr }`. |
| `clear()` | `void clear() noexcept` | Resets `type` to `Status::Ok` and `msg` to `nullptr`. |

`msg`, when present, is always a static string literal — it is never
heap-allocated and never freed.

### `status_str()`

```cpp
[[nodiscard]] inline const char* status_str(Status s) noexcept;
```

Returns a short, static string describing a `Status` value. This function
performs no allocation and no syscalls, and is explicitly documented as
safe to call from a signal handler.

## 3. Error Codes

The following table lists every `Status` value defined in
`include/lynx/core/error.hpp`, grouped as in the source, along with the
numeric value, the string returned by `status_str()`, and the condition
that raises it.

### Ok

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::Ok` | `0` | `"ok"` | No error. Default state of every `BaseObject`. |

### Socket Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::SocketCreateFail` | `1` | `"socket create failed"` | `socket(AF_PACKET, ...)` returned `-1`. |
| `Status::SocketBindFail` | `2` | `"socket bind failed"` | `bind()` to the interface failed. |
| `Status::SocketOptionFail` | `3` | `"socket option failed"` | `setsockopt()` failed (promiscuous mode, timeout, receive buffer, direction, etc.). |

### Interface Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::IfaceNotFound` | `10` | `"interface not found"` | `if_nametoindex()` could not resolve the given interface name. |
| `Status::IfaceNotOpen` | `11` | `"interface not open"` | `send()` / `recv()` was called before `open()`. |
| `Status::IfaceAlreadyOpen` | `12` | `"interface already open"` | `open()` was called twice without an intervening `close()`. |

### MAC / ARP Resolution Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::MacResolveFail` | `20` | `"MAC resolve failed"` | The `SIOCGIFHWADDR` ioctl failed while resolving the local interface's hardware MAC. |
| `Status::ArpResolveFail` | `21` | `"ARP lookup failed"` | The `SIOCGARP` ioctl-based kernel ARP cache lookup failed — either the target host is absent from the cache, or the cache entry exists but is not yet complete (`ATF_COM` not set). |
| `Status::ArpTimeout` | `22` | `"ARP timeout"` | **Reserved.** Intended for an active ARP probe with timeout, planned for v1. Not currently raised anywhere in the codebase. |

### Send Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::SendFail` | `30` | `"send failed"` | `sendto()` returned `-1`. |
| `Status::SendTruncated` | `31` | `"send truncated"` | `sendto()` reported sending fewer bytes than requested. |

### Receive Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::RecvFail` | `40` | `"recv failed"` | `recvfrom()` returned `-1` for a reason other than `EAGAIN` / `EINTR` (which are treated as ordinary timeouts, not errors). |

### Buffer Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::BufferTooSmall` | `50` | `"buffer too small"` | A `Buffer::write()`, `Buffer::reserve()`, or `Buffer::patch()` call would exceed the buffer's capacity. |
| `Status::BufferAllocFail` | `51` | `"buffer alloc failed"` | A heap allocation for a `Buffer`'s backing slab (`new uint8_t[]`) threw or returned null. |

### Packet / Dissection Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::MalformedPacket` | `60` | `"malformed packet"` | The raw bytes supplied to `dissect()` are too short for the declared header, or fail a structural sanity check (e.g. an unexpected version field, an out-of-range header-length field). |
| `Status::UnknownProtocol` | `61` | `"unknown protocol"` | An ethertype or IP protocol number does not match any protocol known to the dissection path. |
| `Status::TruncatedPayload` | `62` | `"truncated payload"` | A payload-length field in a header declares more bytes than are actually present in the buffer. |
| `Status::ChecksumMismatch` | `63` | `"checksum mismatch"` | A received checksum does not match the checksum computed over the received bytes. |

### Serialization Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::SerializeFail` | `70` | `"serialize failed"` | A layer's `serialize()` call could not write into the destination `Buffer`. |
| `Status::MissingLayer` | `71` | `"missing required layer"` | A required lower layer is absent — for example, computing a TCP or UDP pseudo-header checksum when no `IPv4`/`IPv6` underlayer has been set via `operator/`. |
| `Status::InvalidState` | `72` | (falls back to `"unknown error"` — not enumerated in `status_str()`) | A layer's current state does not permit the requested operation (e.g. calling a CHAP mutator meant for `SUCCESS`/`FAILURE` messages on a `CHALLENGE`/`RESPONSE` packet). |

### Generic Errors

| Value | Numeric | `status_str()` | Raised when |
|---|---|---|---|
| `Status::InvalidArgument` | `90` | `"invalid argument"` | A null pointer, a zero length, or an otherwise invalid argument / enum value was supplied to a call. |
| `Status::NotImplemented` | `91` | `"not implemented"` | A stub for a feature not yet built in this version (e.g. checksum computation for an unsupported underlayer type, or calling `set_load()` on `ARP`, which has no payload). |
| `Status::Unknown` | `99` | (falls back to `"unknown error"`) | Catch-all. Should never appear in practice. |

> **Note:** `Status::InvalidState` and `Status::Unknown` are not explicitly
> handled by name in `status_str()`'s `switch` statement; both, along with
> any other unmatched value, fall through to that function's `default`
> case, which returns `"unknown error"`. Call `error().type` directly (or
> `status()`) if the *numeric* `Status` value is needed rather than a
> string description.

## 4. How to Handle Errors in the Project

Every class in the library that can fail inherits `BaseObject`
(see [API.md § BaseObject Class](API.md#1-baseobject-class)) and exposes a
uniform four-method surface: `ok()`, `status()`, `errmsg()`, and
`error()`. The same handling pattern applies uniformly across `Interface`,
`Buffer`, `IPv4`, `TCP`, and every other protocol class.

### Basic Pattern

```cpp
iface.open();
if (!iface.ok()) {
    printf("error: %s\n", iface.errmsg());   // human-readable
    // iface.status() → Status::SocketBindFail etc.
    return;
}
```

### Clearing and Retrying

Error state is **never** cleared automatically. After handling an error,
call `clear_error()` explicitly if the object is to be reused:

```cpp
iface.clear_error();
```

### First-Error-Wins

Because `BaseObject` only ever records the *first* error raised on a given
object (until `clear_error()` is called), a sequence of chained calls can
be checked once, at the end, and the resulting `errmsg()` / `status()` will
correctly describe the earliest failure in the chain — not a later,
possibly misleading, symptom of it:

```cpp
absorb(sock::open_raw(fd_));                      if (!ok()) return;
absorb(sock::resolve_ifindex(name_, ifindex_));   if (!ok()) return;
absorb(sock::bind_to_iface(fd_, ifindex_));       if (!ok()) return;
// ... first failure in this chain is what ok() / errmsg() will report.
```

### Errors Returned by Free Functions

The Linux socket primitives in
`include/lynx/net/platform/linux/socket.hpp` are free, stateless functions
(no class, no `BaseObject`) — they report failures by returning an `Error`
value directly rather than through an inherited error state:

```cpp
int ifindex = 0;
Error err = sock::resolve_ifindex("wlan0", ifindex);
if (!err.ok()) {
    std::cerr << "resolve_ifindex failed: " << err.what() << "\n";
    return 1;
}
```

`BaseObject::absorb(const Error&)` exists specifically to bridge this
style back into the stateful `BaseObject` model: it records the `Error` on
the calling object's own error state, honoring first-error-wins.

See [platforms/linux.md](platforms/linux.md) for the complete list of
Linux socket primitives and the specific `Status` values each one can
produce.

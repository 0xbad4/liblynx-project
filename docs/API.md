# lynx — API Documentation

## Table of Contents

- [1. BaseObject Class](#1-baseobject-class)
- [2. Buffer Class](#2-buffer-class)
- [3. ProtocolBaseObject Class](#3-protocolbaseobject-class)
- [4. Interface Class and Socket functions](#4-interface-class-and-socket-functions)
  - [4.1 Common Interface Methods](#41-common-interface-methods)
  - [4.2 Platform APIs](#42-platform-apis)
  - [4.3 config.hpp — compile-time configuration](#43-confighpp--compile-time-configuration)
- [5. Utils](#5-utils)
- [6. Protocols Classes](#6-protocols-classes)

---

## 1. BaseObject Class

Defined in: `include/lynx/core/base.hpp`
Namespace: `lynx`

`BaseObject` is the root class inherited by `Interface`, `Packet`, `Buffer`,
`ProtocolBaseObject`, and — transitively — every concrete protocol layer in
the library. It centralizes error-state tracking so that call chains can be
checked once, at the end, rather than after every individual call.

`lynx` does not use C++ exceptions. Every operation that can fail records
its failure on the object's `BaseObject` error state instead of throwing or
returning an error code directly. See [ERRORS.md](ERRORS.md) for the full
list of error codes (`Status`) and the `Error` carrier type.

### Error Policy: First-Error-Wins

`BaseObject` implements a **first-error-wins** policy: once an error has
been recorded on an object, subsequent calls to `set_error()` on that same
object are silently ignored until `clear_error()` is called. This means the
*root cause* of a failure is preserved even if a chain of calls continues to
execute after the first failure.

### Public Methods

| Method | Signature | Description |
|---|---|---|
| `ok()` | `[[nodiscard]] bool ok() const noexcept` | Returns `true` if no error is currently recorded. |
| `status()` | `[[nodiscard]] Status status() const noexcept` | Returns the recorded `Status` value (`Status::Ok` if none). |
| `errmsg()` | `[[nodiscard]] const char* errmsg() const noexcept` | Returns a human-readable error message — the specific message if one was supplied, otherwise a message derived from `status_str()`. |
| `error()` | `[[nodiscard]] const Error& error() const noexcept` | Returns the full `Error` value (`{ Status, const char* }`). |
| `clear_error()` | `void clear_error() noexcept` | Clears the error state so the object can be reused. **Never called automatically** — the caller must call it explicitly after handling an error. |

### Protected Methods (for use by derived classes)

| Method | Signature | Description |
|---|---|---|
| `set_error()` | `void set_error(Status s, const char* msg) noexcept` | Records an error, honoring the first-error-wins policy — a no-op if an error is already recorded. |
| `absorb()` | `void absorb(const Error& e) noexcept` | Convenience overload — calls `set_error()` from an `Error` value directly, only if `e` is not `ok()`. |
| `overwrite_error()` | `void overwrite_error(Status s, const char* msg) noexcept` | Force-overwrites the current error state, bypassing first-error-wins. Intended for use only after an explicit `clear_error()` + retry sequence. |

### Usage Example

```cpp
iface.open();
if (!iface.ok()) {
    printf("error: %s\n", iface.errmsg());   // human-readable
    // iface.status() → Status::SocketBindFail, etc.
    return;
}

// clear after handling and retry
iface.clear_error();
```

The same pattern applies uniformly to `Buffer`, `IPv4`, `TCP`, `Interface`,
and every other class in the library that derives from `BaseObject`.

---

## 2. Buffer Class

Defined in: `include/lynx/core/buffer.hpp`
Namespace: `lynx`
Inherits: `BaseObject`

`Buffer` is a reference-counted byte slab shared across protocol layers. A
single `Buffer` allocation backs an entire packet — individual protocol
layers write into it at successive offsets rather than each allocating
their own copy.

### Design Rules

- Single allocation per packet — layers write into it at offsets, never
  allocate their own copies.
- Uses `std::shared_ptr<uint8_t[]>` for shared ownership across layers.
- Inherits `BaseObject` for error state (`Status::BufferTooSmall`,
  `Status::BufferAllocFail`).
- Two construction paths:
  - `alloc()` — owns a freshly heap-allocated slab (crafting / send path).
  - `wrap()` — a view into an externally owned slab (recv path, zero-copy).

### Construction

| Method | Signature | Description |
|---|---|---|
| `Buffer()` | `Buffer() = default` | Default constructs an empty, invalid buffer. |
| `alloc()` | `[[nodiscard]] static Buffer alloc(uint32_t capacity) noexcept` | Heap-allocates a zeroed slab of `capacity` bytes. Used for packet crafting and the send path. Returns a `Buffer` carrying `Status::InvalidArgument` if `capacity == 0`, or `Status::BufferAllocFail` if the allocation fails. |
| `wrap()` | `[[nodiscard]] static Buffer wrap(std::shared_ptr<uint8_t[]> owner, uint32_t offset, uint32_t length) noexcept` | Takes shared ownership of an existing slab at a given `offset`, exposing `length` valid bytes. Used for the zero-copy receive path: the receive slab is shared, and each protocol layer wraps a view into it at its own offset without copying. A wrapped `Buffer` is read-only — `cap() == len()`, with no room to grow. |

### Write (Crafting Path)

| Method | Signature | Description |
|---|---|---|
| `write()` | `bool write(const uint8_t* src, uint32_t n) noexcept` | Appends `n` bytes from `src` at the current write cursor (`len_`), advancing `len_` by `n` on success. Sets `Status::InvalidArgument` if `src` is null, or `Status::BufferTooSmall` if the write would exceed `cap()`. |
| `reserve()` | `[[nodiscard]] uint8_t* reserve(uint32_t n) noexcept` | Reserves `n` bytes at the current cursor without writing, returning a pointer to the reserved region for direct writes (e.g. for a packed struct overlay). Advances `len_` by `n`. Returns `nullptr` on overflow. |
| `patch()` | `bool patch(uint32_t pos, const uint8_t* src, uint32_t n) noexcept` | Overwrites `n` bytes at absolute position `pos` within the slab, without advancing `len_`. Used for checksum patching after full serialization. |

### Read (Dissection Path)

| Method | Signature | Description |
|---|---|---|
| `read()` | `bool read(uint32_t pos, uint8_t* dst, uint32_t n) const noexcept` | Reads `n` bytes from absolute position `pos` into `dst`. Returns `false` if `dst` is null or the read range exceeds `len()`. |

### Views

| Method | Signature | Description |
|---|---|---|
| `begin()` | `uint8_t* begin() noexcept` / `const uint8_t* begin() const noexcept` | Raw pointer to the start of valid data (offset applied). |
| `end()` | `uint8_t* end() noexcept` / `const uint8_t* end() const noexcept` | Raw pointer past the last valid byte. |
| `at()` | `uint8_t* at(uint32_t pos) noexcept` / `const uint8_t* at(uint32_t pos) const noexcept` | Pointer at absolute offset `pos` within valid data. **No bounds check** — the caller must ensure `pos < len()`. |
| `span()` | `view_t span() noexcept` / `const_view_t span() const noexcept` | `std::span` view of valid bytes — for passing to checksum routines, `sendto()`, etc. |
| `subspan()` | `[[nodiscard]] const_view_t subspan(uint32_t pos, uint32_t n) const noexcept` | Sub-span from absolute position `pos` for `n` bytes, used by dissectors to hand a layer view to the next protocol without copying. Returns an empty span if out of range. |
| `owner()` | `[[nodiscard]] std::shared_ptr<uint8_t[]> owner() const noexcept` | Shared ownership handle — pass to `wrap()` for zero-copy layer views. |

### State

| Method | Signature | Description |
|---|---|---|
| `len()` | `uint32_t len() const noexcept` | Bytes written / valid. |
| `cap()` | `uint32_t cap() const noexcept` | Maximum bytes from `offset()`. |
| `offset()` | `uint32_t offset() const noexcept` | Byte offset within the underlying slab where this view starts. |
| `remaining()` | `uint32_t remaining() const noexcept` | `cap() - len()`. |
| `empty()` | `bool empty() const noexcept` | `true` if `len() == 0`. |
| `valid()` | `bool valid() const noexcept` | `true` if the buffer holds a non-null slab. |
| `reset()` | `void reset() noexcept` | Resets the write cursor (`len_ = 0`). Does not zero memory or reallocate. |

---

## 3. ProtocolBaseObject Class

Defined in: `include/lynx/core/proto_base.hpp`
Namespace: `lynx`
Inherits: `BaseObject`

`ProtocolBaseObject` is the root contract implemented by every concrete
protocol class in the library: all L2 `Frame` subclasses (`Ether`, `Dot1Q`,
`PPP`, `PPPoE`), all L3 `Packet` subclasses (`IPv4`, `IPv6`, `ARP`), all L4
`Segment` subclasses (`TCP`, `UDP`, `ICMP`, `ICMPv6`, `IGMP`, `SCTP`), and
`Raw`.

### Memory Model: Capture, Edit, Resend

When a packet is captured, every dissected layer's payload (`load_`) is a
**borrowed** span into the single receive buffer owned by the capture loop
(or by `RawFrame`, if one is held). No bytes are copied at dissection
time — this is what keeps capture cheap regardless of how many layers are
walked via `as<T>()`. Consequently, `load_` is only valid for as long as
that root buffer is alive — in practice, for the duration of the
`capture()` callback that produced it.

Editing a layer (`add_option()`, `set_message()`, or any similar mutator)
**never** writes through that borrowed view. Instead it allocates a fresh,
independently owned buffer, writes the new content into it, and re-points
the layer's `load_` at the new buffer. The bytes the old `load_` used to
reference are left completely untouched in the original slab — not freed,
not modified, not reused by that call. Their lifetime remains governed
entirely by whoever owns that slab (typically the capture loop), not by the
mutated object.

This is a deliberate design choice, not an oversight. An in-place editable
view would require every layer's bytes to live in disjoint, independently
sized regions — but they do not: `Eth.load_`, `IP.load_`, and `TCP.load_`
are all views over the *same* shared bytes at increasing offsets, not
separate allocations. If a layer with a differently sized header (e.g. ARP,
or IPv4 with options) were swapped in and written through an in-place view,
it would silently overwrite whatever sits immediately after it in the
slab — typically the next layer's header or payload — with no mechanism to
detect or prevent it. Allocating a new owned buffer on every edit removes
this hazard entirely: a layer can never corrupt memory another layer
believes it owns, regardless of how header sizes change across the edit.

**Practical consequence** — capture/edit/resend within one callback is
always safe and requires no special handling:

```cpp
iface.capture([&](const RawFrame& raw) {
    auto chap = ppp->as<CHAP>();
    chap->set_message(reply, reply_len);   // owned buffer, safe
    iface.send(*chap);                      // slab still alive here
    return RecvAction::Continue;
});
```

If a dissected object — or a resend of it — needs to be retained *outside*
the callback that produced it, the root slab may already have been reused
or freed by then, and any layer still borrowing from it (one on which no
mutator was called) would read stale or invalid memory. Call
`materialize()` before storing the object anywhere longer-lived:

```cpp
auto chap = ppp->as<CHAP>();
chap->materialize();      // copies load_ into owned storage now
stash_for_later(std::move(chap));
```

`materialize()` is a cheap no-op if `load_` is already owned (e.g. a
mutator has already been called on the object) — it only allocates when
`load_` is still a borrowed view.

### Pure Virtual Interface

| Method | Signature | Description |
|---|---|---|
| `serialize()` | `virtual void serialize(Buffer& buf) const noexcept = 0` | Serializes this layer (header + `load_`) into `buf` in wire format. |
| `dissect()` | `virtual void dissect(const uint8_t* data, uint32_t len) noexcept = 0` | Parses `data` (of length `len`) into this layer's header and `load_`. |
| `hdr_size()` | `[[nodiscard]] virtual uint32_t hdr_size() const noexcept = 0` | Returns the size, in bytes, of this layer's header on the wire. |
| `hdr()` | `[[nodiscard]] virtual void* hdr() noexcept = 0` | Returns a mutable pointer to the layer's header struct. Subclasses provide a covariant override returning their concrete header type pointer, e.g. `HdrTcp* hdr() noexcept override { return &hdr_; }`. |

### Concrete Methods

| Method | Signature | Description |
|---|---|---|
| `size()` | `[[nodiscard]] uint32_t size() const noexcept` | `hdr_size() + load().size()` — total serialized size of this layer including its payload. |
| `load()` | `[[nodiscard]] const_view_t load() const noexcept` | Returns the current payload view (`load_`). |
| `materialize()` | `void materialize() noexcept` | Promotes `load_` from a borrowed view into owned storage. See [Memory Model](#memory-model-capture-edit-resend) above. |
| `set_load()` | `void set_load(const_view_t payload) noexcept` | Copies `payload` into a freshly owned buffer and points `load_` at it. |
| `as<T>()` | `template<typename T> [[nodiscard]] std::unique_ptr<T> as() const noexcept` | Allocates a `T` and calls `T::dissect(load())` — a zero-copy span is passed down. Returns `nullptr` if the payload is empty, allocation fails, or dissection reports an error. `T` must derive from `ProtocolBaseObject`. |
| `operator/()` | `ProtocolBaseObject& operator/(ProtocolBaseObject& rhs) noexcept` | Crafting-path composition operator: `eth / ip / tcp`. Serializes `rhs` (recursively including `rhs`'s own payload) into a fresh `Buffer`, stores that buffer as this layer's `load_` via `set_load()`, and returns `*this` so calls can be chained left-to-right. `rhs.underlayer_` is set to `this` before serialization, and `rhs.patch_checksum()` is invoked prior to serialization. Changes made to an upper layer after this call do not propagate back into the already-serialized `load_`. |
| `patch_checksum()` | `virtual void patch_checksum() noexcept` | Called after full serialization to compute and patch this layer's checksum, if it has one. Default is a no-op; layers that require no checksum (`Ether`, `Dot1Q`, PPP subprotocols) do not override it. |
| `swap16() / swap32() / swap64()` | `[[nodiscard]] uintN_t swapN(uintN_t value) const noexcept` | Byte-order swap helpers, thin wrappers over `utils::bswap()`. |
| `memory_copy()` | `void memory_copy(void* dst, const void* src, size_t size) const noexcept` | Thin wrapper over `utils::mcopy()` (ultimately `std::memcpy`). |

### Protected Members

| Member | Type | Description |
|---|---|---|
| `load_` | `const_view_t` | Payload view — set when capturing packets (borrowed) or via `set_load()` / mutators (owned). |
| `load_buf_` | `Buffer` | Owned backing storage for `load_`, when owned. |
| `owned_load_` | `std::shared_ptr<uint8_t[]>` | Owned backing storage set by `set_load()` on the crafting path. |
| `underlayer_` | `ProtocolBaseObject*` | Pointer to the layer immediately beneath this one, set by `operator/()`. Used by checksum routines that need underlayer context (e.g. TCP/UDP pseudo-header checksums needing the enclosing `IPv4`/`IPv6`). |

---

## 4. Interface Class and Socket functions

### 4.1 Common Interface Methods

Defined in: `include/lynx/net/platform/linux/iface.hpp`
Namespace: `lynx::io`
Inherits: `BaseObject`

`Interface` binds to a network interface card (NIC) and owns the send /
capture lifecycle. The NIC operates at L2 — every send path ultimately
produces a complete Ethernet frame before invoking `sendto()`. Overloads
exist purely to spare the caller from manually constructing lower layers:

- `write(Ether)` — the frame is already complete; sent as-is.
- `write(Packet&)` (i.e. `IPv4`, `IPv6`, `ARP`) — `Interface` automatically
  prepends an `Ether` header and resolves source/destination MAC addresses.

`capture()` always delivers a complete raw frame to the callback as a
`RawFrame` — the caller extracts whichever layer it cares about via
`raw.as<T>()`.

This "Interface" concept is currently implemented for Linux only. See
[docs/platforms/linux.md](platforms/linux.md) for the Linux-specific
implementation details, and [docs/platforms/windows.md](platforms/windows.md)
/ [docs/platforms/macos.md](platforms/macos.md) for the status of other
platforms.

#### Construction and Lifecycle

| Method | Signature | Description |
|---|---|---|
| Constructor | `explicit Interface(const char* name) noexcept` | Constructs an interface bound (not yet opened) to the NIC named `name`, e.g. `"eth0"`. |
| Destructor | `~Interface() noexcept` | Behavior controlled by `LYNX_CLOSE_ON_DESTROY` (see [§4.3](#43-confighpp--compile-time-configuration)). When enabled (default), if the interface is open it removes promiscuous mode (if set) and closes the socket file descriptor. |
| `open()` | `void open() noexcept` | Creates the raw socket, resolves the interface index, binds to it, and applies all tuning options queued before `open()` was called. Sets `Status::IfaceAlreadyOpen` if already open. |
| `close()` | `void close() noexcept` | Removes promiscuous mode if active, then closes the file descriptor. Safe to call multiple times. |
| `is_open()` | `[[nodiscard]] bool is_open() const noexcept` | `true` if the underlying file descriptor is valid. |
| Move constructor | `Interface(Interface&& o) noexcept` | `Interface` is movable but **not copyable** (it owns a file descriptor). |

#### Tuning

The following tuning methods can be called either before or after `open()`.
If called before `open()`, the option is stored and applied at `open()`
time. If called after `open()`, the option is applied to the live socket
immediately.

| Method | Signature | Description |
|---|---|---|
| `set_promiscuous()` | `void set_promiscuous(bool enable) noexcept` | Enables or disables promiscuous mode on the bound interface. |
| `set_snaplen()` | `void set_snaplen(int bytes) noexcept` | Sets the maximum number of bytes captured per frame. Must be `> 0`. |
| `set_timeout()` | `void set_timeout(int ms) noexcept` | Sets how often (in milliseconds) the blocking `recvfrom()` call wakes to check the stop flag. Must be `>= 0`. |
| `set_direction()` | `void set_direction(sock::Direction dir) noexcept` | Filters which frame directions are delivered (`In`, `Out`, `Both`). |
| `set_buffer_size()` | `void set_buffer_size(int bytes) noexcept` | Sets the kernel-side socket receive buffer size in bytes. `0` uses the kernel default. Must be `>= 0`. |

#### Send

| Method | Signature | Description |
|---|---|---|
| `write(Frame)` | `void write(const proto::Frame& frame) noexcept` | Sends a complete L2 frame as-is — no MAC resolution is performed. |
| `write(Packet&)` | `void write(proto::Packet& pkt) noexcept` | Sends any L3 `Packet` (`IPv4`, `IPv6`, `ARP`). `Interface` automatically prepends an `Ether` header, chooses the ethertype and destination MAC per the policy driven by the `Packet`'s own virtuals (`ethertype()`, `dst()`, `is_broadcast()`), and resolves the source MAC per `LYNX_SRC_MAC_POLICY`. |

#### Capture

| Method | Signature | Description |
|---|---|---|
| `capture()` | `void capture(capture_callback_t cb) noexcept` | Runs a blocking receive loop, reusing a single `Buffer` allocation across iterations. On each iteration it wraps the received bytes in a `RawFrame` and invokes `cb`. The loop exits when `cb` returns `RecvAction::Stop`, when `stop()` has been called from another thread, or on a hard receive error. |
| `stop()` | `void stop() noexcept` | Thread-safe: signals the capture loop to exit on its next timeout tick. |

`RecvAction` (defined in `lynx::io`):

| Value | Meaning |
|---|---|
| `RecvAction::Continue` | Keep looping. |
| `RecvAction::Stop` | Exit the receive loop cleanly. |

#### Accessors

| Method | Signature | Description |
|---|---|---|
| `name()` | `[[nodiscard]] const char* name() const noexcept` | The interface name passed to the constructor. |
| `fd()` | `[[nodiscard]] int fd() const noexcept` | The underlying raw socket file descriptor. |
| `ifindex()` | `[[nodiscard]] int ifindex() const noexcept` | The kernel interface index resolved at `open()`. |

### 4.2 Platform APIs

`Interface` is implemented on top of a small set of free, stateless socket
helper functions per supported platform. Each platform exposes its own
concrete implementation of these primitives.

| Platform | Status | Document |
|---|---|---|
| Linux | Supported (`AF_PACKET`, kernel 3.x+) | [platforms/linux.md](platforms/linux.md) |
| Windows | Not implemented — planned for v1 | [platforms/windows.md](platforms/windows.md) |
| macOS | Not implemented — planned for v1 | [platforms/macos.md](platforms/macos.md) |

The platform selection is performed at compile time in
`include/lynx/net/io.hpp`:

```cpp
#if defined(__linux__)
    #include "./platform/linux/iface.hpp"
    #include "./platform/linux/socket.hpp"
#else
    #error "lynx::io is only supported on Linux for now"
#endif
```

### 4.3 config.hpp — compile-time configuration

Defined in: `include/lynx/config.hpp`

All configuration is performed via preprocessor defines, edited before
including `lynx/lynx`. Every define is resolved at compile time, so there is
zero runtime overhead associated with any of these policies.

| Define | Default | Values | Description |
|---|---|---|---|
| `LYNX_DST_MAC_POLICY` | `2` | `1` = `BROADCAST`, `2` = `ARP_LOOKUP` | Controls how `send(Packet)` / `send(Segment)` resolves the destination MAC when no `Ether` frame is provided. `BROADCAST` always uses `ff:ff:ff:ff:ff:ff` (safe fallback, no ARP needed — suitable for discovery, testing, fuzzing). `ARP_LOOKUP` resolves the destination MAC from the destination IP via the kernel ARP cache (`SIOCGARP`); if the IP is not cached, the send fails with `Status::ArpResolveFail` (suitable for normal unicast traffic). |
| `LYNX_SRC_MAC_POLICY` | `1` | `1` = `IFACE_MAC`, `2` = `RANDOM_MAC` | Controls what is placed in the Ethernet source field when `Interface` auto-wraps a `Packet` or `Segment` in an `Ether` frame. `IFACE_MAC` uses the real hardware MAC of the bound interface (`SIOCGIFHWADDR`) — the default, most compatible option. `RANDOM_MAC` generates a random, locally administered, unicast MAC per packet (bit 1 of the first octet set, bit 0 cleared) — useful for anonymization, spoofing tests, or red-team tooling. |
| `LYNX_MANUAL_SRC_MAC` | `{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }` | 6 comma-separated hex bytes | Reserved for a future fixed-MAC policy (policy value `3`), not yet implemented. |
| `LYNX_ETHERTYPE_POLICY` | `1` | `1` = `AUTO`, `2` = `MANUAL` | Controls how `Interface` determines the ethertype field when wrapping a `Packet` in an `EtherFrame`. `AUTO` detects it from the `Packet` subtype at serialize time (`IPv4Packet` → `0x0800`, `IPv6Packet` → `0x86DD`, `ARPPacket` → `0x0806`). `MANUAL` uses `LYNX_MANUAL_ETHERTYPE` for all packets. |
| `LYNX_MANUAL_ETHERTYPE` | `0x0800` | any `uint16_t` | The ethertype used when `LYNX_ETHERTYPE_POLICY == 2`. |
| `LYNX_RECV_BUFFER_SIZE` | `0` | any non-negative integer (bytes) | Size of the kernel-side socket receive buffer. Larger values reduce drops under high traffic at the cost of more kernel memory. `0` uses the kernel default (typically 212992 bytes). |
| `LYNX_DEFAULT_SNAPLEN` | `65535` | any positive integer (bytes) | Maximum bytes captured per frame. `65535` captures full frames, including jumbo frames; lower values reduce per-packet copy cost if only headers are needed. |
| `LYNX_DEFAULT_TIMEOUT_MS` | `100` | any non-negative integer (ms) | How often the blocking `recvfrom()` call wakes up to check the stop flag. Lower values make `stop()` more responsive; higher values reduce spurious wakeups. |
| `LYNX_CLOSE_ON_DESTROY` | `1` | `1` or `0` | `1` closes the socket in the `Interface` destructor (safe default, prevents file-descriptor leaks). `0` leaves the socket open on destruction — use when `Interface` lifetime is managed manually or the object lives in shared state beyond a single scope. |
| `LYNX_INHERITANCE_POLICY` | `final` | `final` or empty | Controls whether concrete protocol classes (`Ether`, `IPv4`, `TCP`, etc.) are marked `final`. Base classes are not affected. To allow further subclassing of concrete protocol classes, redefine this macro to expand to nothing. |

Example — editing `config.hpp` before including the master header:

```cpp
// MAC resolution when Interface auto-wraps a Packet in Ether
#define LYNX_DST_MAC_POLICY  2   // 1=broadcast  2=ARP lookup
#define LYNX_SRC_MAC_POLICY  1   // 1=iface MAC  2=random per packet

// close socket in Interface destructor
#define LYNX_CLOSE_ON_DESTROY  1

// recv defaults
#define LYNX_DEFAULT_SNAPLEN      65535
#define LYNX_DEFAULT_TIMEOUT_MS   100
#define LYNX_RECV_BUFFER_SIZE     0     // 0 = kernel default
```

---

## 5. Utils

Defined in: `include/lynx/core/utils.hpp` (namespace `lynx::utils`), with
supporting value types defined directly under `lynx::`.

### Value Types

| Type | Definition | Description |
|---|---|---|
| `hr_mac` | `struct { char data[18]; }` | Human-readable MAC address string (e.g. `"aa:bb:cc:dd:ee:ff"`, null-terminated). |
| `mn_mac` | `struct { uint8_t data[6]; }` | Machine/numeric (binary) MAC address. |
| `hr_ipv4` | `struct { char data[16]; }` | Human-readable dotted-decimal IPv4 address string. |
| `mn_ipv4` | `struct { uint8_t data[4]; }` | Machine/numeric (binary) IPv4 address. |
| `hr_ipv6` | `struct { char data[40]; }` | Human-readable colon-hex IPv6 address string. |
| `mn_ipv6` | `struct { uint8_t data[16]; }` | Machine/numeric (binary) IPv6 address. |

### Checksum Functions

| Function | Signature | Description |
|---|---|---|
| `inet_checksum()` | `uint16_t inet_checksum(const uint8_t* data, size_t len)` | Computes the RFC 1071 Internet checksum (one's-complement sum) over `data`. Used by IPv4, TCP, UDP, ICMP, ICMPv6, and IGMP. |
| `inet_checksum()` (span overload) | `[[nodiscard]] inline uint16_t inet_checksum(const_view_t data) noexcept` | Overload accepting a `std::span`. |
| `crc32c()` | `[[nodiscard]] inline uint32_t crc32c(const uint8_t* data, uint32_t len) noexcept` | Computes a CRC-32c checksum (Castagnoli polynomial `0x1EDC6F41`) over `data`, using a precomputed 256-entry lookup table. Used exclusively by `SCTP::patch_checksum()` — this is **not** related to `inet_checksum()`, which implements the different RFC 1071 algorithm. |

### Address Encode / Decode

| Function | Signature | Description |
|---|---|---|
| `mac_encode()` | `[[nodiscard]] inline hr_mac mac_encode(const uint8_t mac[6]) noexcept` | Encodes a 6-byte MAC into its colon-separated hexadecimal string form. |
| `mac_decode()` | `[[nodiscard]] inline mn_mac mac_decode(const char* s) noexcept` | Parses a colon- or hyphen-separated hexadecimal MAC string into 6 bytes. Returns an all-zero `mn_mac` on parse failure. |
| `ipv4_encode()` | `[[nodiscard]] inline hr_ipv4 ipv4_encode(const uint8_t ip[4]) noexcept` | Encodes a 4-byte IPv4 address into dotted-decimal string form. |
| `ipv4_decode()` | `[[nodiscard]] inline mn_ipv4 ipv4_decode(const char* s) noexcept` | Parses a dotted-decimal IPv4 address string into 4 bytes. Returns an all-zero `mn_ipv4` on parse failure. |
| `ipv6_encode()` | `[[nodiscard]] inline hr_ipv6 ipv6_encode(const uint8_t ip[16]) noexcept` | Encodes a 16-byte IPv6 address into its colon-hexadecimal string form (fully expanded, not compressed). |
| `ipv6_decode()` | `[[nodiscard]] inline mn_ipv6 ipv6_decode(const char* s) noexcept` | Parses a fully expanded colon-hexadecimal IPv6 address string into 16 bytes. Returns an all-zero `mn_ipv6` on parse failure. |
| `ipv6_from_mac()` | `[[nodiscard]] inline mn_ipv6 ipv6_from_mac(const uint8_t mac[6]) noexcept` | Derives a modified EUI-64 interface identifier from a 6-byte MAC address, for constructing IPv6 link-local addresses. |

### Randomization

| Function | Signature | Description |
|---|---|---|
| `buf_randomize()` | `[[nodiscard]] inline std::span<uint8_t> buf_randomize(uint8_t* buf, size_t len) noexcept` | Fills `buf` with `len` pseudo-random bytes (via `std::rand()`) and returns a span over it. Used, for example, to generate randomized source MAC addresses in the bundled examples. |

### Byte Order and Memory

| Function | Signature | Description |
|---|---|---|
| `bswap<T>()` | `template<typename T> requires std::unsigned_integral<T> [[nodiscard]] static constexpr T bswap(T value) noexcept` | Byte-swaps an unsigned integer of any width via `std::byteswap`. Compiles to a single `bswap` / `rev` instruction on x86 / ARM. Used throughout the protocol layers in place of `__builtin_bswap*` (see [CHANGELOG](README.md#6-changelog)). |
| `mcopy()` | `static void mcopy(void* dst, const void* src, size_t size) noexcept` | Thin wrapper over `std::memcpy`, kept for symmetry with the rest of the `utils` namespace — compilers inline it to a single move or `rep movsb` regardless of whether `memcpy` is called directly. |

### Usage Example

```cpp
auto encoded = utils::mac_encode(mac);       // hr_mac — human readable
std::string s(encoded.data);

auto decoded = utils::mac_decode("aa:bb:cc:dd:ee:ff");  // mn_mac — binary
std::memcpy(dst_mac, decoded.data, 6);

auto ip_encoded = utils::ipv4_encode(ip_bytes);
auto ip_decoded = utils::ipv4_decode("192.168.1.1");
```

---

## 6. Protocols Classes

The following table summarizes every concrete protocol class in the
library, its OSI layer, and its checksum behavior. Each entry links to its
dedicated protocol reference document under [protocols/](protocols).

| Class | Layer | Checksum | Reference |
|---|---|---|---|
| `Ether` | L2 | none (FCS appended by the NIC) | [protocols/ethernet.md](protocols/ethernet.md) |
| `Dot1Q` | L2 | none | [protocols/dot1q.md](protocols/dot1q.md) |
| `PPP` | L2 | none (FCS handled at serial/modem level) | [protocols/ppp.md](protocols/ppp.md) |
| `PPPoE` | L2 | none | [protocols/pppoe.md](protocols/pppoe.md) |
| `LCP` | L2 (PPP subprotocol) | none | [protocols/ppp.md](protocols/ppp.md#lcp--link-control-protocol) |
| `PAP` | L2 (PPP subprotocol) | none | [protocols/ppp.md](protocols/ppp.md#pap--password-authentication-protocol) |
| `CHAP` | L2 (PPP subprotocol) | none | [protocols/ppp.md](protocols/ppp.md#chap--challenge-handshake-authentication-protocol) |
| `IPCP` | L2 (PPP NCP subprotocol) | none | [protocols/ppp.md](protocols/ppp.md#ipcp--ip-control-protocol) |
| `IPv6CP` | L2 (PPP NCP subprotocol) | none | [protocols/ppp.md](protocols/ppp.md#ipv6cp--ipv6-control-protocol) |
| `ARP` | L3 | none | [protocols/arp.md](protocols/arp.md) |
| `IPv4` | L3 | header checksum | [protocols/ipv4.md](protocols/ipv4.md) |
| `IPv6` | L3 | none (removed in RFC 2460) | [protocols/ipv6.md](protocols/ipv6.md) |
| `TCP` | L4 | pseudo-header (IPv4 or IPv6) | [protocols/tcp.md](protocols/tcp.md) |
| `UDP` | L4 | pseudo-header (IPv4 or IPv6) | [protocols/udp.md](protocols/udp.md) |
| `ICMP` | L4 | header + data | [protocols/icmp.md](protocols/icmp.md) |
| `ICMPv6` | L4 | pseudo-header (IPv6) | [protocols/icmpv6.md](protocols/icmpv6.md) |
| `IGMP` | L4 | header only | [protocols/igmp.md](protocols/igmp.md) |
| `SCTP` | L4 | CRC-32c over entire packet | [protocols/sctp.md](protocols/sctp.md) |
| `Raw` | any | none | [protocols/raw.md](protocols/raw.md) |

### Common Base Classes

Every protocol class ultimately derives from `ProtocolBaseObject`
(see [§3](#3-protocolbaseobject-class)), by way of one of three
layer-specific intermediate base classes:

| Base Class | Defined In | Layer | Description |
|---|---|---|---|
| `Frame` | `include/lynx/protocols/l2/frame.hpp` | L2 | Base for `Ether`, `Dot1Q`, `PPP`, `PPPoE`. Adds `type()`, returning a `FrameType` enumerator. |
| `Packet` | `include/lynx/protocols/l3/packet.hpp` | L3 | Base for `IPv4`, `IPv6`, `ARP`. Adds `ethertype()`, `dst()`, and `is_broadcast()`. |
| `Segment` | `include/lynx/protocols/l4/segment.hpp` | L4 | Base for `TCP`, `UDP`, `ICMP`, `ICMPv6`, `IGMP`, `SCTP`. Adds `proto()`, the IP protocol number used to select the checksum algorithm. |

`RawFrame` (also in `include/lynx/protocols/l2/frame.hpp`) is a distinct,
lightweight class — it is **not** a `Frame` or `ProtocolBaseObject`
subclass. It is a pure byte carrier and type classifier: the object passed
by `Interface::capture()` to the user callback. See
[protocols/ethernet.md § RawFrame](protocols/ethernet.md#rawframe) for
details.

`FrameType` (namespace `lynx::proto`) values:

| Value | Meaning |
|---|---|
| `FrameType::Unknown` | Frame type could not be classified. |
| `FrameType::Eth` | Standard Ethernet II. |
| `FrameType::Dot1Q` | 802.1Q VLAN-tagged (ethertype `0x8100`). |
| `FrameType::PPPoE` | PPP over Ethernet (ethertype `0x8863` / `0x8864`). |
| `FrameType::PPP` | Point-to-Point Protocol (carried inside PPPoE or raw). |

For the individual protocol classes, see the dedicated documents linked in
the table above. Each protocol document covers:

- The applicable RFC(s), where one exists.
- The wire header layout.
- Constructors and construction defaults.
- Serialization / dissection behavior, including any header-specific quirks
  (compression, variable-length options, checksum algorithm).
- Constants relevant to the protocol.
- A crafting and/or dissection code example.

# lynx — Documentation

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1 Overview](#11-overview)
  - [1.2 Purpose and Inspiration](#12-purpose-and-inspiration)
- [2. Getting Started](#2-getting-started)
  - [2.1 Prerequisites and Dependencies](#21-prerequisites-and-dependencies)
  - [2.2 Installation](#22-installation)
  - [2.3 Quick Start](#23-quick-start)
- [3. Usage](#3-usage)
  - [3.1 Basic Usage Examples](#31-basic-usage-examples)
  - [3.2 Command-Line Options and Flags](#32-command-line-options-and-flags)
- [4. Further Documentation](#4-further-documentation)
- [5. Versioning](#5-versioning)
- [6. Changelog](#6-changelog)

---

## 1. Introduction

### 1.1 Overview

`lynx` is a header-only, Linux-first C++17 library for packet capture and
packet crafting. It provides object-oriented representations of common
network protocols across the data-link (L2), network (L3), and transport
(L4) layers, and exposes a raw-socket (`AF_PACKET`) based interface for
sending and receiving Ethernet frames on Linux.

Core design characteristics of the library:

- **Header-only** — the entire library is distributed as C++ header files
  under `include/lynx`; no separate compilation or linking step is required
  beyond including the master header.
- **Zero-copy dissection** — when a frame is captured, every protocol layer
  that is subsequently parsed via `as<T>()` shares a view into the single
  receive buffer allocated for that capture iteration. No layer copies bytes
  during dissection.
- **Mutable header access after dissection** — once a layer has been
  dissected, its header fields can be read and modified directly, enabling
  capture-edit-resend workflows.
- **Lazy layer parsing** — a layer is only parsed when the caller explicitly
  requests it via `as<T>()`; unrequested layers are never touched.
- **Compile-time configuration** — behavioral policies (MAC resolution,
  destructor semantics, buffer sizes, timeouts) are controlled via
  preprocessor defines in `config.hpp`, incurring no runtime overhead.
- **No exceptions** — every class that can fail derives from `BaseObject`
  and reports failures through an explicit error-state mechanism
  (see [ERRORS.md](API.md) and [ERRORS.md](ERRORS.md)) rather than through
  C++ exceptions or return codes.

### 1.2 Purpose and Inspiration

`lynx` is inspired by [Scapy](https://scapy.net/), the Python packet
manipulation library, and aims to bring a similar packet-crafting ergonomic
model (`layer1 / layer2 / layer3` composition) to a statically typed,
header-only C++ library suitable for use in performance-sensitive or
resource-constrained environments where a Python runtime is undesirable.

The library's stated goal is to provide a single small toolset for both
capturing and crafting raw Ethernet frames, without requiring the caller to
manage byte offsets, byte-order conversions, or checksum computations by
hand.

---

## 2. Getting Started

### 2.1 Prerequisites and Dependencies

`lynx` currently targets Linux exclusively. Building or using the library
requires:

| Requirement | Detail |
|---|---|
| Operating system | Linux (kernel 3.x or later — for `AF_PACKET` support) |
| Language standard | C++17 |
| Compiler | GCC or Clang (any release supporting C++17 and `std::span`) |
| Privileges | `root`, or the `CAP_NET_RAW` capability, to open raw sockets |

The library depends only on the C++ standard library. The only standard
library components used internally are `std::shared_ptr`, `std::span`, and a
small number of `<cstdint>` / `<cstring>` facilities — see
[API.md](API.md#5-utils) for details on internal dependencies.

Windows and macOS are not currently supported. See
[docs/platforms/windows.md](platforms/windows.md) and
[docs/platforms/macos.md](platforms/macos.md) for their current status.

### 2.2 Installation

`lynx` is header-only. There is no build step to install the library itself:

1. Clone or download the repository.
2. Add the `include/` directory of the repository to your compiler's include
   path (e.g. `-Iinclude` for GCC/Clang).
3. `#include <lynx/lynx>` in your source files.

Example compilation of one of the bundled examples:

```sh
g++ -std=c++17 -Iinclude src/examples/capture.cpp -o capture
sudo ./capture eth0
```

Because raw sockets require elevated privileges, any binary that opens an
`Interface` (see [API.md § Interface Class and Socket functions](API.md#4-interface-class-and-socket-functions))
must be run as `root` or granted `CAP_NET_RAW`:

```sh
sudo setcap cap_net_raw+ep ./capture
./capture eth0
```

### 2.3 Quick Start

```cpp
#include <lynx/lynx>

using namespace lynx;

Interface iface("eth0");
iface.set_promiscuous(true);
iface.open();

// craft and send
IPv4 ip;
__builtin_memcpy(ip.hdr()->dst_ip, dst, 4);
ip.hdr()->proto = constants::IP_PROTO_TCP;

TCP tcp;
tcp.hdr()->dst_port = 80;
tcp.hdr()->flags    = constants::TCP_FLAG_SYN;

ip / tcp;
iface.send(ip);

// capture
iface.capture([](const RawFrame& raw) {
    if (raw.type() == FrameType::Eth) {
        auto eth = raw.as<Ether>();
        auto ip  = eth->as<IPv4>();
        auto tcp = ip->as<TCP>();
        // ...
    }
    return RecvAction::Continue;
});
```

---

## 3. Usage

### 3.1 Basic Usage Examples

#### Opening and Tuning an Interface

```cpp
Interface iface("eth0");

// tuning — call before or after open()
iface.set_promiscuous(true);
iface.set_snaplen(65535);
iface.set_timeout(100);           // ms — how often recv checks the stop flag
iface.set_direction(sock::Direction::Both);
iface.set_buffer_size(0);         // 0 = kernel default

iface.open();
if (!iface.ok()) { /* iface.errmsg() */ }

iface.close();                    // removes promiscuous mode, closes the fd
iface.stop();                     // signals the recv loop to exit (thread-safe)
```

#### Crafting a Packet

Every protocol object provides sensible defaults; only fields that must
differ from the default need to be set explicitly.

```cpp
// L2
Ether eth;
__builtin_memcpy(eth.hdr()->dst_mac, dst_mac, 6);
eth.hdr()->ethertype = constants::ETH_TYPE_IPV4;

// L3
IPv4 ip;
ip.hdr()->ttl   = 64;
ip.hdr()->proto = constants::IP_PROTO_TCP;
__builtin_memcpy(ip.hdr()->src_ip, src, 4);
__builtin_memcpy(ip.hdr()->dst_ip, dst, 4);

// L4
TCP tcp;
tcp.hdr()->src_port = 12345;
tcp.hdr()->dst_port = 80;
tcp.hdr()->flags    = constants::TCP_FLAG_SYN;
tcp.hdr()->window   = 65535;
tcp.hdr()->seq      = 1000;

// payload
const uint8_t data[] = "GET / HTTP/1.1\r\n\r\n";
Raw payload(data, sizeof(data) - 1);

// chain — right to left, each layer serializes the next as its load
ip / tcp / payload;
iface.send(ip);             // Interface prepends Ether, resolves MACs
```

Checksums (IP header checksum, TCP/UDP pseudo-header checksum, etc.) are
computed automatically immediately before a packet is sent — see
[API.md § ProtocolBaseObject Class](API.md#3-protocolbaseobject-class) for
the mechanism (`operator/` and `patch_checksum()`).

To send a complete L2 frame with no MAC resolution performed by the
library:

```cpp
eth / ip / tcp / payload;
iface.send(eth);
```

#### Capturing Packets

`capture()` runs a blocking loop that invokes a user-supplied callback for
every received frame. Call `iface.stop()` from another thread to exit the
loop.

```cpp
iface.capture([](const RawFrame& raw) -> RecvAction {

    if (raw.type() != FrameType::Eth)
        return RecvAction::Continue;

    auto eth = raw.as<Ether>();
    if (!eth || !eth->ok()) return RecvAction::Continue;

    auto ip = eth->as<IPv4>();
    if (!ip  || !ip->ok())  return RecvAction::Continue;

    if (ip->hdr()->proto == constants::IP_PROTO_TCP) {
        auto tcp = ip->as<TCP>();
        if (tcp && tcp->ok()) {
            // tcp->hdr()->src_port, dst_port, flags ...
            // tcp->load() — application data span
        }
    }

    return RecvAction::Continue;
});
```

`RawFrame` owns the captured raw bytes. `as<T>()` allocates a typed layer
object and calls `dissect()` on it — the operation is zero-copy: the new
object views the same underlying memory as its parent. Every object
returned by `as<T>()` is a `std::unique_ptr<T>`, so no manual memory
management is required.

After `dissect()`, all header fields are stored in host byte order and can
be compared directly against constants defined under `lynx::constants::`:

```cpp
if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV4) { ... }
if (tcp->hdr()->flags & constants::TCP_FLAG_SYN)       { ... }
```

### 3.2 Command-Line Options and Flags

`lynx` is a library, not a standalone executable, and therefore defines no
command-line interface of its own. The bundled example programs under
`src/examples/` accept a single optional command-line argument: the name of
the network interface to bind to. If omitted, the examples default to
`wlan0`.

```sh
./capture eth0     # capture on eth0
./capture           # capture on wlan0 (default)
```

All library behavior that would otherwise be exposed as command-line flags
is instead controlled at compile time through `config.hpp`. See
[API.md § Interface Class and Socket functions](API.md#4-interface-class-and-socket-functions)
for the full list of compile-time configuration knobs.

---

## 4. Further Documentation

| Document | Contents |
|---|---|
| [API.md](API.md) | Full API reference: `BaseObject`, `ProtocolBaseObject`, all protocol classes, `Interface`/socket functions, `utils`, `Buffer` |
| [ERRORS.md](ERRORS.md) | Complete list of error codes (`Status`) and error-handling conventions |
| [protocols/](protocols) | Per-protocol reference documentation, one file per protocol |
| [platforms/](platforms) | Per-platform I/O reference documentation |

---

## 5. Versioning

**v0 (current)** — packet capture, packet crafting, send/recv, L2–L4
protocol support, `AF_PACKET`-based I/O on Linux.

**v1 (planned)** — extended protocol coverage, support for additional
platforms/operating systems (see [platforms/windows.md](platforms/windows.md)
and [platforms/macos.md](platforms/macos.md)).

---

## 6. Changelog

### Changed

- Replaced `__builtin_bswap` with `utils::bswap` to avoid compiler-specific
  intrinsics.
- Updated test cases.
- Updated project architecture.

### Added

> The following protocols have not been extensively tested in this release
> and are provided as-is.

- PPP with its subprotocols (LCP, PAP, CHAP, IPCP, IPv6CP)
- PPPoE
- SCTP

# Platform: Windows

## Table of Contents

- [1. Status](#1-status)
- [2. Current Behavior](#2-current-behavior)
- [3. Planned Implementation](#3-planned-implementation)

---

## 1. Status

**Not implemented.** Windows support is planned for a future release (see
[README.md § Versioning](../README.md#5-versioning)) but no code exists
for it in the current version of the repository.

## 2. Current Behavior

Platform selection is performed at compile time in
`include/lynx/net/io.hpp`:

```cpp
#if defined(__linux__)
    #include "./platform/linux/iface.hpp"
    #include "./platform/linux/socket.hpp"
#else
    #error "lynx::io is only supported on Linux for now"
#endif
```

Attempting to compile any translation unit that includes
`<lynx/lynx>` (which unconditionally includes `net/io.hpp`) on a
non-Linux target — including Windows, where `__linux__` is not defined —
will fail at the `#error` directive above, with the message
`"lynx::io is only supported on Linux for now"`.

The protocol-dissection and packet-crafting layers documented in
[protocols/](.) and [API.md](../API.md) (`Ether`, `IPv4`, `TCP`, `Buffer`,
`ProtocolBaseObject`, etc.) do not themselves depend on any
platform-specific headers and could, in principle, be used on Windows in
isolation — but the master header `<lynx/lynx>` pulls in `net/io.hpp`
unconditionally, so the library as a whole does not currently build on
Windows without modification.

## 3. Planned Implementation

No Windows-specific socket layer (`include/lynx/net/platform/windows/`)
exists yet. Based on the architecture of the existing
[Linux implementation](linux.md), a future Windows backend would be
expected to:

- Implement the same `lynx::sock::*` free-function surface described in
  [linux.md § 5. Socket Primitives](linux.md#5-socket-primitives-lynxsock),
  most likely via the Win32 raw-socket / [Npcap](https://npcap.com/)
  driver stack, since standard Winsock does not expose `AF_PACKET`-style
  raw Ethernet capture.
- Implement a `lynx::io::Interface` with the same public surface
  documented in
  [API.md § 4.1 Common Interface Methods](../API.md#41-common-interface-methods),
  so that code written against `Interface` remains portable across
  platforms without modification.
- Be selected via an additional `#elif defined(_WIN32)` branch in
  `include/lynx/net/io.hpp`.

Until this work lands, Windows users wishing to use `lynx` for packet
capture/crafting today would need to do so inside a Linux environment
(e.g. WSL2), where the existing [Linux backend](linux.md) applies
directly.

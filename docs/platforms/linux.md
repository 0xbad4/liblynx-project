# Platform: Linux

## Table of Contents

- [1. Reference](#1-reference)
- [2. Status](#2-status)
- [3. Requirements](#3-requirements)
- [4. Architecture](#4-architecture)
- [5. Socket Primitives (`lynx::sock`)](#5-socket-primitives-lynxsock)
- [6. Interface Implementation Notes](#6-interface-implementation-notes)
- [7. Example](#7-example)

---

## 1. Reference

- Defined in: `include/lynx/net/platform/linux/iface.hpp`
  (`lynx::io::Interface`), `include/lynx/net/platform/linux/socket.hpp`
  (`lynx::sock::*`)
- Selected at compile time by `include/lynx/net/io.hpp` when
  `defined(__linux__)`.

## 2. Status

**Supported.** This is currently the only platform `lynx` implements. See
[windows.md](windows.md) and [macos.md](macos.md) for the status of other
platforms.

## 3. Requirements

| Requirement | Detail |
|---|---|
| Kernel | Linux 3.x or later (for `AF_PACKET` / `PACKET_IGNORE_OUTGOING` support) |
| Privileges | `root`, or the `CAP_NET_RAW` capability |
| Headers used | `<sys/socket.h>`, `<sys/ioctl.h>`, `<linux/if_packet.h>`, `<linux/if_ether.h>`, `<net/if.h>`, `<arpa/inet.h>`, `<netinet/in.h>`, `<net/if_arp.h>` |

## 4. Architecture

The Linux implementation is split into two files with a clear separation
of concerns:

- **`socket.hpp`** — a set of free, stateless functions (namespace
  `lynx::sock`) wrapping individual Linux syscalls / ioctls. Every
  function returns an `Error` value directly (see
  [ERRORS.md § Errors Returned by Free Functions](../ERRORS.md#errors-returned-by-free-functions))
  rather than participating in the `BaseObject` error-state model — they
  have no class, no vtable, and no state of their own.
- **`iface.hpp`** — `lynx::io::Interface`, a stateful `BaseObject`
  subclass that owns a file descriptor and composes the `sock::*`
  primitives into the full open/tune/send/capture/close lifecycle
  documented in [API.md § Interface Class and Socket
  functions](../API.md#4-interface-class-and-socket-functions).

All raw I/O is performed over a single `AF_PACKET` / `SOCK_RAW` socket,
bound to one interface, capturing every ethertype (`ETH_P_ALL`).

## 5. Socket Primitives (`lynx::sock`)

Every function below is `[[nodiscard]]`, `noexcept`, and returns an
`Error` (see [ERRORS.md § The Error Type](../ERRORS.md#2-the-error-type)).

| Function | Signature | Underlying syscall/ioctl | Description |
|---|---|---|---|
| `open_raw()` | `Error open_raw(int& fd)` | `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` | Creates a raw socket that captures all ethertypes. Writes `INVALID_FD` (`-1`) into `fd` on failure. Error: `Status::SocketCreateFail`. |
| `resolve_ifindex()` | `Error resolve_ifindex(const char* name, int& idx)` | `if_nametoindex()` | Maps an interface name to its kernel interface index. Writes `INVALID_IDX` (`-1`) into `idx` on failure. Error: `Status::IfaceNotFound`. |
| `bind_to_iface()` | `Error bind_to_iface(int fd, int ifindex)` | `bind()` on an `AF_PACKET` `sockaddr_ll` | Binds the socket to a specific interface index so only its frames are received. Error: `Status::SocketBindFail`. |
| `set_promiscuous()` | `Error set_promiscuous(int fd, int ifindex, bool enable)` | `setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP \| PACKET_DROP_MEMBERSHIP)` with `PACKET_MR_PROMISC` | Enters or leaves promiscuous mode. **Always call with `enable=false` before closing**, to clean up NIC state. Error: `Status::SocketOptionFail`. |
| `set_recv_timeout()` | `Error set_recv_timeout(int fd, int timeout_ms)` | `setsockopt(SOL_SOCKET, SO_RCVTIMEO)` | Sets how often the blocking `recvfrom()` wakes to check the stop flag. `timeout_ms = 0` makes `recvfrom()` block indefinitely (not recommended — `stop()` would be unresponsive). Error: `Status::SocketOptionFail`. |
| `set_recv_buffer()` | `Error set_recv_buffer(int fd, int size_bytes)` | `setsockopt(SOL_SOCKET, SO_RCVBUF)` | Sets the kernel-side receive ring buffer size. `size_bytes = 0` leaves the kernel default in place and returns success immediately without a syscall. Error: `Status::SocketOptionFail`. |
| `set_direction()` | `Error set_direction(int fd, Direction dir)` | `setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING)` | `Direction::In` sets `PACKET_IGNORE_OUTGOING=1` (drops outgoing frames at the kernel level). `Direction::Out` performs no kernel-side filtering — outgoing-only filtering must be done by the caller in the recv loop based on `sll_pkttype`. `Direction::Both` (default) sets `PACKET_IGNORE_OUTGOING=0`. Error: `Status::SocketOptionFail`. |
| `get_iface_mac()` | `Error get_iface_mac(int fd, const char* name, uint8_t out_mac[6])` | `ioctl(SIOCGIFHWADDR)` | Reads the hardware MAC address of the named interface. Error: `Status::MacResolveFail`. |
| `arp_lookup()` | `Error arp_lookup(int fd, const char* iface, const uint8_t dst_ip[4], uint8_t out_mac[6])` | `ioctl(SIOCGARP)` | Queries the **kernel ARP cache** (no packets are sent — this is a pure cache lookup) for `dst_ip`, scoped to `iface` to avoid cross-interface hits. Fails with `Status::ArpResolveFail` if the entry is absent from the cache, or if present but incomplete (`ATF_COM` flag not set, meaning the kernel has sent an ARP request but not yet received a reply). Active ARP probing (send request, wait for reply) is noted in the source as a planned v1 feature. |
| `randomize_mac()` | `Error randomize_mac(uint8_t out_mac[6])` | reads `/dev/urandom` | Generates a random, locally administered, unicast MAC (bit 0 of the first octet cleared, bit 1 set). Falls back to an XOR-shift of the output buffer's own stack address if `/dev/urandom` cannot be opened. **Never fails** — always returns `Error::none()`; the `Error` return type is kept only for interface consistency with the other `sock::*` functions. |
| `raw_send()` | `Error raw_send(int fd, int ifindex, const uint8_t* buf, uint32_t len, const uint8_t dst_mac[6])` | `sendto()` on an `AF_PACKET` `sockaddr_ll` | The single `sendto()` call in the library. `dst_mac` fills `sll_addr` and must already be resolved by the caller. Errors: `Status::SendFail` (send failed), `Status::SendTruncated` (fewer bytes sent than requested). |
| `raw_recv()` | `int32_t raw_recv(int fd, uint8_t* buf, uint32_t cap, uint8_t out_src_mac[6], Error& err)` | `recvfrom()` on an `AF_PACKET` `sockaddr_ll` | The single `recvfrom()` call in the library. Returns `n > 0` (bytes received), `n == 0` (timeout — `EAGAIN`/`EINTR`, not an error, caller should check the stop flag and retry), or `n == -1` (hard error, populates `err`). `out_src_mac`, if non-null, is filled from the received `sockaddr_ll`. |
| `close_fd()` | `void close_fd(int& fd)` | `close()` | Closes `fd` and resets it to `INVALID_FD`. Safe to call multiple times (a no-op if already `INVALID_FD`). Does not return an `Error` — `close()` is not expected to meaningfully fail in this context. |

### Constants (`lynx::sock`)

| Constant | Value | Description |
|---|---|---|
| `INVALID_FD` | `-1` | Sentinel for "no open socket". |
| `INVALID_IDX` | `-1` | Sentinel for "no resolved interface index". |

### `Direction` enum (`lynx::sock::Direction`)

| Value | Description |
|---|---|
| `Direction::In` | Incoming frames only. |
| `Direction::Out` | Outgoing frames only (filtered by the caller in the recv loop, since the kernel provides no direct "outgoing only" socket option). |
| `Direction::Both` | Default — all frames, no directional filtering. |

## 6. Interface Implementation Notes

`lynx::io::Interface` (see full API in
[API.md § 4.1 Common Interface Methods](../API.md#41-common-interface-methods))
composes the primitives above as follows:

- **`open()`** calls, in order: `open_raw()` → `resolve_ifindex()` →
  `bind_to_iface()` → `set_recv_timeout()` → `set_recv_buffer()` →
  `set_direction()` → (if promiscuous mode was requested)
  `set_promiscuous()`. Each step uses `absorb()` to record any failure on
  `Interface`'s own `BaseObject` state and stops the sequence early on
  the first failure — see [ERRORS.md §
  First-Error-Wins](../ERRORS.md#first-error-wins).
- **`write(Frame)`** allocates a `Buffer` sized to `frame.size()`,
  serializes the frame into it, and passes it directly to `raw_send()` —
  the destination MAC used for `sll_addr` is read directly from byte
  offset `0` of the serialized frame, since every supported L2 header
  (`HdrEth`, `HdrDot1Q`) places the destination MAC at that offset.
- **`write(Packet&)`** (the L3 overload) builds a fresh `Ether` frame
  around the given `Packet`, resolving its `ethertype` from
  `pkt.ethertype()`, and its destination MAC either as broadcast (if
  `pkt.is_broadcast()`) or via `resolve_ether()` → `arp_lookup()` for a
  routed unicast destination (see [config.hpp §
  LYNX_DST_MAC_POLICY](../API.md#43-confighpp--compile-time-configuration)).
  The source MAC is resolved via `resolve_src_mac()`, which reads either
  the real interface MAC (`get_iface_mac()`) or a randomized one
  (`randomize_mac()`) depending on `LYNX_SRC_MAC_POLICY`.
- **`capture()`** allocates a single `Buffer` sized to the configured
  snaplen once, then loops calling `raw_recv()` into it, resetting the
  buffer's write cursor each iteration. Each successfully received frame
  is wrapped in a `RawFrame` (see
  [ethernet.md § RawFrame](../protocols/ethernet.md#6-rawframe)) — which
  shares the same underlying slab with a no-op deleter, since the slab is
  kept alive by the `Buffer` local to `capture()`'s stack frame for the
  duration of each callback invocation — and passed to the caller's
  callback. The loop exits when the callback returns
  `io::RecvAction::Stop`, when `stop()` has set the atomic stop flag
  (checked once per timeout tick), or when `raw_recv()` reports a hard
  error.

## 7. Example

Direct use of the low-level `lynx::sock` primitives, bypassing
`Interface` (as demonstrated in `src/examples/socket_funcs.cpp`):

```cpp
#include <lynx/lynx>

using namespace lynx;

int ifindex = 0;
Error err = sock::resolve_ifindex("wlan0", ifindex);
if (!err.ok()) {
    std::cerr << "resolve_ifindex failed: " << err.what() << "\n";
    return 1;
}

int fd;
err = sock::open_raw(fd);
if (!err.ok()) {
    std::cerr << "open_raw failed: " << err.what() << "\n";
    return 1;
}

uint8_t iface_mac[6];
err = sock::get_iface_mac(fd, "wlan0", iface_mac);

uint8_t target_ip[4] = {100, 112, 0, 1};
uint8_t target_mac[6];
err = sock::arp_lookup(fd, "wlan0", target_ip, target_mac);
if (!err.ok()) {
    std::cerr << "arp_lookup failed: " << err.what() << "\n";
    close(fd);
    return 1;
}
```

Typical usage through the higher-level `Interface` API is documented in
[README.md § Usage](../README.md#3-usage) and
[API.md § 4.1 Common Interface Methods](../API.md#41-common-interface-methods).

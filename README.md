# lynx

A header-only, Linux-first C++17 packet capture and crafting library. Inspired by scapy.

```cpp
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

## features

- packet crafting via `operator/` — `Ether / IPv4 / TCP / Raw`
- packet capture via a blocking callback loop
- zero-copy dissection — all layers share one recv slab
- mutable header access after dissect — edit captured packets in place
- lazy layer parsing — only parse what you ask for via `as<T>()`
- MAC resolution via kernel ARP cache
- promiscuous mode, direction filtering, recv buffer tuning
- compile-time policy knobs via `config.hpp`

---

## requirements

- Linux (AF_PACKET — kernel 3.x+)
- C++17
- GCC or Clang
- root / `CAP_NET_RAW` to open raw sockets

---

## Interface

```cpp
Interface iface("eth0");

// tuning — call before or after open()
iface.set_promiscuous(true);
iface.set_snaplen(65535);
iface.set_timeout(100);           // ms — how often recv checks stop flag
iface.set_direction(sock::Direction::Both);
iface.set_buffer_size(0);         // 0 = kernel default

iface.open();
if (!iface.ok()) { /* iface.errmsg() */ }

iface.close();                    // removes promisc, closes fd
iface.stop();                     // signal recv loop to exit (thread-safe)
```

---

## crafting

every protocol object has sensible defaults — only set what you need.

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

checksums are computed automatically before sending — IP header checksum and TCP/UDP pseudo-header checksum.

for a complete L2 frame with no MAC resolution:

```cpp
eth / ip / tcp / payload;
iface.send(eth);
```

---

## capture

`capture` takes a blocking callback. call `iface.stop()` from another thread to exit.

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

`RawFrame` owns the raw bytes. `as<T>()` allocates a typed layer and calls `dissect()` — zero-copy, the new object views the same memory. all `as<T>()` objects are `unique_ptr<T>` — cleaned up automatically.

after dissect, header fields are in host byte order — compare directly against `constants::`:

```cpp
if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV4) { ... }
if (tcp->hdr()->flags & constants::TCP_FLAG_SYN)       { ... }
```

---

## config.hpp

edit before including `lynx/lynx` to control compile-time behavior:

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

## error handling

every class inherits `BaseObject` — no exceptions, no return codes.

```cpp
iface.open();
if (!iface.ok()) {
    printf("error: %s\n", iface.errmsg());   // human-readable
    // iface.status() → Status::SocketBindFail etc.
    return;
}

// clear after handling and retry
iface.clear_error();
```

the same pattern applies to `Buffer`, `IPv4`, `TCP`, and every other class.

---

## protocols

| class | layer | checksum |
|---|---|---|
| `Ether` | L2 | none (FCS by NIC) |
| `Dot1Q` | L2 | none |
| `ARP` | L3 | none |
| `IPv4` | L3 | header checksum |
| `IPv6` | L3 | none (removed in RFC 2460) |
| `TCP` | L4 | pseudo-header (IPv4 or IPv6) |
| `UDP` | L4 | pseudo-header (IPv4 or IPv6) |
| `ICMP` | L4 | header + data |
| `ICMPv6` | L4 | pseudo-header (IPv6) |
| `IGMP` | L4 | header only |
| `Raw` | any | none |

---

## versioning

**v0 (current)** — capture, crafting, send/recv, L2–L4 protocols, AF_PACKET I/O.

**v1 (planned)** — extend protocols set, add support for other platforms/OSs.

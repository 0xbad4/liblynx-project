#pragma once

// ═══════════════════════════════════════════════════════════════════
//  lynx configuration
//  edit this file before including lynx.hpp
//  all defines are compile-time — zero runtime overhead
// ═══════════════════════════════════════════════════════════════════


// ───────────────────────────────────────────────────────────────────
//  DST MAC resolution policy
//  used by send(Packet) and send(Segment) when no EtherFrame provided
//
//  1 — BROADCAST   ff:ff:ff:ff:ff:ff always used as dst MAC
//                  safe fallback, works on any LAN, no ARP needed
//                  use for: discovery packets, testing, fuzzing
//
//  2 — ARP_LOOKUP  resolve dst MAC from dst IP via kernel ARP cache
//                  (SIOCGARP ioctl). if IP not in cache → send fails
//                  with Status::ArpResolveFail
//                  use for: normal unicast traffic
// ───────────────────────────────────────────────────────────────────
#define LYNX_DST_MAC_POLICY 2


// ───────────────────────────────────────────────────────────────────
//  SRC MAC resolution policy
//  controls what goes in the Ethernet src field when Interface
//  auto-wraps a Packet or Segment in an EtherFrame
//
//  1 — IFACE_MAC   use the real hardware MAC of the bound interface
//                  (SIOCGIFHWADDR ioctl). default, most compatible
//
//  2 — RANDOM_MAC  generate a random locally-administered unicast MAC
//                  per packet. bit 1 of first octet set (locally admin)
//                  bit 0 cleared (unicast). use for: anonymization,
//                  spoofing tests, red team tooling
// ───────────────────────────────────────────────────────────────────
#define LYNX_SRC_MAC_POLICY 1


// ───────────────────────────────────────────────────────────────────
//  manual src MAC
//  only used when LYNX_SRC_MAC_POLICY is extended to support
//  a fixed user-defined MAC (future policy 3)
//  format: six comma-separated hex bytes
// ───────────────────────────────────────────────────────────────────
#define LYNX_MANUAL_SRC_MAC { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }


// ───────────────────────────────────────────────────────────────────
//  ethertype auto-detection
//  when Interface wraps a Packet in EtherFrame it needs to set
//  the correct ethertype field
//
//  1 — AUTO   detect from Packet subtype at serialize time
//             IPv4Packet → 0x0800, IPv6Packet → 0x86DD,
//             ARPPacket  → 0x0806
//
//  2 — MANUAL use LYNX_MANUAL_ETHERTYPE below for all packets
// ───────────────────────────────────────────────────────────────────
#define LYNX_ETHERTYPE_POLICY 1

#define LYNX_MANUAL_ETHERTYPE 0x0800


// ───────────────────────────────────────────────────────────────────
//  recv buffer
//  size of the kernel-side socket receive buffer in bytes
//  larger = fewer drops under high traffic, more memory used
//  0 = use kernel default (typically 212992 bytes)
// ───────────────────────────────────────────────────────────────────
#define LYNX_RECV_BUFFER_SIZE 0


// ───────────────────────────────────────────────────────────────────
//  snaplen
//  max bytes captured per frame
//  65535 captures full frames including jumbo frames
//  lower values reduce per-packet copy cost if you only need headers
// ───────────────────────────────────────────────────────────────────
#define LYNX_DEFAULT_SNAPLEN 65535


// ───────────────────────────────────────────────────────────────────
//  recv timeout
//  how often the blocking recvfrom wakes up to check stop flag (ms)
//  lower = more responsive stop(), higher = fewer spurious wakeups
//  100ms is a sensible default for most use cases
// ───────────────────────────────────────────────────────────────────
#define LYNX_DEFAULT_TIMEOUT_MS 100


// ───────────────────────────────────────────────────────────────────────────
//  destructor socket policy
//  1 — close socket in destructor (safe default, prevents fd leaks)
//  0 — leave socket open on destruction (use when Interface lifetime is
//      managed manually or lives in shared state beyond a single scope)
// ───────────────────────────────────────────────────────────────────────────
#define LYNX_CLOSE_ON_DESTROY 1


// ───────────────────────────────────────────────────────────────────
//  Inheritance policy
//  Base classes not concerned, default set to `final`.
// Allow it by simply redefining `LYNX_INHERITANCE_POLICY` macro empty
// ───────────────────────────────────────────────────────────────────
#define LYNX_INHERITANCE_POLICY final
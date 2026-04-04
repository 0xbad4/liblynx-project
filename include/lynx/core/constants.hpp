#pragma once

//  protocol-defined numeric constants — ethertypes, IP protocols,
//  port numbers, header sizes, and common flag values.
//
//  all values are constexpr uint16_t / uint8_t / uint32_t.
//  no OS headers, no platform dependency — safe everywhere.

#include <cstdint>

namespace lynx::constants {

// ───────────────────────────────────────────────────────────────────────────
//  ethertypes
//  carried in the Ethernet frame header (bytes 12-13, network byte order).
//  used by Interface::send() to fill EtherFrame::ethertype,
//  and by the dissector to select the next protocol layer.
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint16_t ETH_TYPE_IPV4 = 0x0800;  // Internet Protocol v4
inline constexpr uint16_t ETH_TYPE_ARP  = 0x0806;  // Address Resolution Protocol
inline constexpr uint16_t ETH_TYPE_IPV6 = 0x86DD;  // Internet Protocol v6
inline constexpr uint16_t ETH_TYPE_VLAN = 0x8100;  // 802.1Q VLAN tag (dot1q tpid)

// ───────────────────────────────────────────────────────────────────────────
//  IP protocol numbers
//  carried in IPv4 header byte 9 (proto field).
//  carried in IPv6 header byte 6 (next header field).
//  used by Interface::send(IPv4, Segment) to identify segment type
//  for checksum computation and by the dissector for next-layer selection.
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint8_t IP_PROTO_ICMP   =   1;    // Internet Control Message (IPv4)
inline constexpr uint8_t IP_PROTO_IGMP   =   2;    // Internet Group Management
inline constexpr uint8_t IP_PROTO_TCP    =   6;    // Transmission Control
inline constexpr uint8_t IP_PROTO_UDP    =  17;    // User Datagram
inline constexpr uint8_t IP_PROTO_IPV6   =  41;    // IPv6 encapsulation
inline constexpr uint8_t IP_PROTO_ICMPV6 =  58;    // ICMPv6 (IPv6 next_hdr)
inline constexpr uint8_t IP_PROTO_RAW    = 255;    // raw / unspecified

// ───────────────────────────────────────────────────────────────────────────
//  ARP hardware / protocol types
//  arp_hrd — hardware address space
//  arp_pro — protocol address space
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint16_t ARP_HRD_ETHER  = 0x0001;  // Ethernet (htype)
inline constexpr uint16_t ARP_PRO_IPV4   = 0x0800;  // IPv4 (ptype — same as ETH_TYPE_IPV4)

inline constexpr uint16_t ARP_OP_REQUEST = 1;        // who has <ip>? tell <src>
inline constexpr uint16_t ARP_OP_REPLY   = 2;        // <ip> is at <mac>

// fixed field lengths for Ethernet+IPv4 ARP (hlen / plen fields)
inline constexpr uint8_t  ARP_HLEN_ETH   = 6;        // MAC address length
inline constexpr uint8_t  ARP_PLEN_IPV4  = 4;        // IPv4 address length
inline constexpr uint8_t  ARP_DEFAULT_OP = ARP_OP_REQUEST;        // Default operation

// ───────────────────────────────────────────────────────────────────────────
//  header sizes in bytes
//  used for buffer pre-allocation and offset arithmetic.
// ───────────────────────────────────────────────────────────────────────────

// ── layer 2 ──────────────────────────────────────────────────────────────
inline constexpr uint32_t ETH_HDR_LEN     =  14;   // dst(6) + src(6) + type(2)
inline constexpr uint32_t ETH_MIN_LEN     =  60;   // minimum frame payload (excl FCS)
inline constexpr uint32_t ETH_MAX_LEN     = 1514;  // maximum frame (excl FCS)
inline constexpr uint32_t ETH_JUMBO_LEN   = 9014;  // jumbo frame (excl FCS)

inline constexpr uint32_t DOT1Q_HDR_LEN   =  18;   // eth(14) + tpid(2) + tci(2)
inline constexpr uint32_t DOT1Q_TAG_LEN   =   4;   // just the inserted tag: tpid + tci

// ── layer 3 ──────────────────────────────────────────────────────────────
inline constexpr uint32_t ARP_HDR_LEN     =  28;   // fixed for Ethernet + IPv4

inline constexpr uint32_t IPV4_HDR_LEN    =  20;   // base header, no options
inline constexpr uint32_t IPV4_MAX_LEN    = 65535; // maximum total IP datagram
inline constexpr uint8_t  IPV4_TTL_DEF    =  64;   // sensible default TTL
inline constexpr uint8_t  IPV4_VERSION    =   4;

inline constexpr uint32_t IPV6_HDR_LEN     =  40;   // fixed header only
inline constexpr uint8_t  IPV6_HOP_DEF     =  64;   // sensible default hop limit
inline constexpr uint8_t  IPV6_VERSION     =  6;
inline constexpr uint8_t  IPV6_PROTO_NONXT =  59;

// ── layer 4 ──────────────────────────────────────────────────────────────
inline constexpr uint32_t TCP_HDR_LEN     =  20;   // base header, no options
inline constexpr uint32_t UDP_HDR_LEN     =   8;
inline constexpr uint32_t ICMP_HDR_LEN    =   8;   // type(1)+code(1)+chk(2)+rest(4)
inline constexpr uint32_t ICMPV6_HDR_LEN  =   8;   // same layout as ICMP
inline constexpr uint32_t IGMP_HDR_LEN    =   8;   // v1/v2 base: type(1)+resp(1)+chk(2)+grp(4)
inline constexpr uint32_t MLD_HDR_LEN     =   8;   // base before records

// ───────────────────────────────────────────────────────────────────────────
//  TCP flags
//  yaml: NS CWR ECE URG ACK PSH RST SYN FIN (9 bits)
//  the low byte holds the classic 8 flags. NS lives in the high nibble of
//  data_off byte. combine with bitwise OR: TCP_FLAG_SYN | TCP_FLAG_ACK
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint16_t TCP_FLAG_FIN = 0x001;
inline constexpr uint16_t TCP_FLAG_SYN = 0x002;
inline constexpr uint16_t TCP_FLAG_RST = 0x004;
inline constexpr uint16_t TCP_FLAG_PSH = 0x008;
inline constexpr uint16_t TCP_FLAG_ACK = 0x010;
inline constexpr uint16_t TCP_FLAG_URG = 0x020;
inline constexpr uint16_t TCP_FLAG_ECE = 0x040;
inline constexpr uint16_t TCP_FLAG_CWR = 0x080;
inline constexpr uint16_t TCP_FLAG_NS  = 0x100;  // nonce sum (RFC 3540)

// common flag combos
inline constexpr uint16_t TCP_FLAG_SYN_ACK = TCP_FLAG_SYN | TCP_FLAG_ACK;
inline constexpr uint16_t TCP_FLAG_FIN_ACK = TCP_FLAG_FIN | TCP_FLAG_ACK;
inline constexpr uint16_t TCP_FLAG_RST_ACK = TCP_FLAG_RST | TCP_FLAG_ACK;

// ───────────────────────────────────────────────────────────────────────────
//  ICMP (IPv4) — type and code values
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint8_t ICMP_ECHO_REPLY    =  0;
inline constexpr uint8_t ICMP_DST_UNREACH   =  3;
inline constexpr uint8_t ICMP_ECHO_REQUEST  =  8;
inline constexpr uint8_t ICMP_TIME_EXCEED   = 11;
inline constexpr uint8_t ICMP_REDIRECT      =  5;

// destination unreachable codes (type=3)
inline constexpr uint8_t ICMP_UNREACH_NET       = 0;
inline constexpr uint8_t ICMP_UNREACH_HOST      = 1;
inline constexpr uint8_t ICMP_UNREACH_PROTO     = 2;
inline constexpr uint8_t ICMP_UNREACH_PORT      = 3;
inline constexpr uint8_t ICMP_UNREACH_NEEDFRAG  = 4;   // fragmentation needed — path MTU

// time exceeded codes (type=11)
inline constexpr uint8_t ICMP_TIMEX_TTL         = 0;   // TTL expired in transit
inline constexpr uint8_t ICMP_TIMEX_FRAG        = 1;   // fragment reassembly timeout

// ───────────────────────────────────────────────────────────────────────────
//  ICMPv6 — type values (next_hdr=58 in IPv6)
//  checksum covers IPv6 pseudo-header (src+dst+len+next_hdr)
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint8_t ICMPV6_ECHO_REQUEST   = 128;
inline constexpr uint8_t ICMPV6_ECHO_REPLY     = 129;
inline constexpr uint8_t ICMPV6_DST_UNREACH    =   1;
inline constexpr uint8_t ICMPV6_TIME_EXCEED    =   3;
// NDP (Neighbor Discovery Protocol)
inline constexpr uint8_t ICMPV6_RS             = 133;  // router solicitation
inline constexpr uint8_t ICMPV6_RA             = 134;  // router advertisement
inline constexpr uint8_t ICMPV6_NS             = 135;  // neighbor solicitation
inline constexpr uint8_t ICMPV6_NA             = 136;  // neighbor advertisement

// ───────────────────────────────────────────────────────────────────────────
//  IGMP — type values (proto=2, rides over IPv4)
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint8_t IGMP_QUERY            = 0x11; // membership query (v1/v2/v3)
inline constexpr uint8_t IGMP_V2_REPORT        = 0x16; // v2 membership report
inline constexpr uint8_t IGMP_V2_LEAVE         = 0x17; // v2 leave group
inline constexpr uint8_t IGMP_V3_REPORT        = 0x22; // v3 membership report

// ───────────────────────────────────────────────────────────────────────────
//  MLD — type values (ICMPv6 type=143, rides over IPv6)
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint8_t MLD_V2_REPORT         = 143;  // MLDv2 membership report

// ───────────────────────────────────────────────────────────────────────────
//  well-known port numbers
//  trimmed to protocols referenced in the yaml security notes.
//  expand as new protocols are added to the library.
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint16_t PORT_SSH      =   22;
inline constexpr uint16_t PORT_DNS      =   53;  // UDP amplification vector
inline constexpr uint16_t PORT_DHCP_SRV =   67;
inline constexpr uint16_t PORT_DHCP_CLI =   68;
inline constexpr uint16_t PORT_HTTP     =   80;
inline constexpr uint16_t PORT_NTP      =  123;  // UDP amplification (monlist)
inline constexpr uint16_t PORT_HTTPS    =  443;
inline constexpr uint16_t PORT_SSDP     = 1900;  // UDP amplification (M-SEARCH)
inline constexpr uint16_t PORT_MDNS     = 5353;

// ───────────────────────────────────────────────────────────────────────────
//  IPv4 special addresses (network byte order)
//  use with care — these are in host byte order here, call htonl() if
//  passing directly to a sockaddr_in.
// ───────────────────────────────────────────────────────────────────────────

inline constexpr uint32_t IPV4_BROADCAST   = 0xFFFFFFFF;   // 255.255.255.255
inline constexpr uint32_t IPV4_LOOPBACK    = 0x7F000001;   // 127.0.0.1
inline constexpr uint32_t IPV4_ANY         = 0x00000000;   // 0.0.0.0

// ───────────────────────────────────────────────────────────────────────────
//  MAC special addresses
// ───────────────────────────────────────────────────────────────────────────

// broadcast: ff:ff:ff:ff:ff:ff
inline constexpr uint8_t MAC_BROADCAST[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

// all-zeros: used as unset/invalid sentinel
inline constexpr uint8_t MAC_ZERO[6]      = { 0x00,0x00,0x00,0x00,0x00,0x00 };

} // namespace lynx::constants
#pragma once

#include "lynx/core/base.hpp"

//  packed header structs — one per protocol, named Hdr<Proto>.
//  these are plain data overlays — no methods, no inheritance.
//  used by protocol classes via hdr() and for zero-copy dissection.


#define LYNX_PACKED struct __attribute__((packed))

namespace lynx::hdrs {

    // ── layer 2 
    LYNX_PACKED HdrEth {
        uint8_t  dst_mac[6];  // destination MAC address
        uint8_t  src_mac[6];  // source MAC address
        uint16_t ethertype;   // payload protocol (0x0800 IPv4 / 0x86DD IPv6 / 0x0806 ARP)
    };

    // 802.1Q VLAN tag - inserted between src_mac and ethertype of Ethernet header
    LYNX_PACKED HdrDot1Q {
        uint8_t   dst_mac[6];  // destination MAC address
        uint8_t   src_mac[6];  // source MAC address
        
        // actual 802.1q
        uint16_t tpid;          // always 0x8100 — confirms this is a tag
        uint16_t tci;           // pcp(3b) | dei(1b) | vid(12b)

        // priority code point (QoS) (3bits)
        [[nodiscard]] uint8_t  pcp()    const noexcept { return (tci >> 13) & 0x07; }
        // drop eligible indicator   (1bit)
        [[nodiscard]] bool     dei()    const noexcept { return (tci >> 12) & 0x01; }
        // VLAN identifier 0-4094    (12bits)
        [[nodiscard]] uint16_t vlan_id()const noexcept { return  tci        & 0x0FFF; }

        static uint16_t make_tci(uint8_t pcp, bool dei, uint16_t vid) noexcept {
            return static_cast<uint16_t>(
                ((pcp & 0x07) << 13) | ((dei ? 1 : 0) << 12) | (vid & 0x0FFF)
            );
        }

        uint16_t ethertype;     // inner payload protocol — what comes after this tag
    };

    // ── layer 3 
    LYNX_PACKED HdrARP {
        uint16_t htype;   // hardware type (0x0001 Ethernet)
        uint16_t ptype;   // protocol type (0x0800 IPv4)
        uint8_t  hlen;    // hardware address length (6 for MAC)
        uint8_t  plen;    // protocol address length (4 for IPv4)
        uint16_t oper;    // operation (1 request / 2 reply)
        uint8_t  sha[6];  // sender hardware address
        uint8_t  spa[4];  // sender protocol address
        uint8_t  tha[6];  // target hardware address
        uint8_t  tpa[4];  // target protocol address
    };

    // version(4b) and ihl(4b) share one byte — accessed via helpers below
    LYNX_PACKED HdrIPv4 {
        uint8_t  ver_ihl;       // [7:4] version=4  [3:0] ihl (header len in 32b words)
        uint8_t  dscp_ecn;      // [7:2] dscp       [1:0] ecn
        uint16_t total_len;     // total length: header + payload
        uint16_t id;            // identification (fragmentation)
        uint16_t flags_frag;    // [15:13] flags  [12:0] fragment offset
        uint8_t  ttl;           // hop limit (default 64)
        uint8_t  proto;         // next protocol (6 TCP / 17 UDP / 1 ICMP)
        uint16_t checksum;      // header checksum — auto-computed
        uint8_t  src_ip[4];     // source address 
        uint8_t  dst_ip[4];     // destination address
        // options follow if ihl > 5 (rarely used)

        // ── sub-byte accessors 
        [[nodiscard]] uint8_t  version()  const noexcept { return (ver_ihl    >> 4)  & 0x0F; }
        [[nodiscard]] uint8_t  ihl()      const noexcept { return  ver_ihl           & 0x0F; }
        [[nodiscard]] uint8_t  dscp()     const noexcept { return (dscp_ecn   >> 2)  & 0x3F; }
        [[nodiscard]] uint8_t  ecn()      const noexcept { return  dscp_ecn          & 0x03; }
        [[nodiscard]] uint8_t  ip_flags() const noexcept { return (flags_frag >> 13) & 0x07; }  // DF/MF
        [[nodiscard]] uint16_t frag_off() const noexcept { return  flags_frag        & 0x1FFF; }
        [[nodiscard]] uint32_t hdr_len()  const noexcept { return  ihl() * 4u; }

        void set_ver_ihl(uint8_t ver, uint8_t ihl_words) noexcept {
            ver_ihl = static_cast<uint8_t>((ver << 4) | (ihl_words & 0x0F));
        }
        void set_dscp_ecn(uint8_t dscp, uint8_t ecn) noexcept {
            dscp_ecn = static_cast<uint8_t>(((dscp & 0x3F) << 2) | (ecn & 0x03));
        }
        void set_flags_frag(uint8_t flags, uint16_t offset) noexcept {
            flags_frag = static_cast<uint16_t>(((flags & 0x07) << 13) | (offset & 0x1FFF));
        }
    };

    // version(4b) traffic_cls(8b) flow_label(20b) share the first 4 bytes
    LYNX_PACKED HdrIPv6 {
        uint32_t ver_tc_fl;     // [31:28] version=6  [27:20] traffic class  [19:0] flow label
        uint16_t payload_len;   // length of payload after this header
        uint8_t  next_hdr;      // next header type (same values as IPv4 proto)
        uint8_t  hop_limit;     // TTL equivalent (default 64)
        uint8_t  src_ip[16];    // source address
        uint8_t  dst_ip[16];    // destination address

        // ── sub-byte accessors
        [[nodiscard]] uint8_t  version()     const noexcept { return (ver_tc_fl >> 28) & 0x0F; }
        [[nodiscard]] uint8_t  traffic_cls() const noexcept { return (ver_tc_fl >> 20) & 0xFF; }
        [[nodiscard]] uint32_t flow_label()  const noexcept { return  ver_tc_fl        & 0x000FFFFF; }

        void set_ver_tc_fl(uint8_t ver, uint8_t tc, uint32_t fl) noexcept {
            ver_tc_fl = ((static_cast<uint32_t>(ver) & 0x0F) << 28)
                    | ((static_cast<uint32_t>(tc)        ) << 20)
                    | ( static_cast<uint32_t>(fl)  & 0x000FFFFF);
        }
    };

    // ── layer 4

    // Same header for IMCPv4 and ICMPv6
    LYNX_PACKED HdrICMP {
        uint8_t  type;
        uint8_t  code;
        uint16_t checksum;
        uint32_t rest;      // host byte order — bswapped in serialize() / dissect()

        // echo: high 16 bits = identifier
        [[nodiscard]] uint16_t id() const noexcept {
            return static_cast<uint16_t>(rest >> 16);
        }

        // echo: low 16 bits = sequence number
        [[nodiscard]] uint16_t seq() const noexcept {
            return static_cast<uint16_t>(rest & 0xFFFF);
        }

        // pack id + seq into rest — both in host byte order
        void set_id_seq(uint16_t id, uint16_t seq) noexcept {
            rest = (static_cast<uint32_t>(id) << 16) | static_cast<uint32_t>(seq);
        }
    };

    // rides over IPv4 (protocol=2). used for multicast group management
    LYNX_PACKED HdrIGMP {
        uint8_t  type;          // 0x11 query / 0x16 v2 report / 0x17 leave / 0x22 v3 report
        uint8_t  max_resp;      // max response time (queries only, 0 otherwise)
        uint16_t checksum;      // standard internet checksum — auto-computed
        uint8_t  group_addr[4]; // multicast group (0.0.0.0 for general query)
    };

    LYNX_PACKED HdrTCP {
        uint16_t src_port;      // source port
        uint16_t dst_port;      // destination port
        uint32_t seq;           // sequence number
        uint32_t ack;           // acknowledgment number
        uint8_t  data_off;      // [7:4] header len in 32b words (min 5)  [3:0] reserved+NS
        uint8_t  flags;         // CWR ECE URG ACK PSH RST SYN FIN
        uint16_t window;        // receive window size
        uint16_t checksum;      // pseudo-header checksum — auto-computed
        uint16_t urg_ptr;       // urgent pointer (valid only if URG set)

        // ── sub-byte accessors
        [[nodiscard]] uint8_t  hdr_len()  const noexcept { return (data_off >> 4) & 0x0F; }
        [[nodiscard]] bool     flag(uint8_t f) const noexcept { return flags & f; }
        [[nodiscard]] uint32_t hdr_bytes()const noexcept { return hdr_len() * 4u; }

        void set_data_off(uint8_t words) noexcept {
            data_off = static_cast<uint8_t>((words & 0x0F) << 4);
        }
    };

    LYNX_PACKED HdrUDP {
        uint16_t src_port;      // source port
        uint16_t dst_port;      // destination port
        uint16_t length;        // header + payload length
        uint16_t checksum;      // optional in IPv4 / mandatory in IPv6 — auto-computed
    };

} // namespace lynx::hdrs

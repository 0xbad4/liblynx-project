#pragma once

#include "lynx/core/common.hpp"

namespace lynx::hdrs
{
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
} // namespace lynx::hdrs

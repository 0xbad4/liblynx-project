#pragma once

#include "lynx/core/common.hpp"

namespace lynx::hdrs
{
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
    
} // namespace lynx::hdrs

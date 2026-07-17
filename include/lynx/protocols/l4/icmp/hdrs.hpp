#pragma once

#include "lynx/core/common.hpp"

namespace lynx::hdrs
{
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
} // namespace lynx::hdrs

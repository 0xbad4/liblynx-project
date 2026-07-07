#pragma once

#include "core/common.hpp"

namespace lynx::hdrs
{
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
} // namespace lynx::hdrs

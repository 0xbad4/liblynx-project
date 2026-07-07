#pragma once

#include "core/common.hpp"

namespace lynx::hdrs
{
    LYNX_PACKED HdrUDP {
        uint16_t src_port;      // source port
        uint16_t dst_port;      // destination port
        uint16_t length;        // header + payload length
        uint16_t checksum;      // optional in IPv4 / mandatory in IPv6 — auto-computed
    };
} // namespace lynx::hdrs

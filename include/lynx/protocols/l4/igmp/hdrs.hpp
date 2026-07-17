#pragma once

#include "lynx/core/common.hpp"

namespace lynx::hdrs
{
    // rides over IPv4 (protocol=2). used for multicast group management
    LYNX_PACKED HdrIGMP {
        uint8_t  type;          // 0x11 query / 0x16 v2 report / 0x17 leave / 0x22 v3 report
        uint8_t  max_resp;      // max response time (queries only, 0 otherwise)
        uint16_t checksum;      // standard internet checksum — auto-computed
        uint8_t  group_addr[4]; // multicast group (0.0.0.0 for general query)
    };    
} // namespace lynx::hdrs

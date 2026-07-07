#pragma once

#include "core/common.hpp"

namespace lynx::hdrs
{
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
} // namespace lynx::hdrs

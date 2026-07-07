#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  IP protocol numbers
    inline constexpr uint8_t IP_PROTO_UDP    =  17;    // User Datagram

    //  UDP — header size
    inline constexpr uint32_t UDP_HDR_LEN = 8;

} // namespace lynx::constants

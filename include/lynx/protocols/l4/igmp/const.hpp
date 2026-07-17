#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  IGMP — header size
    inline constexpr uint8_t IP_PROTO_IGMP   =   2;    // Internet Group Management
    
    inline constexpr uint32_t IGMP_HDR_LEN = 8;  // v1/v2 base: type(1)+resp(1)+chk(2)+grp(4)

    //  IGMP — type values (proto=2, rides over IPv4)

    inline constexpr uint8_t IGMP_QUERY     = 0x11;  // membership query (v1/v2/v3)
    inline constexpr uint8_t IGMP_V2_REPORT = 0x16;  // v2 membership report
    inline constexpr uint8_t IGMP_V2_LEAVE  = 0x17;  // v2 leave group
    inline constexpr uint8_t IGMP_V3_REPORT = 0x22;  // v3 membership report

} // namespace lynx::constants

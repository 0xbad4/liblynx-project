#pragma once

//  ports — well-known port number constants.
//  expand as new protocols are added to the library.
//
//  all values are constexpr uint16_t.

#include <cstdint>

namespace lynx::constants {

    //  well-known port numbers

    inline constexpr uint16_t PORT_SSH      =   22;
    inline constexpr uint16_t PORT_DNS      =   53;  // UDP amplification vector
    inline constexpr uint16_t PORT_DHCP_SRV =   67;
    inline constexpr uint16_t PORT_DHCP_CLI =   68;
    inline constexpr uint16_t PORT_HTTP     =   80;
    inline constexpr uint16_t PORT_NTP      =  123;  // UDP amplification (monlist)
    inline constexpr uint16_t PORT_HTTPS    =  443;
    inline constexpr uint16_t PORT_SSDP     = 1900;  // UDP amplification (M-SEARCH)
    inline constexpr uint16_t PORT_MDNS     = 5353;

} // namespace lynx::constants

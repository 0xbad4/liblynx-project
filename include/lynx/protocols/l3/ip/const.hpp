#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  IP protocol number
    inline constexpr uint8_t IP_PROTO_IPV6   =  41;    // IPv6 encapsulation
    inline constexpr uint8_t IP_PROTO_RAW    = 255;    // raw / unspecified
 
    //  IPv4 — header size and datagram limits

    inline constexpr uint32_t IPV4_HDR_LEN  =  20;    // base header, no options
    inline constexpr uint32_t IPV4_MAX_LEN  = 65535;  // maximum total IP datagram

    inline constexpr uint8_t  IPV4_VERSION  =  4;
    inline constexpr uint8_t  IPV4_TTL_DEF  = 64;     // sensible default TTL

    //  IPv4 special addresses (host byte order)
    //  use with care — call htonl() if passing directly to a sockaddr_in.

    inline constexpr uint32_t IPV4_BROADCAST = 0xFFFFFFFF;  // 255.255.255.255
    inline constexpr uint32_t IPV4_LOOPBACK  = 0x7F000001;  // 127.0.0.1
    inline constexpr uint32_t IPV4_ANY       = 0x00000000;  // 0.0.0.0

    
    // --------------------------------------------------
    //  IPv6 — header size and defaults

    inline constexpr uint32_t IPV6_HDR_LEN      = 40;  // fixed header only
    inline constexpr uint8_t  IPV6_VERSION      =  6;
    inline constexpr uint8_t  IPV6_HOP_DEF      = 64;  // sensible default hop limit
    inline constexpr uint8_t  IPV6_PROTO_NONXT  = 59;  // No Next Header (RFC 2460)

} // namespace lynx::constants

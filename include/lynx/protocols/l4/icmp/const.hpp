#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  IP protocol number
    inline constexpr uint8_t IP_PROTO_ICMP   =   1;    // Internet Control Message (IPv4)
    inline constexpr uint8_t IP_PROTO_ICMPV6 =  58;    // ICMPv6 (IPv6 next_hdr)

    //  ICMP / ICMPv6 — header sizes

    inline constexpr uint32_t ICMP_HDR_LEN   = 8;  // type(1)+code(1)+chk(2)+rest(4)
    inline constexpr uint32_t ICMPV6_HDR_LEN = 8;  // same layout as ICMP

    //  ICMP (IPv4) — type and code values

    inline constexpr uint8_t ICMP_ECHO_REPLY   =  0;
    inline constexpr uint8_t ICMP_DST_UNREACH  =  3;
    inline constexpr uint8_t ICMP_REDIRECT     =  5;
    inline constexpr uint8_t ICMP_ECHO_REQUEST =  8;
    inline constexpr uint8_t ICMP_TIME_EXCEED  = 11;

    // destination unreachable codes (type=3)
    inline constexpr uint8_t ICMP_UNREACH_NET      = 0;
    inline constexpr uint8_t ICMP_UNREACH_HOST     = 1;
    inline constexpr uint8_t ICMP_UNREACH_PROTO    = 2;
    inline constexpr uint8_t ICMP_UNREACH_PORT     = 3;
    inline constexpr uint8_t ICMP_UNREACH_NEEDFRAG = 4;  // fragmentation needed — path MTU

    // time exceeded codes (type=11)
    inline constexpr uint8_t ICMP_TIMEX_TTL  = 0;  // TTL expired in transit
    inline constexpr uint8_t ICMP_TIMEX_FRAG = 1;  // fragment reassembly timeout

    //  ICMPv6 — type values (next_hdr=58 in IPv6)
    //  checksum covers IPv6 pseudo-header (src+dst+len+next_hdr)

    inline constexpr uint8_t ICMPV6_DST_UNREACH  =   1;
    inline constexpr uint8_t ICMPV6_TIME_EXCEED  =   3;
    inline constexpr uint8_t ICMPV6_ECHO_REQUEST = 128;
    inline constexpr uint8_t ICMPV6_ECHO_REPLY   = 129;

    // NDP (Neighbor Discovery Protocol)
    inline constexpr uint8_t ICMPV6_RS = 133;  // router solicitation
    inline constexpr uint8_t ICMPV6_RA = 134;  // router advertisement
    inline constexpr uint8_t ICMPV6_NS = 135;  // neighbor solicitation
    inline constexpr uint8_t ICMPV6_NA = 136;  // neighbor advertisement
} // namespace lynx::constants

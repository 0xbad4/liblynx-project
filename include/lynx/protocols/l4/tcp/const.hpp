#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  IP protocol numbers
    inline constexpr uint8_t IP_PROTO_TCP    =   6;    // Transmission Control

    //  TCP — header size

    inline constexpr uint32_t TCP_HDR_LEN = 20;  // base header, no options

    //  TCP flags
    //  NS CWR ECE URG ACK PSH RST SYN FIN (9 bits)
    //  the low byte holds the classic 8 flags. NS lives in the high nibble of
    //  the data_off byte. combine with bitwise OR: TCP_FLAG_SYN | TCP_FLAG_ACK

    inline constexpr uint16_t TCP_FLAG_FIN = 0x001;
    inline constexpr uint16_t TCP_FLAG_SYN = 0x002;
    inline constexpr uint16_t TCP_FLAG_RST = 0x004;
    inline constexpr uint16_t TCP_FLAG_PSH = 0x008;
    inline constexpr uint16_t TCP_FLAG_ACK = 0x010;
    inline constexpr uint16_t TCP_FLAG_URG = 0x020;
    inline constexpr uint16_t TCP_FLAG_ECE = 0x040;
    inline constexpr uint16_t TCP_FLAG_CWR = 0x080;
    inline constexpr uint16_t TCP_FLAG_NS  = 0x100;  // nonce sum (RFC 3540)

    // common flag combos
    inline constexpr uint16_t TCP_FLAG_SYN_ACK = TCP_FLAG_SYN | TCP_FLAG_ACK;
    inline constexpr uint16_t TCP_FLAG_FIN_ACK = TCP_FLAG_FIN | TCP_FLAG_ACK;
    inline constexpr uint16_t TCP_FLAG_RST_ACK = TCP_FLAG_RST | TCP_FLAG_ACK;

} // namespace lynx::constants

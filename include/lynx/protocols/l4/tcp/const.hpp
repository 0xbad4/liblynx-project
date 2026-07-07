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

    // --------------------------------------------------
    //  SCTP - header size
    inline consteval uint32_t SCTP_HDR_LEN       = 12;
    inline consteval uint32_t SCTP_CHUNK_HDR_LEN = 4;

    // SCTP - chunk types
    inline constexpr uint8_t  SCTP_CHUNK_DATA          = 0;
    inline constexpr uint8_t  SCTP_CHUNK_INIT          = 1;
    inline constexpr uint8_t  SCTP_CHUNK_INIT_ACK      = 2;
    inline constexpr uint8_t  SCTP_CHUNK_SACK          = 3;
    inline constexpr uint8_t  SCTP_CHUNK_HEARTBEAT     = 4;
    inline constexpr uint8_t  SCTP_CHUNK_HEARTBEAT_ACK = 5;
    inline constexpr uint8_t  SCTP_CHUNK_ABORT         = 6;
    inline constexpr uint8_t  SCTP_CHUNK_SHUTDOWN      = 7;
    inline constexpr uint8_t  SCTP_CHUNK_SHUTDOWN_ACK  = 8;
    inline constexpr uint8_t  SCTP_CHUNK_ERROR         = 9;
    inline constexpr uint8_t  SCTP_CHUNK_COOKIE_ECHO   = 10;
    inline constexpr uint8_t  SCTP_CHUNK_COOKIE_ACK    = 11;
    inline constexpr uint8_t  SCTP_CHUNK_SHUTDOWN_COMPLETE = 14;

    // DATA chunk flags
    inline constexpr uint8_t  SCTP_DATA_FLAG_E = 0x01;  // ending fragment
    inline constexpr uint8_t  SCTP_DATA_FLAG_B = 0x02;  // beginning fragment
    inline constexpr uint8_t  SCTP_DATA_FLAG_U = 0x04;  // unordered

    // INIT chunk fixed parameters
    inline constexpr uint16_t SCTP_DEFAULT_OUT_STREAMS = 10;
    inline constexpr uint16_t SCTP_DEFAULT_IN_STREAMS  = 65535;
    inline constexpr uint32_t SCTP_DEFAULT_RWND        = 106496; // 104KB, common default

    // CRC-32c
    inline constexpr uint32_t SCTP_CRC32C_POLY  = 0x1EDC6F41;
    inline constexpr uint32_t SCTP_CRC32C_INIT  = 0xFFFFFFFF;

} // namespace lynx::constants

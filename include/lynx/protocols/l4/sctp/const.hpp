#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  IP protocol numbers
    inline constexpr uint8_t IP_PROTO_SCTP        = 132;

    //  SCTP - header size
    inline constexpr uint32_t SCTP_HDR_LEN       = 12;
    inline constexpr uint32_t SCTP_CHUNK_HDR_LEN = 4;

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

} // namespace lynx::constants

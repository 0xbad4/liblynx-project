#pragma once

#include <cstdint>

namespace lynx::constants
{
    // ─ PPPoE ethertypes
    inline constexpr uint16_t PPPOE_ETHERTYPE_DISC    = 0x8863;
    inline constexpr uint16_t PPPOE_ETHERTYPE_SESSION = 0x8864;
 
    // ── PPPoE fixed field values 
    // ver_type is always 0x11 — version=1 (high nibble), type=1 (low nibble)
    inline constexpr uint8_t  PPPOE_VER_TYPE          = 0x11;
 
    // ── PPPoE code values 
    inline constexpr uint8_t  PPPOE_CODE_SESSION      = 0x00;  // session data
    inline constexpr uint8_t  PPPOE_CODE_PADI         = 0x09;  // discovery initiation
    inline constexpr uint8_t  PPPOE_CODE_PADO         = 0x07;  // discovery offer
    inline constexpr uint8_t  PPPOE_CODE_PADR         = 0x19;  // discovery request
    inline constexpr uint8_t  PPPOE_CODE_PADS         = 0x65;  // session confirmed
    inline constexpr uint8_t  PPPOE_CODE_PADT         = 0xA7;  // terminate
 
    // ── PPPoE TLV tag types (discovery phase only)
    inline constexpr uint16_t PPPOE_TAG_EOL           = 0x0000;  // end of list
    inline constexpr uint16_t PPPOE_TAG_SVC_NAME      = 0x0101;  // service name
    inline constexpr uint16_t PPPOE_TAG_AC_NAME       = 0x0102;  // access concentrator name
    inline constexpr uint16_t PPPOE_TAG_HOST_UNIQ     = 0x0103;  // host unique (arbitrary bytes)
    inline constexpr uint16_t PPPOE_TAG_AC_COOKIE     = 0x0104;  // AC cookie (replay protection)
    inline constexpr uint16_t PPPOE_TAG_VENDOR        = 0x0105;  // vendor specific
    inline constexpr uint16_t PPPOE_TAG_SVC_ERR       = 0x0201;  // service name error
    inline constexpr uint16_t PPPOE_TAG_AC_ERR        = 0x0202;  // AC system error
    inline constexpr uint16_t PPPOE_TAG_GENERIC_ERR   = 0x0203;  // generic error
 
    // ── PPPoE header size 
    inline constexpr uint32_t PPPOE_HDR_LEN           = 6;  // ver_type(1)+code(1)+session_id(2)+length(2)
    
} // namespace lynx::constants

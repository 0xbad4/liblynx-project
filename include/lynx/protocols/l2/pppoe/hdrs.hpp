#pragma once

#include "core/common.hpp"
#include "const.hpp

namespace lynx::hdrs
{
    // ── PPPoE header
    // 6 bytes. sits directly after the Ethernet header.
    // length carries the payload size — not the total frame size.
    // do not set length manually — serialize() computes it from load_.size().
 
    LYNX_PACKED HdrPPPoE {
        uint8_t  ver_type;      // PPPOE_VER_TYPE — always 0x11
        uint8_t  code;          // PPPOE_CODE_*
        uint16_t session_id;    // 0x0000 during discovery, assigned by server in PADS
        uint16_t length;        // payload length — computed in serialize()
 
        [[nodiscard]] uint8_t version() const noexcept { return (ver_type >> 4) & 0x0F; }
        [[nodiscard]] uint8_t type()    const noexcept { return  ver_type       & 0x0F; }
 
        [[nodiscard]] bool is_session()   const noexcept { return code == constants::PPPOE_CODE_SESSION; }
        [[nodiscard]] bool is_discovery() const noexcept { return code != constants::PPPOE_CODE_SESSION; }
    };
 
    // ── PPPoE discovery TLV header
    // discovery frames (PADI/PADO/PADR/PADS/PADT) carry TLV-encoded tags.
    // length does not include the type and length bytes themselves.
    // multiple tags are packed back to back — walk them by advancing
    // (sizeof(HdrPPPoETag) + length) bytes per tag until the payload ends.


    LYNX_PACKED PPPoETag {
        uint16_t                type   = 0;
        uint16_t                length = 0;
        const_view_t            value{};
    };
} // namespace lynx::hdrs

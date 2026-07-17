#pragma once

#include "lynx/core/common.hpp"
#include "const.hpp"

namespace lynx::hdrs
{
    // ── PPP full header
    // address is always 0xFF (all-stations) and control is always 0x03
    // (unnumbered information) on standard point-to-point links.
    // both bytes are present unless ACFC was negotiated via LCP.

    LYNX_PACKED HdrPPP {
        uint8_t address; // always 0xFF (all-stations) on standard point-to-point links.
        uint8_t control;  // always 0x03 (unnumbered information) on standard point-to-point links
        uint16_t protocol;  // PPP_PROTO_* — identifies the encapsulated payload

        [[nodiscard]] bool is_ipv4()    const noexcept { return protocol == constants::PPP_PROTO_IP;     }
        [[nodiscard]] bool is_ipv6()    const noexcept { return protocol == constants::PPP_PROTO_IPV6;   }
        [[nodiscard]] bool is_lcp()     const noexcept { return protocol == constants::PPP_PROTO_LCP;    }
        [[nodiscard]] bool is_ipcp()    const noexcept { return protocol == constants::PPP_PROTO_IPCP;   }
        [[nodiscard]] bool is_ipv6cp()  const noexcept { return protocol == constants::PPP_PROTO_IPV6CP; }
        [[nodiscard]] bool is_pap()     const noexcept { return protocol == constants::PPP_PROTO_PAP;    }
        [[nodiscard]] bool is_chap()    const noexcept { return protocol == constants::PPP_PROTO_CHAP;   }
        [[nodiscard]] bool is_ccp()     const noexcept { return protocol == constants::PPP_PROTO_CCP;    }
    };

    // ── LCP / NCP common header
    // shared by LCP, IPCP, IPv6CP, CCP, ECP, PAP, and CHAP.
    // the protocol field in HdrPPP determines which subprotocol is carried.
    // options or data follow immediately after this 4-byte header.

    LYNX_PACKED HdrLCP {
        uint8_t  code;      // PPP_CODE_* — message type
        uint8_t  id;        // identifier echoed in replies to correlate request/reply
        uint16_t length;    // total length including this header and all data
                            // computed by serialize() — do not set manually
    };

    // TLV base
    LYNX_PACKED HdrBaseTLV {
        uint8_t type;        // *_OPT_*
        uint8_t length;      // total option length in bytes (includes type + length)
        const_view_t value;  // option data — length is (length - 2) bytes
    };

    // ── LCP / NCP option TLV header
    // options in Configure-Request / Ack / Nak / Reject are encoded as TLVs.
    // length includes both the type and length bytes themselves.
    // data[] is flexible array — access via pointer arithmetic on load_ span.

    LYNX_PACKED HdrLCPOpt : HdrBaseTLV {
        HdrLCPOpt(const HdrBaseTLV& base) : HdrBaseTLV(base) {}
    };

    // ── PAP header
    // carried inside PPP (protocol=0xC023).
    // body layout for AUTH_REQ: peer-id-len(1B) | peer-id | passwd-len(1B) | passwd
    // body layout for ACK/NAK:  msg-len(1B) | message

    LYNX_PACKED HdrPAP : HdrLCP {};

    // ── PAP message bodies
    // PAP has no fixed-size value fields — every field is a length-prefixed
    // byte string. dissect() only sets load_ to the raw body bytes — it does
    // NOT parse these structs. each struct below is a *view*, returned on
    // demand by a PAP accessor (e.g. PAP::auth_request()) which validates that
    // the length-prefixed sections fit inside load_ at call time.
    // a zeroed struct (all spans empty) signals "malformed / out of range".


    // PAP_CODE_AUTH_REQ body: peer-id-len(1) | peer-id | passwd-len(1) | passwd
    LYNX_PACKED PAPAuthRequest {
        std::span<const uint8_t> peer_id{};
        std::span<const uint8_t> passwd{};
    };

    // ── CHAP header
    // carried inside PPP (protocol=0xC223).
    // body layout for CHALLENGE/RESPONSE: value-size(1B) | value | name
    // body layout for SUCCESS/FAILURE:    message (arbitrary text)

    LYNX_PACKED HdrCHAP : HdrLCP {};

    // CHAP_CODE_CHALLENGE / RESPONSE body: value-size(1) | value | name
    // NOTE: for other codes (SUCCESS / FAILURE) the body is just a message string — no fixed fields.
    LYNX_PACKED CHAPChallengeResponse {
        std::span<const uint8_t> value{};
        std::span<const uint8_t> name{};
    };

    // ── IPv6CP header
    // shared by IPv6CP option negotiation, extends LCP base structure.
    // carried inside PPP (protocol=0x8057).
    LYNX_PACKED HdrIPv6CP : HdrLCP {};

    // IPv6CP TLVs
    // IPv6CP option TLVs for address negotiation and interface identification
    LYNX_PACKED HdrIPv6CPOpt : HdrBaseTLV {
        HdrIPv6CPOpt(const HdrBaseTLV& base) : HdrBaseTLV(base) {}
    };

    // IPCP header
    // shared by IPCP option negotiation, extends LCP base structure.
    // carried inside PPP (protocol=0x8021).
    LYNX_PACKED HdrIPCP : HdrLCP {};

    // IPCP TLVs
    // IPCP option TLVs for IP address negotiation and compression protocol
    LYNX_PACKED HdrIPCPOpt : HdrBaseTLV {
        HdrIPCPOpt(const HdrBaseTLV& base) : HdrBaseTLV(base) {}
    };    
} // namespace lynx::hdrs

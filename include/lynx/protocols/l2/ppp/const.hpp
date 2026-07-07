#pragma once

#include <cstdint>

namespace lynx::constants
{
    // PPP - header length variants
    // the full header is 4 bytes: address(1) + control(1) + protocol(2).
    // LCP negotiation can compress it:
    //   ACFC (address/control field compression) drops address + control → 2B
    //   PFC  (protocol field compression)        drops protocol high byte → 3B
    //   both active                                                        → 1B

    inline constexpr uint32_t PPP_HDR_LEN        = 4;  // full uncompressed
    inline constexpr uint32_t PPP_HDR_LEN_ACFC   = 2;  // address+control stripped
    inline constexpr uint32_t PPP_HDR_LEN_PFC    = 3;  // protocol compressed to 1B
    inline constexpr uint32_t PPP_HDR_LEN_MIN    = 1;  // both compressions active
    inline constexpr uint32_t PPP_HDR_LEN_MAX    = 4;

    // fixed field values for the uncompressed form
    inline constexpr uint8_t  PPP_ADDRESS        = 0xFF;  // all-stations address
    inline constexpr uint8_t  PPP_CONTROL        = 0x03;  // unnumbered information

    // PPP - protocol numbers
    // values < 0x8000 are network-layer data protocols.
    // values >= 0x8000 are control / NCP protocols.

    inline constexpr uint16_t PPP_PROTO_IP        = 0x0021;  // IPv4
    inline constexpr uint16_t PPP_PROTO_IPV6      = 0x0057;  // IPv6
    inline constexpr uint16_t PPP_PROTO_IPX       = 0x002B;  // Novell IPX
    inline constexpr uint16_t PPP_PROTO_BRIDGING  = 0x0031;  // bridged PDU
    inline constexpr uint16_t PPP_PROTO_MPLS_UC   = 0x0281;  // MPLS unicast
    inline constexpr uint16_t PPP_PROTO_MPLS_MC   = 0x0283;  // MPLS multicast
    inline constexpr uint16_t PPP_PROTO_LCP       = 0xC021;  // link control
    inline constexpr uint16_t PPP_PROTO_PAP       = 0xC023;  // password auth
    inline constexpr uint16_t PPP_PROTO_LQR       = 0xC025;  // link quality report
    inline constexpr uint16_t PPP_PROTO_CHAP      = 0xC223;  // challenge handshake auth
    inline constexpr uint16_t PPP_PROTO_EAP       = 0xC227;  // extensible auth
    inline constexpr uint16_t PPP_PROTO_IPCP      = 0x8021;  // IPv4 control
    inline constexpr uint16_t PPP_PROTO_IPV6CP    = 0x8057;  // IPv6 control
    inline constexpr uint16_t PPP_PROTO_IPXCP     = 0x802B;  // IPX control
    inline constexpr uint16_t PPP_PROTO_MPLSCP    = 0x8281;  // MPLS control
    inline constexpr uint16_t PPP_PROTO_CCP       = 0x80FD;  // compression control
    inline constexpr uint16_t PPP_PROTO_ECP       = 0x8053;  // encryption control

    // ── LCP / NCP shared code values
    // the first 11 codes are identical for LCP, IPCP, IPv6CP, CCP, and ECP.
    // these are the only codes IPCP / IPv6CP / CCP / ECP use — they do not
    // define PROTO_REJ, ECHO_REQ, ECHO_REP, or DISCARD (LCP-only, marked below).

    inline constexpr uint8_t  PPP_CODE_CONF_REQ   = 1;   // configure-request
    inline constexpr uint8_t  PPP_CODE_CONF_ACK   = 2;   // configure-ack
    inline constexpr uint8_t  PPP_CODE_CONF_NAK   = 3;   // configure-nak
    inline constexpr uint8_t  PPP_CODE_CONF_REJ   = 4;   // configure-reject
    inline constexpr uint8_t  PPP_CODE_TERM_REQ   = 5;   // terminate-request
    inline constexpr uint8_t  PPP_CODE_TERM_ACK   = 6;   // terminate-ack
    inline constexpr uint8_t  PPP_CODE_CODE_REJ   = 7;   // code-reject
    inline constexpr uint8_t  PPP_CODE_PROTO_REJ  = 8;   // protocol-reject (LCP only)
    inline constexpr uint8_t  PPP_CODE_ECHO_REQ   = 9;   // echo-request    (LCP only)
    inline constexpr uint8_t  PPP_CODE_ECHO_REP   = 10;  // echo-reply      (LCP only)
    inline constexpr uint8_t  PPP_CODE_DISCARD    = 11;  // discard-request (LCP only)

    // ── LCP option types
    inline constexpr uint8_t  LCP_OPT_MRU         = 1;   // maximum receive unit (2B value)
    inline constexpr uint8_t  LCP_OPT_ACCM        = 2;   // async-control-character-map (4B)
    inline constexpr uint8_t  LCP_OPT_AUTH        = 3;   // auth protocol (2B proto + optional data)
    inline constexpr uint8_t  LCP_OPT_QUALITY     = 4;   // link quality monitoring
    inline constexpr uint8_t  LCP_OPT_MAGIC       = 5;   // magic number (4B)
    inline constexpr uint8_t  LCP_OPT_PFC         = 7;   // protocol field compression
    inline constexpr uint8_t  LCP_OPT_ACFC        = 8;   // address/control field compression
    inline constexpr uint8_t  LCP_OPT_FCS_ALT     = 9;   // FCS alternatives

    // ── IPCP option types
    inline constexpr uint8_t  IPCP_OPT_ADDRS      = 1;   // IP addresses (deprecated)
    inline constexpr uint8_t  IPCP_OPT_COMPRESS   = 2;   // IP compression protocol
    inline constexpr uint8_t  IPCP_OPT_ADDR       = 3;   // IP address (4B)
    inline constexpr uint8_t  IPCP_OPT_DNS1       = 129; // primary DNS server
    inline constexpr uint8_t  IPCP_OPT_DNS2       = 131; // secondary DNS server

    // ── IPv6CP option types
    inline constexpr uint8_t  IPV6CP_OPT_IFACE_ID = 1;   // interface identifier (8B)
    inline constexpr uint8_t  IPV6CP_OPT_COMPRESS = 2;   // IPv6 compression protocol

    // ── PAP code values
    inline constexpr uint8_t  PAP_CODE_AUTH_REQ   = 1;   // authenticate-request
    inline constexpr uint8_t  PAP_CODE_AUTH_ACK   = 2;   // authenticate-ack
    inline constexpr uint8_t  PAP_CODE_AUTH_NAK   = 3;   // authenticate-nak

    // ── CHAP code values
    inline constexpr uint8_t  CHAP_CODE_CHALLENGE = 1;
    inline constexpr uint8_t  CHAP_CODE_RESPONSE  = 2;
    inline constexpr uint8_t  CHAP_CODE_SUCCESS   = 3;
    inline constexpr uint8_t  CHAP_CODE_FAILURE   = 4;

    // ── CCP / ECP — compression and encryption control protocols
    // header layout, codes, and TLV format are identical to LCP/IPCP
    // (use PPP_CODE_* and HdrLCP). CCP and ECP differ only in algorithm
    // identifiers carried inside the configuration option values, which
    // are negotiated per-vendor and outside the scope of v0.

    // ── defaults
    inline constexpr uint16_t PPP_DEFAULT_MRU      = 1500;  // bytes
    inline constexpr uint32_t PPP_DEFAULT_ACCM     = 0xFFFFFFFF;
} // namespace lynx::constants

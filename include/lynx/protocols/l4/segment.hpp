#pragma once

#include "lynx/core/base.hpp"
#include "lynx/core/proto_base.hpp"
#include "lynx/protocols/hdrs.hpp"

namespace lynx::proto
{
 
//  Segment — L4 base
//  base for TCP, UDP, ICMP, ICMPv6, IGMP.
//
//  adds proto() used by Interface::patch_seg_checksum() to select the
//  correct checksum algorithm:
//    TCP / UDP  → IPv4 pseudo-header checksum
//    ICMP       → header + data only, no pseudo-header
//    ICMPv6     → IPv6 pseudo-header checksum
 
class Segment : public ProtocolBaseObject {
public:
    virtual ~Segment() = default;
 
    // IP protocol number — constants::IP_PROTO_TCP / UDP / ICMP etc.
    // drives checksum algorithm selection in Interface::patch_seg_checksum()
    [[nodiscard]] virtual uint8_t proto() const noexcept = 0;
};


} // namespace lynx::proto

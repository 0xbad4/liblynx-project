#pragma once


#include "lynx/core/base.hpp"
#include "lynx/core/proto_base.hpp"
#include "lynx/protocols/hdrs.hpp"

namespace lynx::proto
{
    
//  Packet — L3 base
//  base for IPv4, IPv6, ARP.
 
class Packet : public ProtocolBaseObject {
public:
    virtual ~Packet() = default;
 
    // ethertype to place in the Ethernet header wrapping this packet
    [[nodiscard]] virtual uint16_t       ethertype()    const noexcept = 0;
 
    // 4B IPv4 destination address — used by Interface for ARP resolution
    // returns nullptr if this protocol does not have a routable dst
    // (ARP always broadcasts — returns nullptr and overrides is_broadcast)
    [[nodiscard]] virtual const uint8_t* dst()          const noexcept = 0;
 
    // override to true for protocols that always broadcast (ARP requests)
    // when true: Interface sets dst MAC = ff:ff:ff:ff:ff:ff, dst() ignored
    [[nodiscard]] virtual bool           is_broadcast() const noexcept { return false; }

};

} // namespace lynx::proto

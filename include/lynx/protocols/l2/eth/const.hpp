#pragma once 

#include <cstdint>

namespace lynx::constants
{
    //  Ethernet II — header sizes and frame length limits

    inline constexpr uint32_t ETH_HDR_LEN    =  14;   // dst(6) + src(6) + type(2)
    inline constexpr uint32_t ETH_MIN_LEN    =  60;   // minimum frame payload (excl FCS)
    inline constexpr uint32_t ETH_MAX_LEN    = 1514;  // maximum frame (excl FCS)
    inline constexpr uint32_t ETH_JUMBO_LEN  = 9014;  // jumbo frame (excl FCS)


    //  ethertypes
    //  carried in the Ethernet frame header (bytes 12-13, network byte order).
    //  used by Interface::send() to fill EtherFrame::ethertype,
    //  and by the dissector to select the next protocol layer.
    inline constexpr uint16_t ETH_TYPE_IPV4 = 0x0800;  // Internet Protocol v4
    inline constexpr uint16_t ETH_TYPE_ARP  = 0x0806;  // Address Resolution Protocol
    inline constexpr uint16_t ETH_TYPE_IPV6 = 0x86DD;  // Internet Protocol v6
    inline constexpr uint16_t ETH_TYPE_VLAN = 0x8100;  // 802.1Q VLAN tag (dot1q tpid)
    
    //  IEEE 802.1Q — VLAN tagging
    //  inserts a 4-byte tag between src MAC and ethertype.

    inline constexpr uint32_t DOT1Q_HDR_LEN  =  18;   // eth(14) + tpid(2) + tci(2)
    inline constexpr uint32_t DOT1Q_TAG_LEN  =   4;   // just the inserted tag: tpid + tci

    //  MAC special addresses
    // broadcast: ff:ff:ff:ff:ff:ff
    inline constexpr uint8_t MAC_BROADCAST[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

    // all-zeros: used as unset/invalid sentinel
    inline constexpr uint8_t MAC_ZERO[6]      = { 0x00,0x00,0x00,0x00,0x00,0x00 };
} // namespace lynx::constants

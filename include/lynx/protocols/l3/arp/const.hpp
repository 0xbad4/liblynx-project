#pragma once

#include <cstdint>

namespace lynx::constants
{
    //  ARP hardware / protocol types
    //  arp_hrd — hardware address space
    //  arp_pro — protocol address space

    inline constexpr uint16_t ARP_HRD_ETHER  = 0x0001;  // Ethernet (htype)
    inline constexpr uint16_t ARP_PRO_IPV4   = 0x0800;  // IPv4 (ptype — same as ETH_TYPE_IPV4)

    inline constexpr uint16_t ARP_OP_REQUEST = 1;        // who has <ip>? tell <src>
    inline constexpr uint16_t ARP_OP_REPLY   = 2;        // <ip> is at <mac>

    // fixed field lengths for Ethernet+IPv4 ARP (hlen / plen fields)
    inline constexpr uint8_t  ARP_HLEN_ETH   = 6;        // MAC address length
    inline constexpr uint8_t  ARP_PLEN_IPV4  = 4;        // IPv4 address length
    inline constexpr uint8_t  ARP_DEFAULT_OP = ARP_OP_REQUEST;  // default operation

    // ── header size 
    inline constexpr uint32_t ARP_HDR_LEN    = 28;  // fixed for Ethernet + IPv4

} // namespace lynx::constants

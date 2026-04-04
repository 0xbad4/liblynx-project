#include <lynx/lynx>
#include <iostream>
#include <chrono>

using namespace lynx;

// LAYER 2 (DATA LINK) EXAMPLES

/** Example: Basic Ethernet II Frame */
void craft_ethernet_ipv4_tcp(io::Interface& iface) {
    std::cout << "\n=== Crafting Ethernet + IPv4 + TCP (SYN) ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ip[4], dst_ip[4];
    
    utils::mac_decode("e0:d4:64:db:d2:5b", dst_mac);
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("192.168.137.90", src_ip);
    utils::ipv4_decode("192.168.137.62", dst_ip);
    
    // Craft L2 -> L3 -> L4 stack
    proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
    proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP, 0, 1234, 0, 64);
    proto::TCP   tcp(3345, 4444, 1000, 0, constants::TCP_FLAG_SYN, 65535);
    
    ip4 / tcp;
    
    if (!ip4.ok()) {
        std::cout << "✗ IPv4 Error: " << ip4.errmsg() << std::endl;
    }

    eth / ip4;
    
    if (eth.ok() && iface.ok()) {
        iface.write(eth);
        std::cout << "✓ TCP SYN packet sent (Eth + IPv4 + TCP)" << std::endl;
    } else {
        std::cout << "✗ Error: " << iface.errmsg() << std::endl;
    }
}

/** Example: 802.1Q VLAN Tagged Frame */
void craft_vlan_tagged_frame(io::Interface& iface) {
    std::cout << "\n=== Crafting Dot1Q VLAN Tagged + IPv4 + TCP ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ip[4], dst_ip[4];
    
    utils::mac_decode("ff:ff:ff:ff:ff:ff", dst_mac);    // broadcast
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("10.0.0.1", src_ip);
    utils::ipv4_decode("10.0.0.2", dst_ip);
    
    // VLAN ID 100, Priority 5
    uint16_t tci = lynx::hdrs::HdrDot1Q::make_tci(5, false, 100);
    
    proto::Dot1Q dot1q(dst_mac, src_mac, constants::ETH_TYPE_VLAN, tci, constants::ETH_TYPE_IPV4);
    proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
    proto::TCP   tcp(8080, 80, 5000, 0, constants::TCP_FLAG_SYN | constants::TCP_FLAG_ACK, 32768);
    
    ip4 / tcp;
    dot1q / ip4;
    
    if (dot1q.ok() && iface.ok()) {
        iface.write(dot1q);
        std::cout << "✓ VLAN tagged packet sent (VLAN 100, Priority 5)" << std::endl;
    } else {
        std::cout << "✗ Error: " << iface.errmsg() << std::endl;
    }
}

// LAYER 3 (NETWORK) EXAMPLES

/** Example: ARP Request (Ethernet + ARP) */
void craft_arp_request(io::Interface& iface) {
    std::cout << "\n=== Crafting ARP Request ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t target_ip[4], sender_ip[4];
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
    
    utils::mac_decode("ff:ff:ff:ff:ff:ff", dst_mac);    // broadcast
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("192.168.1.100", sender_ip);
    utils::ipv4_decode("192.168.1.1", target_ip);
    
    proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_ARP);
    proto::ARP   arp(
        constants::ARP_HRD_ETHER,      // hardware type: Ethernet
        constants::ARP_PRO_IPV4,       // protocol type: IPv4
        6,                              // hardware address length
        4,                              // protocol address length
        constants::ARP_OP_REQUEST,      // operation: request
        src_mac,                        // sender hardware address
        sender_ip,                      // sender protocol address
        zero_mac,                       // target hardware address (unknown)
        target_ip                       // target protocol address
    );
    
    eth / arp;
    
    if (eth.ok() && iface.ok()) {
        iface.write(eth);
        std::cout << "✓ ARP request sent (Who has " << "192.168.1.1" << "?)" << std::endl;
    } else {
        std::cout << "✗ Error: " << iface.errmsg() << std::endl;
    }
}

/** Example: ARP Reply (Ethernet + ARP) */
void craft_arp_reply(io::Interface& iface, const uint8_t target_mac[6]) {
    std::cout << "\n=== Crafting ARP Reply ===" << std::endl;
    
    uint8_t src_mac[6];
    uint8_t target_ip[4], sender_ip[4];
    
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("192.168.1.1", sender_ip);
    utils::ipv4_decode("192.168.1.100", target_ip);
    
    proto::Ether eth(target_mac, src_mac, constants::ETH_TYPE_ARP);
    proto::ARP   arp(
        constants::ARP_HRD_ETHER,
        constants::ARP_PRO_IPV4,
        6, 4,
        constants::ARP_OP_REPLY,        // operation: reply
        src_mac,
        sender_ip,
        target_mac,                     // target's MAC (from request)
        target_ip
    );
    
    eth / arp;
    
    if (eth.ok() && iface.ok()) {
        iface.write(eth);
        std::cout << "✓ ARP reply sent" << std::endl;
    } else {
        std::cout << "✗ Error: " << iface.errmsg() << std::endl;
    }
}

/** Example: IPv6 packet (Ethernet + IPv6 + TCP) */
void craft_ipv6_tcp(io::Interface& iface) {
    std::cout << "\n=== Crafting Ethernet + IPv6 + TCP ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ipv6[16], dst_ipv6[16];
    
    utils::mac_decode("33:33:ff:00:00:01", dst_mac);
    sock::randomize_mac(src_mac);
    
    // Example IPv6 addresses (simplified - normally would parse from strings)
    std::memset(src_ipv6, 0, 16);
    std::memset(dst_ipv6, 0, 16);
    src_ipv6[0] = 0xfe;
    src_ipv6[1] = 0x80;
    dst_ipv6[0] = 0xfe;
    dst_ipv6[1] = 0x80;
    
    proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV6);
    proto::IPv6  ip6(0x60000000, 20, constants::IP_PROTO_TCP, 64, src_ipv6, dst_ipv6);
    proto::TCP   tcp(5000, 443, 100, 0, constants::TCP_FLAG_SYN, 65535);
    
    ip6 / tcp;
    eth / ip6;
    
    if (eth.ok() && iface.ok()) {
        iface.write(eth);
        std::cout << "✓ IPv6 TCP SYN packet sent" << std::endl;
    } else {
        std::cout << "✗ Error: " << iface.errmsg() << std::endl;
    }
}

// LAYER 4 (TRANSPORT) EXAMPLES

/** Example: TCP Handshake Packets */
void craft_tcp_variations(io::Interface& iface) {
    std::cout << "\n=== Crafting TCP Variations ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ip[4], dst_ip[4];
    
    utils::mac_decode("aa:bb:cc:dd:ee:ff", dst_mac);
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("10.0.0.50", src_ip);
    utils::ipv4_decode("10.0.0.100", dst_ip);
    
    // TCP SYN packet
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
        proto::TCP   tcp(12345, 80, 1234567890, 0, constants::TCP_FLAG_SYN, 65535);
        ip4 / tcp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ TCP SYN packet sent" << std::endl;
        }
    }
    
    // TCP SYN+ACK packet
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
        proto::TCP   tcp(80, 12345, 9876543210, 1234567891, 
                        constants::TCP_FLAG_SYN | constants::TCP_FLAG_ACK, 65535);
        ip4 / tcp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ TCP SYN+ACK packet sent" << std::endl;
        }
    }
    
    // TCP ACK packet
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
        proto::TCP   tcp(12345, 80, 1234567891, 9876543211, constants::TCP_FLAG_ACK, 65535);
        ip4 / tcp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ TCP ACK packet sent" << std::endl;
        }
    }
    
    // TCP RST packet
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
        proto::TCP   tcp(12345, 80, 1234567891, 9876543211, constants::TCP_FLAG_RST, 0);
        ip4 / tcp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ TCP RST packet sent" << std::endl;
        }
    }
    
    // TCP FIN packet
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_TCP);
        proto::TCP   tcp(12345, 80, 1234567891, 9876543211, constants::TCP_FLAG_FIN, 65535);
        ip4 / tcp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ TCP FIN packet sent" << std::endl;
        }
    }
}

/** Example: UDP packets */
void craft_udp_packets(io::Interface& iface) {
    std::cout << "\n=== Crafting UDP Packets ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ip[4], dst_ip[4];
    
    utils::mac_decode("00:11:22:33:44:55", dst_mac);
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("192.168.0.50", src_ip);
    utils::ipv4_decode("192.168.0.1", dst_ip);
    
    // UDP DNS query (port 53)
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_UDP);
        proto::UDP   udp;
        udp.hdr()->src_port = htons(5353);
        udp.hdr()->dst_port = htons(53);
        
        ip4 / udp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ UDP DNS query packet sent (port 53)" << std::endl;
        }
    }
    
    // UDP NTP packet (port 123)
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_UDP);
        proto::UDP   udp;
        udp.hdr()->src_port = htons(123);
        udp.hdr()->dst_port = htons(123);
        
        ip4 / udp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ UDP NTP packet sent (port 123)" << std::endl;
        }
    }
}

/** Example: ICMP Echo Request/Reply */
void craft_icmp_packets(io::Interface& iface) {
    std::cout << "\n=== Crafting ICMP Packets ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ip[4], dst_ip[4];
    
    utils::mac_decode("ff:ff:ff:ff:ff:ff", dst_mac);
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("192.168.1.100", src_ip);
    utils::ipv4_decode("192.168.1.1", dst_ip);
    
    // ICMP Echo Request (ping)
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_ICMP);
        proto::ICMP  icmp(8, 0, 1234, 1);  // type=8 (echo request), code=0, id=1234, seq=1
        
        ip4 / icmp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ ICMP Echo Request sent" << std::endl;
        }
    }
    
    // ICMP Echo Reply
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_ICMP);
        proto::ICMP  icmp(0, 0, 1234, 1);  // type=0 (echo reply)
        
        ip4 / icmp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ ICMP Echo Reply sent" << std::endl;
        }
    }
    
    // ICMP Destination Unreachable
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_ICMP);
        proto::ICMP  icmp(3, 1, 0, 0);  // type=3 (destination unreachable), code=1 (host unreachable)
        
        ip4 / icmp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ ICMP Destination Unreachable sent" << std::endl;
        }
    }
}

/** Example: ICMPv6 Packets */
void craft_icmpv6_packets(io::Interface& iface) {
    std::cout << "\n=== Crafting ICMPv6 Packets ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ipv6[16], dst_ipv6[16];
    
    utils::mac_decode("33:33:ff:00:00:01", dst_mac);
    sock::randomize_mac(src_mac);
    
    // Initialize IPv6 addresses
    std::memset(src_ipv6, 0, 16);
    std::memset(dst_ipv6, 0, 16);
    src_ipv6[0] = 0xfe;
    src_ipv6[1] = 0x80;
    dst_ipv6[0] = 0xff;
    dst_ipv6[1] = 0x02;
    
    // ICMPv6 Echo Request
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV6);
        proto::IPv6  ip6(0x60000000, 8, constants::IP_PROTO_ICMPV6, 255, src_ipv6, dst_ipv6);
        proto::ICMPv6 icmpv6(128, 0, 5000, 1);  // type=128 (echo request)
        
        ip6 / icmpv6;
        eth / ip6;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ ICMPv6 Echo Request sent" << std::endl;
        }
    }
}

/** Example: IGMP Packets */
void craft_igmp_packets(io::Interface& iface) {
    std::cout << "\n=== Crafting IGMP Packets ===" << std::endl;
    
    uint8_t dst_mac[6], src_mac[6];
    uint8_t src_ip[4], dst_ip[4];
    uint8_t group_addr[4];
    
    utils::mac_decode("01:00:5e:00:00:01", dst_mac);  // IGMP multicast MAC
    sock::randomize_mac(src_mac);
    utils::ipv4_decode("192.168.1.50", src_ip);
    utils::ipv4_decode("224.0.0.1", dst_ip);
    utils::ipv4_decode("224.0.0.1", group_addr);
    
    // IGMP v2 Membership Report
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_IGMP);
        proto::IGMP  igmp(0x16, 0, group_addr);  // type=0x16 (v2 report)
        
        ip4 / igmp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ IGMP v2 Membership Report sent (224.0.0.1)" << std::endl;
        }
    }
    
    // IGMP Leave Group
    {
        proto::Ether eth(dst_mac, src_mac, constants::ETH_TYPE_IPV4);
        proto::IPv4  ip4(src_ip, dst_ip, constants::IP_PROTO_IGMP);
        proto::IGMP  igmp(0x17, 0, group_addr);  // type=0x17 (leave group)
        
        ip4 / igmp;
        eth / ip4;
        if (iface.ok()) {
            iface.write(eth);
            std::cout << "  ✓ IGMP Leave Group sent (224.0.0.1)" << std::endl;
        }
    }
}

// MAIN FUNCTION

int main(int argc, char* argv[]) {
    
    std::string iface_name = "wlan0";
    if (argc > 1) {
        iface_name = argv[1];
    }
    
    io::Interface iface(iface_name.c_str());
    iface.open();
    
    if (!iface.ok()) {
        std::cout << "✗ Failed to open interface: " << iface.errmsg() << std::endl;
        return 1;
    }
    
    std::cout << "✓ Interface opened: " << iface_name << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Layer 2 Examples
    craft_ethernet_ipv4_tcp(iface);
    craft_vlan_tagged_frame(iface);
    
    // Layer 3 Examples
    craft_arp_request(iface);
    craft_ipv6_tcp(iface);
    
    // Layer 4 Examples
    craft_tcp_variations(iface);
    craft_udp_packets(iface);
    craft_icmp_packets(iface);
    craft_icmpv6_packets(iface);
    craft_igmp_packets(iface);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "✓ All craft examples completed" << std::endl;
    
    return 0;
}

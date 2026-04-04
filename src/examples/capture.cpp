#include <lynx/lynx>
#include <iostream>
#include <string>
#include <iomanip>

using namespace lynx;

// PROTOCOL DISSECTION HELPERS

/** Print MAC address in dotted format */
std::string format_mac(const uint8_t mac[6]) {
    char buf[18];
    utils::mac_encode(mac, buf);
    return std::string(buf);
}

/** Print IPv4 address in dotted decimal format */
std::string format_ipv4(const uint8_t ip[4]) {
    char buf[16];
    utils::ipv4_encode(ip, buf);
    return std::string(buf);
}

/** Print hex value with optional prefix */
std::string hex_format(uint16_t value, bool with_prefix = true) {
    std::stringstream ss;
    if (with_prefix) ss << "0x";
    ss << std::hex << std::setfill('0') << std::setw(4) << value;
    return ss.str();
}

// LAYER 2 (DATA LINK) DISSECTION

void dissect_ethernet(const std::unique_ptr<proto::Ether>& eth) {
    std::cout << "  [L2] Ethernet:" << std::endl;
    std::cout << "    Source MAC  : " << format_mac(eth->hdr()->src_mac) << std::endl;
    std::cout << "    Dest MAC    : " << format_mac(eth->hdr()->dst_mac) << std::endl;
    std::cout << "    EtherType   : " << hex_format(eth->hdr()->ethertype) << std::endl;
}

void dissect_dot1q(const std::unique_ptr<proto::Dot1Q>& dot1q) {
    std::cout << "  [L2] 802.1Q VLAN Tagged:" << std::endl;
    std::cout << "    Source MAC  : " << format_mac(dot1q->hdr()->src_mac) << std::endl;
    std::cout << "    Dest MAC    : " << format_mac(dot1q->hdr()->dst_mac) << std::endl;
    std::cout << "    TPID        : " << hex_format(dot1q->hdr()->tpid) << std::endl;
    std::cout << "    Priority    : " << (int)dot1q->hdr()->pcp() << std::endl;
    std::cout << "    DEI         : " << (dot1q->hdr()->dei() ? "1" : "0") << std::endl;
    std::cout << "    VLAN ID     : " << dot1q->hdr()->vlan_id() << std::endl;
    std::cout << "    EtherType   : " << hex_format(dot1q->hdr()->ethertype) << std::endl;
}

// LAYER 3 (NETWORK) DISSECTION

void dissect_ipv4(const std::unique_ptr<proto::IPv4>& ip4) {
    std::cout << "  [L3] IPv4:" << std::endl;
    std::cout << "    Version     : " << (int)ip4->hdr()->version() << std::endl;
    std::cout << "    IHL         : " << (int)ip4->hdr()->ihl() << " words" << std::endl;
    std::cout << "    DSCP        : " << (unsigned)ip4->hdr()->dscp() << std::endl;
    std::cout << "    ECN         : " << (unsigned)ip4->hdr()->ecn() << std::endl;
    std::cout << "    Total Length: " << ntohs(ip4->hdr()->total_len) << " bytes" << std::endl;
    std::cout << "    Identification: " << ntohs(ip4->hdr()->id) << std::endl;
    std::cout << "    Flags       : " << (int)ip4->hdr()->ip_flags() << std::endl;
    std::cout << "    Fragment Off: " << ip4->hdr()->frag_off() << std::endl;
    std::cout << "    TTL         : " << (int)ip4->hdr()->ttl << std::endl;
    std::cout << "    Protocol    : " << (int)ip4->hdr()->proto << std::endl;
    std::cout << "    Checksum    : " << hex_format(ip4->hdr()->checksum) << std::endl;
    std::cout << "    Source IP   : " << format_ipv4(ip4->hdr()->src_ip) << std::endl;
    std::cout << "    Dest IP     : " << format_ipv4(ip4->hdr()->dst_ip) << std::endl;
}

void dissect_ipv6(const std::unique_ptr<proto::IPv6>& ip6) {
    std::cout << "  [L3] IPv6:" << std::endl;
    std::cout << "    Version     : " << (int)ip6->hdr()->version() << std::endl;
    std::cout << "    Traffic Cl. : " << (unsigned)ip6->hdr()->traffic_cls() << std::endl;
    std::cout << "    Flow Label  : " << hex_format(ip6->hdr()->flow_label(), false) << std::endl;
    std::cout << "    Payload Len : " << ntohs(ip6->hdr()->payload_len) << " bytes" << std::endl;
    std::cout << "    Next Header : " << (int)ip6->hdr()->next_hdr << std::endl;
    std::cout << "    Hop Limit   : " << (int)ip6->hdr()->hop_limit << std::endl;
}

void dissect_arp(const std::unique_ptr<proto::ARP>& arp) {
    std::cout << "  [L3] ARP:" << std::endl;
    std::cout << "    Hardware Type: " << hex_format(arp->hdr()->htype) << std::endl;
    std::cout << "    Protocol Type: " << hex_format(arp->hdr()->ptype) << std::endl;
    std::cout << "    HW Addr Len : " << (int)arp->hdr()->hlen << std::endl;
    std::cout << "    Prot Addr Len: " << (int)arp->hdr()->plen << std::endl;
    std::cout << "    Operation   : ";
    switch (ntohs(arp->hdr()->oper)) {
        case constants::ARP_OP_REQUEST: std::cout << "Request (1)"; break;
        case constants::ARP_OP_REPLY:   std::cout << "Reply (2)"; break;
        default:                        std::cout << ntohs(arp->hdr()->oper);
    }
    std::cout << std::endl;
    std::cout << "    Sender MAC  : " << format_mac(arp->hdr()->sha) << std::endl;
    std::cout << "    Sender IP   : " << format_ipv4(arp->hdr()->spa) << std::endl;
    std::cout << "    Target MAC  : " << format_mac(arp->hdr()->tha) << std::endl;
    std::cout << "    Target IP   : " << format_ipv4(arp->hdr()->tpa) << std::endl;
}

// LAYER 4 (TRANSPORT) DISSECTION

void dissect_tcp(const std::unique_ptr<proto::TCP>& tcp) {
    std::cout << "  [L4] TCP:" << std::endl;
    std::cout << "    Source Port : " << ntohs(tcp->hdr()->src_port) << std::endl;
    std::cout << "    Dest Port   : " << ntohs(tcp->hdr()->dst_port) << std::endl;
    std::cout << "    Sequence    : " << ntohl(tcp->hdr()->seq) << std::endl;
    std::cout << "    Ack Number  : " << ntohl(tcp->hdr()->ack) << std::endl;
    std::cout << "    Data Offset : " << (int)(tcp->hdr()->data_off >> 4) << " words" << std::endl;
    std::cout << "    Flags       : [";
    if (tcp->hdr()->flags & constants::TCP_FLAG_SYN) std::cout << "SYN ";
    if (tcp->hdr()->flags & constants::TCP_FLAG_ACK) std::cout << "ACK ";
    if (tcp->hdr()->flags & constants::TCP_FLAG_FIN) std::cout << "FIN ";
    if (tcp->hdr()->flags & constants::TCP_FLAG_RST) std::cout << "RST ";
    if (tcp->hdr()->flags & constants::TCP_FLAG_PSH) std::cout << "PSH ";
    if (tcp->hdr()->flags & constants::TCP_FLAG_URG) std::cout << "URG ";
    std::cout << "]" << std::endl;
    std::cout << "    Window Size : " << ntohs(tcp->hdr()->window) << std::endl;
    std::cout << "    Checksum    : " << hex_format(tcp->hdr()->checksum) << std::endl;
    std::cout << "    Urgent Ptr  : " << ntohs(tcp->hdr()->urg_ptr) << std::endl;
}

void dissect_udp(const std::unique_ptr<proto::UDP>& udp) {
    std::cout << "  [L4] UDP:" << std::endl;
    std::cout << "    Source Port : " << ntohs(udp->hdr()->src_port) << std::endl;
    std::cout << "    Dest Port   : " << ntohs(udp->hdr()->dst_port) << std::endl;
    std::cout << "    Length      : " << ntohs(udp->hdr()->length) << " bytes" << std::endl;
    std::cout << "    Checksum    : " << hex_format(udp->hdr()->checksum) << std::endl;
}

void dissect_icmp(const std::unique_ptr<proto::ICMP>& icmp) {
    std::cout << "  [L4] ICMP:" << std::endl;
    std::cout << "    Type        : " << (int)icmp->hdr()->type << " - ";
    switch (icmp->hdr()->type) {
        case 0:  std::cout << "Echo Reply"; break;
        case 3:  std::cout << "Destination Unreachable"; break;
        case 8:  std::cout << "Echo Request"; break;
        case 11: std::cout << "Time Exceeded"; break;
        default: std::cout << "Other";
    }
    std::cout << std::endl;
    std::cout << "    Code        : " << (int)icmp->hdr()->code << std::endl;
    std::cout << "    Checksum    : " << hex_format(icmp->hdr()->checksum) << std::endl;
    std::cout << "    Identifier  : " << icmp->hdr()->id() << std::endl;
    std::cout << "    Sequence    : " << icmp->hdr()->seq() << std::endl;
}

void dissect_icmpv6(const std::unique_ptr<proto::ICMP>& icmpv6) {
    std::cout << "  [L4] ICMPv6:" << std::endl;
    std::cout << "    Type        : " << (int)icmpv6->hdr()->type << " - ";
    switch (icmpv6->hdr()->type) {
        case 128: std::cout << "Echo Request"; break;
        case 129: std::cout << "Echo Reply"; break;
        case 135: std::cout << "Neighbor Solicitation"; break;
        case 136: std::cout << "Neighbor Advertisement"; break;
        default:  std::cout << "Other";
    }
    std::cout << std::endl;
    std::cout << "    Code        : " << (int)icmpv6->hdr()->code << std::endl;
    std::cout << "    Checksum    : " << hex_format(icmpv6->hdr()->checksum) << std::endl;
}

void dissect_igmp(const std::unique_ptr<proto::IGMP>& igmp) {
    std::cout << "  [L4] IGMP:" << std::endl;
    std::cout << "    Type        : " << hex_format(igmp->hdr()->type, false) << " - ";
    switch (igmp->hdr()->type) {
        case 0x11: std::cout << "Membership Query"; break;
        case 0x16: std::cout << "Membership Report v2"; break;
        case 0x17: std::cout << "Leave Group"; break;
        case 0x22: std::cout << "Membership Report v3"; break;
        default:   std::cout << "Other";
    }
    std::cout << std::endl;
    std::cout << "    Max Resp    : " << (int)igmp->hdr()->max_resp << std::endl;
    std::cout << "    Checksum    : " << hex_format(igmp->hdr()->checksum) << std::endl;
    std::cout << "    Group Addr  : " << format_ipv4(igmp->hdr()->group_addr) << std::endl;
}

// PACKET CAPTURE CALLBACK

io::RecvAction captured(const proto::RawFrame& rf) {
    static int packet_count = 0;
    
    if (!rf.ok()) {
        std::cout << "✗ Frame error: " << rf.errmsg() << std::endl;
        return io::RecvAction::Continue;
    }
    
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "Packet #" << (++packet_count) << " - Frame Type: ";
    
    switch (rf.type()) {
    case proto::FrameType::Eth:
    {
        std::cout << "Ethernet II" << std::endl;
        std::unique_ptr<proto::Ether> eth = rf.as<proto::Ether>();
        if (!eth || !eth->ok()) {
            std::cout << "  ✗ Failed to parse Ethernet" << std::endl;
            return io::RecvAction::Continue;
        }
        
        dissect_ethernet(eth);
        
        // Check for IPv4
        if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV4) {
            std::unique_ptr<proto::IPv4> ip4 = eth->as<proto::IPv4>();
            if (ip4 && ip4->ok()) {
                dissect_ipv4(ip4);
                
                // Check L4 protocol type
                switch (ip4->hdr()->proto) {
                case constants::IP_PROTO_TCP: {
                    std::unique_ptr<proto::TCP> tcp = ip4->as<proto::TCP>();
                    if (tcp && tcp->ok()) dissect_tcp(tcp);
                    break;
                }
                case constants::IP_PROTO_UDP: {
                    std::unique_ptr<proto::UDP> udp = ip4->as<proto::UDP>();
                    if (udp && udp->ok()) dissect_udp(udp);
                    break;
                }
                case constants::IP_PROTO_ICMP: {
                    std::unique_ptr<proto::ICMP> icmp = ip4->as<proto::ICMP>();
                    if (icmp && icmp->ok()) dissect_icmp(icmp);
                    break;
                }
                case constants::IP_PROTO_IGMP: {
                    std::unique_ptr<proto::IGMP> igmp = ip4->as<proto::IGMP>();
                    if (igmp && igmp->ok()) dissect_igmp(igmp);
                    break;
                }
                default:
                    std::cout << "  [L4] Protocol: " << (int)ip4->hdr()->proto << " (unknown)" << std::endl;
                }
            }
        }
        // Check for IPv6
        else if (eth->hdr()->ethertype == constants::ETH_TYPE_IPV6) {
            std::unique_ptr<proto::IPv6> ip6 = eth->as<proto::IPv6>();
            if (ip6 && ip6->ok()) {
                dissect_ipv6(ip6);
                
                switch (ip6->hdr()->next_hdr) {
                case constants::IP_PROTO_TCP: {
                    std::unique_ptr<proto::TCP> tcp = ip6->as<proto::TCP>();
                    if (tcp && tcp->ok()) dissect_tcp(tcp);
                    break;
                }
                case constants::IP_PROTO_UDP: {
                    std::unique_ptr<proto::UDP> udp = ip6->as<proto::UDP>();
                    if (udp && udp->ok()) dissect_udp(udp);
                    break;
                }
                case constants::IP_PROTO_ICMPV6: {
                    std::unique_ptr<proto::ICMP> icmpv6 = ip6->as<proto::ICMP>();
                    if (icmpv6 && icmpv6->ok()) dissect_icmpv6(icmpv6);
                    break;
                }
                default:
                    std::cout << "  [L4] Protocol: " << (int)ip6->hdr()->next_hdr << " (unknown)" << std::endl;
                }
            }
        }
        // Check for ARP
        else if (eth->hdr()->ethertype == constants::ETH_TYPE_ARP) {
            std::unique_ptr<proto::ARP> arp = eth->as<proto::ARP>();
            if (arp && arp->ok()) {
                dissect_arp(arp);
            }
        }
        else {
            std::cout << "  [L3] EtherType not supported: " << hex_format(eth->hdr()->ethertype) << std::endl;
        }
        break;
    }
    
    case proto::FrameType::Dot1Q:
    {
        std::cout << "802.1Q VLAN Tagged" << std::endl;
        std::unique_ptr<proto::Dot1Q> dot1q = rf.as<proto::Dot1Q>();
        if (!dot1q || !dot1q->ok()) {
            std::cout << "  ✗ Failed to parse Dot1Q" << std::endl;
            return io::RecvAction::Continue;
        }
        
        dissect_dot1q(dot1q);
        
        // Similar dissection as Ethernet for VLAN payload
        if (dot1q->hdr()->ethertype == constants::ETH_TYPE_IPV4) {
            std::unique_ptr<proto::IPv4> ip4 = dot1q->as<proto::IPv4>();
            if (ip4 && ip4->ok()) dissect_ipv4(ip4);
        }
        break;
    }
    
    case proto::FrameType::Unknown:
    default:
        std::cout << "Unknown" << std::endl;
        std::cout << "  Frame length: " << rf.len() << " bytes" << std::endl;
        break;
    }
    
    return io::RecvAction::Continue;  // Keep capturing
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
    
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Protocol Capture Example" << std::endl;
    std::cout << "Interface: " << iface_name << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Capturing packets... (Press Ctrl+C to stop)" << std::endl;
    std::cout << std::endl;
    
    // Start capturing with callback
    iface.capture(captured);
    
    std::cout << "\nCapture stopped." << std::endl;
    
    return 0;
}
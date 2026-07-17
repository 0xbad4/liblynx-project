//  14 — PPP frame crafting
//
//  demonstrates:
//    • PPP default constructor (address=0xFF, control=0x03, proto=IP)
//    • PPP with specific protocol field
//    • PPP protocol constants
//    • hdr()->is_ipv4(), is_lcp(), is_chap(), etc.
//    • stacking PPP / IPv4, PPP / LCP
//    • FrameType::PPP

#include <lynx/lynx>
#include <cstdio>

using namespace lynx;
using namespace lynx::proto;
using namespace lynx::constants;

static void hexdump(const uint8_t* data, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int main()
{
    printf("=== Example 14: PPP Frame Crafting ===\n\n");

    // ── 1. default constructor 
    printf("[1] PPP default constructor\n");

    PPP ppp;
    printf("  address  : 0x%02X (PPP_ADDRESS)\n", ppp.hdr()->address);
    printf("  control  : 0x%02X (PPP_CONTROL)\n", ppp.hdr()->control);
    printf("  protocol : 0x%04X (PPP_PROTO_IP)\n", ppp.hdr()->protocol);
    printf("  is_ipv4(): %s\n", ppp.hdr()->is_ipv4() ? "true" : "false");
    printf("  is_lcp() : %s\n", ppp.hdr()->is_lcp()  ? "true" : "false");
    printf("  type()   : %s\n",
           ppp.type() == FrameType::PPP ? "PPP" : "other");
    printf("  hdr_size : %u bytes\n", ppp.hdr_size());

    // ── 2. PPP / IPv4 
    printf("\n[2] PPP / IPv4\n");

    auto src = utils::ipv4_decode("10.0.0.1");
    auto dst = utils::ipv4_decode("10.0.0.2");

    PPP ppp_ip(PPP_ADDRESS, PPP_CONTROL, PPP_PROTO_IP);
    IPv4 ip(src.data, dst.data, IP_PROTO_TCP);
    ip.hdr()->total_len = ip.hdr_size();

    ppp_ip / ip;

    printf("  protocol  : 0x%04X (IP)\n", ppp_ip.hdr()->protocol);
    printf("  is_ipv4() : %s\n", ppp_ip.hdr()->is_ipv4() ? "true" : "false");
    printf("  size()    : %u\n", ppp_ip.size());

    Buffer buf2 = Buffer::alloc(ppp_ip.size());
    ppp_ip.serialize(buf2);
    printf("  serialized (%u bytes):\n  ", buf2.len());
    hexdump(buf2.begin(), buf2.len());

    // ── 3. PPP / LCP 
    printf("\n[3] PPP / LCP\n");

    PPP ppp_lcp(PPP_ADDRESS, PPP_CONTROL, PPP_PROTO_LCP);
    LCP lcp(PPP_CODE_ECHO_REQ, 42);

    ppp_lcp / lcp;

    printf("  protocol : 0x%04X (LCP)\n", ppp_lcp.hdr()->protocol);
    printf("  is_lcp() : %s\n", ppp_lcp.hdr()->is_lcp() ? "true" : "false");

    Buffer buf3 = Buffer::alloc(ppp_lcp.size());
    ppp_lcp.serialize(buf3);
    printf("  serialized (%u bytes):\n  ", buf3.len());
    hexdump(buf3.begin(), buf3.len());

    // ── 4. protocol type checks 
    printf("\n[4] Protocol type checks\n");

    hdrs::HdrPPP h{};
    h.address = PPP_ADDRESS;
    h.control = PPP_CONTROL;

    h.protocol = PPP_PROTO_IPV6;
    printf("  0x%04X → is_ipv6()  : %s\n", h.protocol, h.is_ipv6()  ? "true" : "false");
    h.protocol = PPP_PROTO_IPCP;
    printf("  0x%04X → is_ipcp()  : %s\n", h.protocol, h.is_ipcp()  ? "true" : "false");
    h.protocol = PPP_PROTO_IPV6CP;
    printf("  0x%04X → is_ipv6cp(): %s\n", h.protocol, h.is_ipv6cp()? "true" : "false");
    h.protocol = PPP_PROTO_PAP;
    printf("  0x%04X → is_pap()   : %s\n", h.protocol, h.is_pap()   ? "true" : "false");
    h.protocol = PPP_PROTO_CHAP;
    printf("  0x%04X → is_chap()  : %s\n", h.protocol, h.is_chap()  ? "true" : "false");
    h.protocol = PPP_PROTO_CCP;
    printf("  0x%04X → is_ccp()   : %s\n", h.protocol, h.is_ccp()   ? "true" : "false");

    // ── 5. PPP protocol constants 
    printf("\n[5] PPP protocol constants\n");
    printf("  PPP_PROTO_IP     = 0x%04X\n", PPP_PROTO_IP);
    printf("  PPP_PROTO_IPV6   = 0x%04X\n", PPP_PROTO_IPV6);
    printf("  PPP_PROTO_LCP    = 0x%04X\n", PPP_PROTO_LCP);
    printf("  PPP_PROTO_PAP    = 0x%04X\n", PPP_PROTO_PAP);
    printf("  PPP_PROTO_CHAP   = 0x%04X\n", PPP_PROTO_CHAP);
    printf("  PPP_PROTO_IPCP   = 0x%04X\n", PPP_PROTO_IPCP);
    printf("  PPP_PROTO_IPV6CP = 0x%04X\n", PPP_PROTO_IPV6CP);

    printf("\ndone.\n");
    return 0;
}

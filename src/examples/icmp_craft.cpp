//  08 — ICMP echo request / reply / unreachable crafting
//
//  demonstrates:
//    • ICMP echo request and reply
//    • ICMP destination unreachable
//    • all ICMP type/code constants
//    • hdr() accessors: id(), seq(), set_id_seq()
//    • checksum auto-computed (no pseudo-header for ICMPv4)
//    • stacking IPv4 / ICMP

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
    printf("=== Example 08: ICMP Crafting ===\n\n");

    auto src = utils::ipv4_decode("10.0.0.1");
    auto dst = utils::ipv4_decode("10.0.0.2");

    // ── 1. ICMP echo request 
    printf("[1] ICMP Echo Request (ping)\n");

    IPv4 ip(src.data, dst.data, IP_PROTO_ICMP);

    ICMP echo_req(ICMP_ECHO_REQUEST, 0, /*id=*/0x1234, /*seq=*/1);

    printf("  type     : %u (echo request)\n", echo_req.hdr()->type);
    printf("  code     : %u\n", echo_req.hdr()->code);
    printf("  id()     : 0x%04X\n", echo_req.hdr()->id());
    printf("  seq()    : %u\n", echo_req.hdr()->seq());
    printf("  proto()  : %u (ICMP)\n", echo_req.proto());

    // add timestamp-like payload
    const uint8_t ping_data[] = {
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    Raw payload(ping_data, sizeof(ping_data));
    echo_req / payload;

    ip.hdr()->total_len = ip.hdr_size() + echo_req.size();
    ip / echo_req;

    printf("  checksum : 0x%04X (auto, no pseudo-header)\n",
           echo_req.hdr()->checksum);

    Buffer buf1 = Buffer::alloc(ip.size());
    ip.serialize(buf1);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. ICMP echo reply 
    printf("\n[2] ICMP Echo Reply\n");

    ICMP echo_rep(ICMP_ECHO_REPLY, 0, 0x1234, 1);
    printf("  type: %u (echo reply)\n", echo_rep.hdr()->type);

    // ── 3. ICMP destination unreachable 
    printf("\n[3] ICMP Destination Unreachable\n");

    ICMP unreach(ICMP_DST_UNREACH, ICMP_UNREACH_PORT);
    printf("  type: %u (dest unreachable)\n", unreach.hdr()->type);
    printf("  code: %u (port unreachable)\n", unreach.hdr()->code);

    // ── 4. set_id_seq() 
    printf("\n[4] set_id_seq()\n");

    ICMP pkt;
    pkt.hdr()->type = ICMP_ECHO_REQUEST;
    pkt.hdr()->code = 0;
    pkt.hdr()->set_id_seq(0xABCD, 42);
    printf("  id()  : 0x%04X\n", pkt.hdr()->id());
    printf("  seq() : %u\n", pkt.hdr()->seq());

    // ── 5. ICMP constants reference 
    printf("\n[5] ICMP constants\n");
    printf("  ECHO_REPLY     = %u\n", ICMP_ECHO_REPLY);
    printf("  DST_UNREACH    = %u\n", ICMP_DST_UNREACH);
    printf("  REDIRECT       = %u\n", ICMP_REDIRECT);
    printf("  ECHO_REQUEST   = %u\n", ICMP_ECHO_REQUEST);
    printf("  TIME_EXCEED    = %u\n", ICMP_TIME_EXCEED);
    printf("  UNREACH_NET    = %u\n", ICMP_UNREACH_NET);
    printf("  UNREACH_HOST   = %u\n", ICMP_UNREACH_HOST);
    printf("  UNREACH_PROTO  = %u\n", ICMP_UNREACH_PROTO);
    printf("  UNREACH_PORT   = %u\n", ICMP_UNREACH_PORT);

    printf("\ndone.\n");
    return 0;
}

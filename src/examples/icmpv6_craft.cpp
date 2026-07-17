//  09 — ICMPv6 echo crafting
//
//  demonstrates:
//    • ICMPv6 echo request over IPv6
//    • checksum uses IPv6 pseudo-header (auto via patch_checksum)
//    • ICMPv6 type constants (echo, NDP)
//    • stacking IPv6 / ICMPv6

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
    printf("=== Example 09: ICMPv6 Crafting ===\n\n");

    auto src = utils::ipv6_decode("fe80:0000:0000:0000:0000:0000:0000:0001");
    auto dst = utils::ipv6_decode("fe80:0000:0000:0000:0000:0000:0000:0002");

    // ── 1. ICMPv6 echo request 
    printf("[1] ICMPv6 Echo Request (ping6)\n");

    IPv6 ip6(
        (6u << 28),            // ver_tc_fl
        0,                     // payload_len (auto)
        IP_PROTO_ICMPV6,       // next header = 58
        64,                    // hop limit
        src.data, dst.data
    );

    ICMPv6 echo(ICMPV6_ECHO_REQUEST, 0, /*id=*/0x0001, /*seq=*/1);

    printf("  type     : %u (echo request)\n", echo.hdr()->type);
    printf("  code     : %u\n", echo.hdr()->code);
    printf("  id()     : 0x%04X\n", echo.hdr()->id());
    printf("  seq()    : %u\n", echo.hdr()->seq());
    printf("  proto()  : %u (ICMPv6)\n", echo.proto());

    // add payload
    const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    Raw payload(data, sizeof(data));
    echo / payload;

    // stack: IPv6 / ICMPv6 auto-computes checksum with pseudo-header
    ip6 / echo;
    printf("  checksum : 0x%04X (IPv6 pseudo-header)\n", echo.hdr()->checksum);

    Buffer buf = Buffer::alloc(ip6.size());
    ip6.serialize(buf);
    printf("  serialized (%u bytes):\n  ", buf.len());
    hexdump(buf.begin(), buf.len());

    // ── 2. ICMPv6 echo reply 
    printf("\n[2] ICMPv6 Echo Reply\n");
    ICMPv6 reply(ICMPV6_ECHO_REPLY, 0, 0x0001, 1);
    printf("  type: %u (echo reply)\n", reply.hdr()->type);

    // ── 3. ICMPv6 constants reference 
    printf("\n[3] ICMPv6 constants\n");
    printf("  DST_UNREACH   = %u\n",  ICMPV6_DST_UNREACH);
    printf("  TIME_EXCEED   = %u\n",  ICMPV6_TIME_EXCEED);
    printf("  ECHO_REQUEST  = %u\n",  ICMPV6_ECHO_REQUEST);
    printf("  ECHO_REPLY    = %u\n",  ICMPV6_ECHO_REPLY);
    printf("  RS (router sol)   = %u\n", ICMPV6_RS);
    printf("  RA (router adv)   = %u\n", ICMPV6_RA);
    printf("  NS (neighbor sol) = %u\n", ICMPV6_NS);
    printf("  NA (neighbor adv) = %u\n", ICMPV6_NA);

    printf("\ndone.\n");
    return 0;
}

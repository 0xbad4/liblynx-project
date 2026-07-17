//  05 — IPv6 packet crafting
//
//  demonstrates:
//    • default constructor (version=6, hop_limit=64, next_hdr=NONXT)
//    • full constructor with all fields
//    • sub-byte accessors: version(), traffic_cls(), flow_label()
//    • set_ver_tc_fl()
//    • stacking IPv6 / Raw(payload)
//    • payload_len auto-computed in serialize()
//    • ethertype() returns ETH_TYPE_IPV6

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
    printf("=== Example 05: IPv6 Packet Crafting ===\n\n");

    auto src = utils::ipv6_decode("2001:0db8:0000:0000:0000:0000:0000:0001");
    auto dst = utils::ipv6_decode("2001:0db8:0000:0000:0000:0000:0000:0002");

    // ── 1. default constructor 
    printf("[1] IPv6 default constructor\n");

    IPv6 ip;
    printf("  version()     : %u\n",   ip.hdr()->version());
    printf("  traffic_cls() : %u\n",   ip.hdr()->traffic_cls());
    printf("  flow_label()  : 0x%05X\n", ip.hdr()->flow_label());
    printf("  next_hdr      : %u (No Next Header)\n", ip.hdr()->next_hdr);
    printf("  hop_limit     : %u\n",   ip.hdr()->hop_limit);
    printf("  hdr_size()    : %u bytes\n", ip.hdr_size());
    printf("  ethertype()   : 0x%04X\n", ip.ethertype());

    // ── 2. full constructor 
    printf("\n[2] IPv6 full constructor\n");

    uint32_t vtc_flow = (6u << 28) | (0x0A << 20) | 0x12345;  // ver=6, tc=0x0A, fl=0x12345

    IPv6 ip2(
        vtc_flow,          // ver_tc_fl
        0,                 // payload_len (auto in serialize)
        IP_PROTO_TCP,      // next header
        64,                // hop limit
        src.data,          // src
        dst.data           // dst
    );

    printf("  src         : %s\n", utils::ipv6_encode(ip2.hdr()->src_ip).data);
    printf("  dst         : %s\n", utils::ipv6_encode(ip2.hdr()->dst_ip).data);
    printf("  version()   : %u\n", ip2.hdr()->version());
    printf("  traffic_cls : 0x%02X\n", ip2.hdr()->traffic_cls());
    printf("  flow_label  : 0x%05X\n", ip2.hdr()->flow_label());
    printf("  next_hdr    : %u (TCP)\n", ip2.hdr()->next_hdr);

    // ── 3. set_ver_tc_fl() 
    printf("\n[3] set_ver_tc_fl()\n");

    ip2.hdr()->set_ver_tc_fl(6, 0xB8, 0xABCDE);  // DSCP=46(EF) in tc
    printf("  traffic_cls : 0x%02X\n", ip2.hdr()->traffic_cls());
    printf("  flow_label  : 0x%05X\n", ip2.hdr()->flow_label());

    // ── 4. stack IPv6 / Raw 
    printf("\n[4] IPv6 / Raw payload\n");

    const uint8_t payload[] = "Hello from IPv6!";
    Raw raw(payload, sizeof(payload) - 1);

    ip2 / raw;

    printf("  size()      : %u (hdr + load)\n", ip2.size());

    Buffer buf = Buffer::alloc(ip2.size());
    ip2.serialize(buf);

    if (!buf.ok()) {
        printf("  buffer error: %s\n", buf.errmsg());
        return 1;
    }

    printf("  serialized (%u bytes):\n  ", buf.len());
    hexdump(buf.begin(), buf.len());

    printf("\ndone.\n");
    return 0;
}

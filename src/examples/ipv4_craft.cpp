//  04 — IPv4 packet crafting
//
//  demonstrates:
//    • default constructor (ver=4, ihl=5, DF=1, TTL=64)
//    • full constructor with all fields
//    • sub-byte accessors: version(), ihl(), dscp(), ecn(), ip_flags()
//    • set_ver_ihl(), set_dscp_ecn(), set_flags_frag()
//    • stacking IPv4 / Raw(payload)
//    • ethertype() returns ETH_TYPE_IPV4
//    • serialization

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
    printf("=== Example 04: IPv4 Packet Crafting ===\n\n");

    auto src_ip = utils::ipv4_decode("10.0.0.1");
    auto dst_ip = utils::ipv4_decode("10.0.0.2");

    // ── 1. default constructor 
    printf("[1] IPv4 default constructor\n");

    IPv4 ip;
    printf("  version()  : %u\n", ip.hdr()->version());
    printf("  ihl()      : %u (header = %u bytes)\n",
           ip.hdr()->ihl(), ip.hdr()->hdr_len());
    printf("  ttl        : %u\n", ip.hdr()->ttl);
    printf("  ip_flags() : 0x%02X (DF=%s)\n",
           ip.hdr()->ip_flags(),
           (ip.hdr()->ip_flags() & 0x02) ? "set" : "clear");
    printf("  ethertype(): 0x%04X\n", ip.ethertype());
    printf("  hdr_size() : %u bytes\n", ip.hdr_size());

    // ── 2. full constructor 
    printf("\n[2] IPv4 full constructor\n");

    IPv4 ip2(
        src_ip.data,     // src
        dst_ip.data,     // dst
        IP_PROTO_TCP,    // proto
        0,               // total_len (set below)
        0x1234,          // id
        0x4000,          // flags_frag: DF=1
        128,             // ttl
        0                // dscp_ecn
    );

    printf("  src: %s\n", utils::ipv4_encode(ip2.hdr()->src_ip).data);
    printf("  dst: %s\n", utils::ipv4_encode(ip2.hdr()->dst_ip).data);
    printf("  proto: %u (TCP)\n", ip2.hdr()->proto);
    printf("  ttl: %u\n", ip2.hdr()->ttl);
    printf("  id: 0x%04X\n", ip2.hdr()->id);

    // ── 3. sub-byte setters 
    printf("\n[3] Sub-byte field setters\n");

    ip2.hdr()->set_dscp_ecn(46, 0);  // DSCP=46 (EF), ECN=0
    printf("  dscp()     : %u (EF = expedited forwarding)\n", ip2.hdr()->dscp());
    printf("  ecn()      : %u\n", ip2.hdr()->ecn());

    ip2.hdr()->set_flags_frag(0x02, 0);  // DF=1, MF=0, offset=0
    printf("  ip_flags() : 0x%02X\n", ip2.hdr()->ip_flags());
    printf("  frag_off() : %u\n", ip2.hdr()->frag_off());

    // ── 4. stack IPv4 / Raw 
    printf("\n[4] IPv4 / Raw payload\n");

    const uint8_t payload[] = "Hello from IPv4!";
    Raw raw(payload, sizeof(payload) - 1);

    // set total_len = header + payload
    ip2.hdr()->total_len = ip2.hdr_size() + (sizeof(payload) - 1);

    ip2 / raw;

    printf("  total_len  : %u\n", ip2.hdr()->total_len);
    printf("  size()     : %u (hdr + load)\n", ip2.size());

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

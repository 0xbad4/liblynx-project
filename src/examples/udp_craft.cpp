//  07 — UDP datagram crafting over IPv4 and IPv6
//
//  demonstrates:
//    • UDP over IPv4 with payload
//    • UDP over IPv6 with payload
//    • auto-checksum via pseudo-header (mandatory in IPv6)
//    • stacking IPv4 / UDP and IPv6 / UDP

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
    printf("=== Example 07: UDP Datagram Crafting ===\n\n");

    // ── 1. UDP over IPv4 
    printf("[1] UDP over IPv4\n");

    auto src_ip = utils::ipv4_decode("192.168.1.10");
    auto dst_ip = utils::ipv4_decode("8.8.8.8");

    IPv4 ip(src_ip.data, dst_ip.data, IP_PROTO_UDP);

    UDP udp;
    udp.hdr()->src_port = 54321;
    udp.hdr()->dst_port = PORT_DNS;  // 53

    // add payload
    const uint8_t dns_query[] = {
        0x12, 0x34,  // transaction ID
        0x01, 0x00,  // flags: standard query
        0x00, 0x01,  // questions: 1
        0x00, 0x00,  // answers: 0
        0x00, 0x00,  // authority: 0
        0x00, 0x00,  // additional: 0
    };
    Raw payload(dns_query, sizeof(dns_query));
    udp / payload;

    // set UDP length: header + payload
    udp.hdr()->length = UDP_HDR_LEN + sizeof(dns_query);

    // set IPv4 total_len
    ip.hdr()->total_len = ip.hdr_size() + udp.size();

    // stack: IPv4 / UDP auto-computes checksum
    ip / udp;

    printf("  src_port : %u\n", udp.hdr()->src_port);
    printf("  dst_port : %u (DNS)\n", udp.hdr()->dst_port);
    printf("  length   : %u\n", udp.hdr()->length);
    printf("  checksum : 0x%04X (auto-computed)\n", udp.hdr()->checksum);
    printf("  proto()  : %u (UDP)\n", udp.proto());
    printf("  hdr_size : %u bytes\n", udp.hdr_size());

    Buffer buf1 = Buffer::alloc(ip.size());
    ip.serialize(buf1);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. UDP over IPv6 
    printf("\n[2] UDP over IPv6 (checksum mandatory)\n");

    auto src6 = utils::ipv6_decode("2001:0db8:0000:0000:0000:0000:0000:0001");
    auto dst6 = utils::ipv6_decode("2001:0db8:0000:0000:0000:0000:0000:0002");

    IPv6 ip6(
        (6u << 28),       // ver_tc_fl
        0,                // payload_len (auto)
        IP_PROTO_UDP,     // next header
        64,               // hop limit
        src6.data,
        dst6.data
    );

    UDP udp6;
    udp6.hdr()->src_port = 5000;
    udp6.hdr()->dst_port = 5001;

    const uint8_t msg[] = "Hello over IPv6 UDP!";
    Raw raw6(msg, sizeof(msg) - 1);
    udp6 / raw6;

    udp6.hdr()->length = UDP_HDR_LEN + (sizeof(msg) - 1);

    ip6 / udp6;

    printf("  checksum : 0x%04X (mandatory in IPv6)\n", udp6.hdr()->checksum);

    Buffer buf2 = Buffer::alloc(ip6.size());
    ip6.serialize(buf2);
    printf("  serialized (%u bytes):\n  ", buf2.len());
    hexdump(buf2.begin(), buf2.len());

    printf("\ndone.\n");
    return 0;
}

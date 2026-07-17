//  06 — TCP segment crafting over IPv4
//
//  demonstrates:
//    • TCP SYN, SYN-ACK, PSH|ACK, FIN|ACK, RST
//    • all TCP flag constants
//    • stacking IPv4 / TCP (auto pseudo-header checksum)
//    • hdr() accessors: hdr_len(), flag(), set_data_off()
//    • adding payload to TCP
//    • proto() returns IP_PROTO_TCP

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
    printf("=== Example 06: TCP Segment Crafting ===\n\n");

    auto src_ip = utils::ipv4_decode("10.0.0.1");
    auto dst_ip = utils::ipv4_decode("10.0.0.2");

    // ── 1. TCP SYN 
    printf("[1] TCP SYN\n");

    IPv4 ip(src_ip.data, dst_ip.data, IP_PROTO_TCP);

    TCP syn(
        12345,                // src_port
        PORT_HTTP,            // dst_port (80)
        1000,                 // seq
        0,                    // ack
        TCP_FLAG_SYN,         // flags: SYN
        65535                 // window
    );

    printf("  src_port : %u\n", syn.hdr()->src_port);
    printf("  dst_port : %u\n", syn.hdr()->dst_port);
    printf("  seq      : %u\n", syn.hdr()->seq);
    printf("  flags    : 0x%02X (SYN)\n", syn.hdr()->flags);
    printf("  window   : %u\n", syn.hdr()->window);
    printf("  hdr_len(): %u (in 32b words)\n", syn.hdr()->hdr_len());
    printf("  proto()  : %u (TCP)\n", syn.proto());

    // total_len must account for IP header + TCP
    ip.hdr()->total_len = ip.hdr_size() + syn.size();

    // stacking: IPv4 / TCP computes TCP checksum via pseudo-header
    ip / syn;

    printf("  checksum : 0x%04X (auto-computed)\n", syn.hdr()->checksum);

    Buffer buf1 = Buffer::alloc(ip.size());
    ip.serialize(buf1);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. TCP SYN-ACK 
    printf("\n[2] TCP SYN-ACK\n");

    TCP synack(80, 12345, 5000, 1001,
               TCP_FLAG_SYN_ACK,  // SYN|ACK combo
               32768);
    printf("  flags: 0x%02X (SYN|ACK)\n", synack.hdr()->flags);

    // ── 3. TCP PSH|ACK with payload 
    printf("\n[3] TCP PSH|ACK with payload\n");

    IPv4 ip3(src_ip.data, dst_ip.data, IP_PROTO_TCP);

    TCP data_seg(12345, 80, 1001, 5001,
                 TCP_FLAG_PSH | TCP_FLAG_ACK,
                 65535);

    const uint8_t http_req[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Raw payload(http_req, sizeof(http_req) - 1);
    data_seg / payload;

    ip3.hdr()->total_len = ip3.hdr_size() + data_seg.size();
    ip3 / data_seg;

    printf("  payload  : %zu bytes\n", data_seg.load().size());
    printf("  checksum : 0x%04X\n", data_seg.hdr()->checksum);

    Buffer buf3 = Buffer::alloc(ip3.size());
    ip3.serialize(buf3);
    printf("  serialized (%u bytes):\n  ", buf3.len());
    hexdump(buf3.begin(), buf3.len());

    // ── 4. flag constants reference 
    printf("\n[4] TCP flag constants\n");
    printf("  FIN     = 0x%03X\n", TCP_FLAG_FIN);
    printf("  SYN     = 0x%03X\n", TCP_FLAG_SYN);
    printf("  RST     = 0x%03X\n", TCP_FLAG_RST);
    printf("  PSH     = 0x%03X\n", TCP_FLAG_PSH);
    printf("  ACK     = 0x%03X\n", TCP_FLAG_ACK);
    printf("  URG     = 0x%03X\n", TCP_FLAG_URG);
    printf("  ECE     = 0x%03X\n", TCP_FLAG_ECE);
    printf("  CWR     = 0x%03X\n", TCP_FLAG_CWR);
    printf("  NS      = 0x%03X\n", TCP_FLAG_NS);
    printf("  SYN_ACK = 0x%03X\n", TCP_FLAG_SYN_ACK);
    printf("  FIN_ACK = 0x%03X\n", TCP_FLAG_FIN_ACK);
    printf("  RST_ACK = 0x%03X\n", TCP_FLAG_RST_ACK);

    printf("\ndone.\n");
    return 0;
}

//  02 — ARP request / reply crafting
//
//  demonstrates:
//    • ARP request (who-has) and ARP reply
//    • all ARP constants
//    • header field accessors
//    • serialization to buffer

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
    printf("=== Example 02: ARP Crafting ===\n\n");

    auto my_mac  = utils::mac_decode("aa:bb:cc:dd:ee:ff");
    auto my_ip   = utils::ipv4_decode("192.168.1.100");
    auto tgt_ip  = utils::ipv4_decode("192.168.1.1");
    uint8_t zero_mac[6] = {};

    // ── 1. ARP request 
    printf("[1] ARP Request (who-has %s)\n",
           utils::ipv4_encode(tgt_ip.data).data);

    ARP req(
        ARP_HRD_ETHER,            // htype: Ethernet
        ETH_TYPE_IPV4,             // ptype: IPv4
        ARP_HLEN_ETH,             // hlen:  6 (MAC length)
        ARP_PLEN_IPV4,            // plen:  4 (IPv4 length)
        ARP_OP_REQUEST,           // oper:  request
        my_mac.data,              // sha:   sender MAC
        my_ip.data,               // spa:   sender IP
        zero_mac,                 // tha:   unknown target MAC
        tgt_ip.data               // tpa:   target IP
    );

    if (!req.ok()) {
        printf("  error: %s\n", req.errmsg());
        return 1;
    }

    printf("  htype : 0x%04X (Ethernet)\n", req.hdr()->htype);
    printf("  ptype : 0x%04X (IPv4)\n",     req.hdr()->ptype);
    printf("  hlen  : %u\n",                req.hdr()->hlen);
    printf("  plen  : %u\n",                req.hdr()->plen);
    printf("  oper  : %u (request)\n",      req.hdr()->oper);
    printf("  sha   : %s\n", utils::mac_encode(req.hdr()->sha).data);
    printf("  spa   : %s\n", utils::ipv4_encode(req.hdr()->spa).data);
    printf("  tha   : %s\n", utils::mac_encode(req.hdr()->tha).data);
    printf("  tpa   : %s\n", utils::ipv4_encode(req.hdr()->tpa).data);
    printf("  ethertype(): 0x%04X (ARP)\n", req.ethertype());
    printf("  is_broadcast(): %s\n", req.is_broadcast() ? "true" : "false");

    Buffer buf1 = Buffer::alloc(req.size());
    req.serialize(buf1);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. ARP reply 
    printf("\n[2] ARP Reply\n");

    auto tgt_mac = utils::mac_decode("de:ad:be:ef:00:01");

    ARP reply;
    reply.hdr()->oper = ARP_OP_REPLY;
    std::memcpy(reply.hdr()->sha, tgt_mac.data, 6);
    std::memcpy(reply.hdr()->spa, tgt_ip.data, 4);
    std::memcpy(reply.hdr()->tha, my_mac.data, 6);
    std::memcpy(reply.hdr()->tpa, my_ip.data, 4);

    printf("  oper  : %u (reply)\n", reply.hdr()->oper);
    printf("  sha   : %s\n", utils::mac_encode(reply.hdr()->sha).data);
    printf("  spa   : %s\n", utils::ipv4_encode(reply.hdr()->spa).data);

    Buffer buf2 = Buffer::alloc(reply.size());
    reply.serialize(buf2);
    printf("  serialized (%u bytes):\n  ", buf2.len());
    hexdump(buf2.begin(), buf2.len());

    // ── 3. default constructor 
    printf("\n[3] ARP default constructor\n");
    ARP def;
    printf("  htype : 0x%04X (ARP_HRD_ETHER)\n", def.hdr()->htype);
    printf("  ptype : 0x%04X (ETH_TYPE_IPV4)\n",  def.hdr()->ptype);
    printf("  oper  : %u (ARP_OP_REQUEST)\n",      def.hdr()->oper);
    printf("  hdr_size(): %u bytes\n",             def.hdr_size());

    printf("\ndone.\n");
    return 0;
}

//  01 — Ethernet frame crafting
//
//  demonstrates:
//    • constructing Ether from MACs + ethertype
//    • constructing Ether from HdrEth struct
//    • stacking Ether / Raw(payload)
//    • serializing to Buffer and hex-dumping
//    • MAC encode/decode utilities

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
    printf("=== Example 01: Ethernet Frame Crafting ===\n\n");

    // ── 1. construct from MAC byte arrays + ethertype 
    printf("[1] Ether from raw MAC arrays\n");

    auto src = utils::mac_decode("aa:bb:cc:dd:ee:ff");
    auto dst = utils::mac_decode("11:22:33:44:55:66");

    Ether eth1(dst.data, src.data, ETH_TYPE_IPV4);

    if (!eth1.ok()) {
        printf("  error: %s\n", eth1.errmsg());
        return 1;
    }

    printf("  src MAC : %s\n", utils::mac_encode(eth1.hdr()->src_mac).data);
    printf("  dst MAC : %s\n", utils::mac_encode(eth1.hdr()->dst_mac).data);
    printf("  ethertype: 0x%04X\n", eth1.hdr()->ethertype);
    printf("  hdr_size : %u bytes\n", eth1.hdr_size());

    // serialize bare header (no payload)
    Buffer buf1 = Buffer::alloc(eth1.size());
    eth1.serialize(buf1);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. construct from HdrEth struct 
    printf("\n[2] Ether from HdrEth struct\n");

    hdrs::HdrEth h{};
    std::memcpy(h.dst_mac, MAC_BROADCAST, 6);
    std::memcpy(h.src_mac, src.data, 6);
    h.ethertype = ETH_TYPE_ARP;

    Ether eth2(h);
    printf("  dst MAC : %s (broadcast)\n",
           utils::mac_encode(eth2.hdr()->dst_mac).data);
    printf("  ethertype: 0x%04X (ARP)\n", eth2.hdr()->ethertype);

    // ── 3. stack Ether / Raw(payload) 
    printf("\n[3] Ether / Raw payload\n");

    const uint8_t payload[] = "Hello, liblynx!";
    Raw raw(payload, sizeof(payload) - 1);

    Ether eth3(dst.data, src.data, 0x88B5);  // IEEE local experimental
    eth3 / raw;

    printf("  total size (hdr + load): %u bytes\n", eth3.size());

    Buffer buf3 = Buffer::alloc(eth3.size());
    eth3.serialize(buf3);

    if (!buf3.ok()) {
        printf("  buffer error: %s\n", buf3.errmsg());
        return 1;
    }

    printf("  serialized (%u bytes):\n  ", buf3.len());
    hexdump(buf3.begin(), buf3.len());

    printf("\ndone.\n");
    return 0;
}

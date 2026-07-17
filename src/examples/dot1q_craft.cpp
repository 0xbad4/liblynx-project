//  03 — 802.1Q VLAN-tagged frame crafting
//
//  demonstrates:
//    • Dot1Q construction with VLAN ID, PCP, DEI
//    • make_tci() helper
//    • sub-byte accessors: vlan_id(), pcp(), dei()
//    • stacking Dot1Q / Raw
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
    printf("=== Example 03: 802.1Q VLAN Frame Crafting ===\n\n");

    auto dst = utils::mac_decode("ff:ff:ff:ff:ff:ff");
    auto src = utils::mac_decode("aa:bb:cc:dd:ee:ff");

    // ── 1. construct with make_tci() 
    printf("[1] Dot1Q with make_tci()\n");

    uint8_t  pcp     = 5;       // priority code point (0-7)
    bool     dei     = false;   // drop eligible indicator
    uint16_t vlan_id = 100;     // VLAN identifier (0-4094)

    uint16_t tci = hdrs::HdrDot1Q::make_tci(pcp, dei, vlan_id);
    printf("  TCI value: 0x%04X  (PCP=%u DEI=%u VID=%u)\n",
           tci, pcp, dei ? 1 : 0, vlan_id);

    Dot1Q dot1q(dst.data, src.data,
                ETH_TYPE_VLAN,      // tpid: always 0x8100
                tci,                // tci: pcp|dei|vid
                ETH_TYPE_IPV4);     // inner ethertype

    if (!dot1q.ok()) {
        printf("  error: %s\n", dot1q.errmsg());
        return 1;
    }

    // read back sub-byte fields
    printf("  vlan_id() : %u\n", dot1q.hdr()->vlan_id());
    printf("  pcp()     : %u\n", dot1q.hdr()->pcp());
    printf("  dei()     : %s\n", dot1q.hdr()->dei() ? "true" : "false");
    printf("  ethertype : 0x%04X\n", dot1q.hdr()->ethertype);
    printf("  tpid      : 0x%04X\n", dot1q.hdr()->tpid);
    printf("  hdr_size(): %u bytes\n", dot1q.hdr_size());
    printf("  type()    : %s\n",
           dot1q.type() == FrameType::Dot1Q ? "Dot1Q" : "other");

    // ── 2. stack Dot1Q / Raw payload 
    printf("\n[2] Dot1Q / Raw payload\n");

    const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    Raw raw(payload, sizeof(payload));
    dot1q / raw;

    printf("  total size: %u bytes (hdr %u + load %zu)\n",
           dot1q.size(), dot1q.hdr_size(), dot1q.load().size());

    Buffer buf = Buffer::alloc(dot1q.size());
    dot1q.serialize(buf);

    printf("  serialized (%u bytes):\n  ", buf.len());
    hexdump(buf.begin(), buf.len());

    // ── 3. construct from HdrDot1Q struct 
    printf("\n[3] Dot1Q from HdrDot1Q struct\n");

    hdrs::HdrDot1Q h{};
    std::memcpy(h.dst_mac, dst.data, 6);
    std::memcpy(h.src_mac, src.data, 6);
    h.tpid      = ETH_TYPE_VLAN;
    h.tci       = hdrs::HdrDot1Q::make_tci(3, true, 42);
    h.ethertype = ETH_TYPE_IPV6;

    Dot1Q dot1q2(h);
    printf("  vlan_id: %u, pcp: %u, dei: %s, ethertype: 0x%04X\n",
           dot1q2.hdr()->vlan_id(),
           dot1q2.hdr()->pcp(),
           dot1q2.hdr()->dei() ? "true" : "false",
           dot1q2.hdr()->ethertype);

    printf("\ndone.\n");
    return 0;
}

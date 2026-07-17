//  15 — PPPoE session and discovery frame crafting
//
//  demonstrates:
//    • PPPoE session frame (carries PPP)
//    • PPPoE discovery PADI/PADO/PADR/PADS/PADT
//    • TLV tags: tlv_add(), tlv_reset(), tlv_next()
//    • is_session(), is_discovery()
//    • stacking Ether / PPPoE / PPP
//    • all PPPoE code and tag constants

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
    printf("=== Example 15: PPPoE Crafting ===\n\n");

    auto dst = utils::mac_decode("ff:ff:ff:ff:ff:ff");
    auto src = utils::mac_decode("aa:bb:cc:dd:ee:ff");

    // ── 1. PPPoE discovery PADI 
    printf("[1] PPPoE PADI (discovery initiation)\n");

    PPPoE padi(PPPOE_CODE_PADI, 0x0000);  // session_id=0 during discovery

    printf("  code          : 0x%02X (PADI)\n", padi.hdr()->code);
    printf("  session_id    : 0x%04X\n", padi.hdr()->session_id);
    printf("  is_discovery(): %s\n", padi.is_discovery() ? "true" : "false");
    printf("  is_session()  : %s\n", padi.is_session()   ? "true" : "false");
    printf("  ethertype()   : 0x%04X (discovery)\n", padi.ethertype());

    // add service-name tag (empty = any service)
    padi.tlv_add(PPPOE_TAG_SVC_NAME, nullptr, 0);
    printf("  added Service-Name tag (empty)\n");

    // add host-uniq tag for correlation
    const uint8_t uniq[] = { 0x01, 0x02, 0x03, 0x04 };
    padi.tlv_add(PPPOE_TAG_HOST_UNIQ, uniq, sizeof(uniq));
    printf("  added Host-Uniq tag (%zu bytes)\n", sizeof(uniq));

    // walk tags
    printf("  walking TLV tags:\n");
    padi.tlv_reset();
    for (;;) {
        auto tag = padi.tlv_next();
        if (tag.length == 0 && tag.type == 0) break;
        printf("    type=0x%04X length=%u value=%zu bytes\n",
               tag.type, tag.length, tag.value.size());
    }

    // wrap in Ethernet
    Ether eth_padi(dst.data, src.data, PPPOE_ETHERTYPE_DISC);
    eth_padi / padi;

    Buffer buf1 = Buffer::alloc(eth_padi.size());
    eth_padi.serialize(buf1);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. PPPoE session frame 
    printf("\n[2] PPPoE session frame (carries PPP)\n");

    PPPoE session(PPPOE_CODE_SESSION, 0x1234);
    printf("  code        : 0x%02X (session)\n", session.hdr()->code);
    printf("  session_id  : 0x%04X\n", session.hdr()->session_id);
    printf("  is_session(): %s\n", session.is_session() ? "true" : "false");
    printf("  ethertype() : 0x%04X (session)\n", session.ethertype());

    // stack PPPoE / PPP / IPv4
    PPP ppp(PPP_ADDRESS, PPP_CONTROL, PPP_PROTO_IP);
    auto s = utils::ipv4_decode("10.0.0.1");
    auto d = utils::ipv4_decode("10.0.0.2");
    IPv4 ip(s.data, d.data, IP_PROTO_TCP);
    ip.hdr()->total_len = ip.hdr_size();

    ppp / ip;
    session / ppp;

    Ether eth_sess(dst.data, src.data, PPPOE_ETHERTYPE_SESSION);
    eth_sess / session;

    Buffer buf2 = Buffer::alloc(eth_sess.size());
    eth_sess.serialize(buf2);
    printf("  serialized (%u bytes):\n  ", buf2.len());
    hexdump(buf2.begin(), buf2.len());

    // ── 3. PPPoE constants 
    printf("\n[3] PPPoE constants\n");
    printf("  codes:\n");
    printf("    PPPOE_CODE_SESSION = 0x%02X\n", PPPOE_CODE_SESSION);
    printf("    PPPOE_CODE_PADI   = 0x%02X\n", PPPOE_CODE_PADI);
    printf("    PPPOE_CODE_PADO   = 0x%02X\n", PPPOE_CODE_PADO);
    printf("    PPPOE_CODE_PADR   = 0x%02X\n", PPPOE_CODE_PADR);
    printf("    PPPOE_CODE_PADS   = 0x%02X\n", PPPOE_CODE_PADS);
    printf("    PPPOE_CODE_PADT   = 0x%02X\n", PPPOE_CODE_PADT);
    printf("  tags:\n");
    printf("    PPPOE_TAG_SVC_NAME  = 0x%04X\n", PPPOE_TAG_SVC_NAME);
    printf("    PPPOE_TAG_AC_NAME   = 0x%04X\n", PPPOE_TAG_AC_NAME);
    printf("    PPPOE_TAG_HOST_UNIQ = 0x%04X\n", PPPOE_TAG_HOST_UNIQ);
    printf("    PPPOE_TAG_AC_COOKIE = 0x%04X\n", PPPOE_TAG_AC_COOKIE);
    printf("    PPPOE_TAG_VENDOR    = 0x%04X\n", PPPOE_TAG_VENDOR);
    printf("    PPPOE_TAG_EOL       = 0x%04X\n", PPPOE_TAG_EOL);

    printf("\ndone.\n");
    return 0;
}

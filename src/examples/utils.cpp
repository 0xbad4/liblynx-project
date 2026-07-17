// ═══════════════════════════════════════════════════════════════════
//  13 — Utility functions
//
//  demonstrates:
//    • MAC encode/decode (hr_mac / mn_mac)
//    • IPv4 encode/decode (hr_ipv4 / mn_ipv4)
//    • IPv6 encode/decode (hr_ipv6 / mn_ipv6)
//    • inet_checksum (RFC 1071)
//    • crc32c (SCTP)
//    • bswap (byte swap)
//    • buf_randomize
// ═══════════════════════════════════════════════════════════════════

#include <lynx/lynx>
#include <cstdio>

using namespace lynx;

static void hexdump(const uint8_t* data, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) printf("%02x ", data[i]);
    printf("\n");
}

int main()
{
    printf("=== Example 13: Utility Functions ===\n\n");

    // ── 1. MAC encode / decode ───────────────────────────────────
    printf("[1] MAC encode / decode\n");

    auto mac = utils::mac_decode("de:ad:be:ef:ca:fe");
    printf("  decoded: ");
    hexdump(mac.data, 6);

    auto encoded = utils::mac_encode(mac.data);
    printf("  encoded: %s\n", encoded.data);

    // round-trip
    auto mac2 = utils::mac_decode(encoded.data);
    printf("  round-trip match: %s\n",
           std::memcmp(mac.data, mac2.data, 6) == 0 ? "yes" : "no");

    // ── 2. IPv4 encode / decode ──────────────────────────────────
    printf("\n[2] IPv4 encode / decode\n");

    auto ip4 = utils::ipv4_decode("192.168.1.42");
    printf("  decoded: ");
    hexdump(ip4.data, 4);

    auto ip4_str = utils::ipv4_encode(ip4.data);
    printf("  encoded: %s\n", ip4_str.data);

    // edge cases
    auto ip_min = utils::ipv4_decode("0.0.0.0");
    auto ip_max = utils::ipv4_decode("255.255.255.255");
    printf("  0.0.0.0     → %s\n", utils::ipv4_encode(ip_min.data).data);
    printf("  255.255.255.255 → %s\n", utils::ipv4_encode(ip_max.data).data);

    // ── 3. IPv6 encode / decode ──────────────────────────────────
    printf("\n[3] IPv6 encode / decode\n");

    auto ip6 = utils::ipv6_decode("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    printf("  decoded: ");
    hexdump(ip6.data, 16);

    auto ip6_str = utils::ipv6_encode(ip6.data);
    printf("  encoded: %s\n", ip6_str.data);

    // link-local
    auto ll = utils::ipv6_decode("fe80:0000:0000:0000:0000:0000:0000:0001");
    printf("  link-local: %s\n", utils::ipv6_encode(ll.data).data);

    // ── 4. inet checksum ─────────────────────────────────────────
    printf("\n[4] inet_checksum (RFC 1071)\n");

    const uint8_t sample[] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
        0xac, 0x10, 0x0a, 0x0c
    };
    uint16_t cksum = utils::inet_checksum(sample, sizeof(sample));
    printf("  checksum of sample IPv4 header: 0x%04X\n", cksum);

    // span overload
    std::span<const uint8_t> sp(sample, sizeof(sample));
    uint16_t cksum2 = utils::inet_checksum(sp);
    printf("  span overload matches: %s\n",
           cksum == cksum2 ? "yes" : "no");

    // ── 5. CRC-32c ───────────────────────────────────────────────
    printf("\n[5] CRC-32c (used by SCTP)\n");

    const uint8_t crc_data[] = "Hello";
    uint32_t crc = utils::crc32c(crc_data, sizeof(crc_data) - 1);
    printf("  crc32c(\"Hello\") = 0x%08X\n", crc);

    // ── 6. byte swap ─────────────────────────────────────────────
    printf("\n[6] bswap()\n");

    uint16_t v16 = 0x1234;
    printf("  bswap(0x%04X) = 0x%04X\n", v16, utils::bswap(v16));

    uint32_t v32 = 0xDEADBEEF;
    printf("  bswap(0x%08X) = 0x%08X\n", v32, utils::bswap(v32));

    uint64_t v64 = 0x0102030405060708ULL;
    printf("  bswap(0x%016lX) = 0x%016lX\n", v64, utils::bswap(v64));

    // ── 7. buf_randomize ─────────────────────────────────────────
    printf("\n[7] buf_randomize()\n");

    uint8_t rand_buf[16] = {};
    auto rspan = utils::buf_randomize(rand_buf, sizeof(rand_buf));
    printf("  randomized %zu bytes: ", rspan.size());
    hexdump(rand_buf, sizeof(rand_buf));

    printf("\ndone.\n");
    return 0;
}

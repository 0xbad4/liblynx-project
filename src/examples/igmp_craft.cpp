//  10 — IGMP message crafting
//
//  demonstrates:
//    • IGMP membership query, v2 report, v2 leave
//    • all IGMP type constants
//    • stacking IPv4 / IGMP
//    • auto-checksum (standard internet checksum, no pseudo-header)

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
    printf("=== Example 10: IGMP Crafting ===\n\n");

    auto src_ip = utils::ipv4_decode("192.168.1.10");
    auto mcast  = utils::ipv4_decode("224.0.0.1");    // all-hosts
    auto group  = utils::ipv4_decode("239.1.2.3");     // specific group

    // ── 1. IGMP membership query 
    printf("[1] IGMP General Membership Query\n");

    uint8_t zero_group[4] = {};  // 0.0.0.0 for general query
    IGMP query(IGMP_QUERY, 100, zero_group);  // max_resp_time=100 (10s)

    printf("  type     : 0x%02X (query)\n", query.hdr()->type);
    printf("  max_resp : %u\n", query.hdr()->max_resp);
    printf("  group    : %s\n", utils::ipv4_encode(query.hdr()->group_addr).data);
    printf("  hdr_size : %u bytes\n", query.hdr_size());
    printf("  proto()  : %u (IGMP)\n", query.proto());

    // ── 2. IGMP v2 membership report 
    printf("\n[2] IGMP v2 Membership Report\n");

    IGMP report(IGMP_V2_REPORT, 0, group.data);
    printf("  type  : 0x%02X (v2 report)\n", report.hdr()->type);
    printf("  group : %s\n", utils::ipv4_encode(report.hdr()->group_addr).data);

    IPv4 ip_report(src_ip.data, mcast.data, query.proto());
    ip_report.hdr()->ttl = 1;  // IGMP uses TTL=1
    ip_report.hdr()->total_len = ip_report.hdr_size() + report.size();
    ip_report / report;

    printf("  checksum : 0x%04X\n", report.hdr()->checksum);

    Buffer buf2 = Buffer::alloc(ip_report.size());
    ip_report.serialize(buf2);
    printf("  serialized (%u bytes):\n  ", buf2.len());
    hexdump(buf2.begin(), buf2.len());

    // ── 3. IGMP v2 leave group 
    printf("\n[3] IGMP v2 Leave Group\n");

    IGMP leave(IGMP_V2_LEAVE, 0, group.data);
    printf("  type  : 0x%02X (v2 leave)\n", leave.hdr()->type);
    printf("  group : %s\n", utils::ipv4_encode(leave.hdr()->group_addr).data);

    // ── 4. IGMP constants reference 
    printf("\n[4] IGMP constants\n");
    printf("  IGMP_QUERY     = 0x%02X\n", IGMP_QUERY);
    printf("  IGMP_V2_REPORT = 0x%02X\n", IGMP_V2_REPORT);
    printf("  IGMP_V2_LEAVE  = 0x%02X\n", IGMP_V2_LEAVE);
    printf("  IGMP_V3_REPORT = 0x%02X\n", IGMP_V3_REPORT);

    printf("\ndone.\n");
    return 0;
}

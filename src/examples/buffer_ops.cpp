//  12 — Buffer operations
//
//  demonstrates:
//    • Buffer::alloc() — allocate and write
//    • Buffer::wrap()  — zero-copy view of external data
//    • write(), read(), reserve(), patch()
//    • begin(), end(), at(), span(), subspan()
//    • len(), cap(), remaining(), empty(), valid(), owner()
//    • reset() — rewind write cursor
//    • error handling: alloc(0), write beyond capacity

#include <lynx/lynx>
#include <cstdio>

using namespace lynx;

static void hexdump(const uint8_t* data, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int main()
{
    printf("=== Example 12: Buffer Operations ===\n\n");

    // ── 1. alloc + write 
    printf("[1] Buffer::alloc() + write()\n");

    Buffer buf = Buffer::alloc(64);
    printf("  ok()        : %s\n", buf.ok() ? "true" : "false");
    printf("  cap()       : %u\n", buf.cap());
    printf("  len()       : %u\n", buf.len());
    printf("  remaining() : %u\n", buf.remaining());
    printf("  empty()     : %s\n", buf.empty() ? "true" : "false");
    printf("  valid()     : %s\n", buf.valid() ? "true" : "false");

    const uint8_t data1[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    buf.write(data1, sizeof(data1));
    printf("  after write(4): len=%u remaining=%u\n", buf.len(), buf.remaining());

    const uint8_t data2[] = { 0xCA, 0xFE };
    buf.write(data2, sizeof(data2));
    printf("  after write(2): len=%u\n", buf.len());
    printf("  contents:\n  ");
    hexdump(buf.begin(), buf.len());

    // ── 2. read 
    printf("\n[2] read()\n");

    uint8_t out[4];
    bool ok = buf.read(0, out, 4);
    printf("  read(0, 4): ok=%s data=", ok ? "true" : "false");
    hexdump(out, 4);

    ok = buf.read(4, out, 2);
    printf("  read(4, 2): ok=%s data=", ok ? "true" : "false");
    hexdump(out, 2);

    // ── 3. reserve 
    printf("\n[3] reserve()\n");

    Buffer buf3 = Buffer::alloc(32);
    uint8_t* ptr = buf3.reserve(8);
    if (ptr) {
        for (int i = 0; i < 8; ++i) ptr[i] = static_cast<uint8_t>(i + 1);
        printf("  reserved 8 bytes, wrote directly\n  ");
        hexdump(buf3.begin(), buf3.len());
    }

    // ── 4. patch 
    printf("\n[4] patch()\n");

    // overwrite bytes at position 2 without advancing cursor
    const uint8_t patch_data[] = { 0xFF, 0xFF };
    buf3.patch(2, patch_data, 2);
    printf("  patched pos 2-3 with 0xFF:\n  ");
    hexdump(buf3.begin(), buf3.len());

    // ── 5. at(), span(), subspan() 
    printf("\n[5] at(), span(), subspan()\n");

    printf("  at(0) = 0x%02X\n", *buf3.at(0));
    printf("  at(5) = 0x%02X\n", *buf3.at(5));

    auto sp = buf3.span();
    printf("  span().size() = %zu\n", sp.size());

    auto sub = buf3.subspan(2, 4);
    printf("  subspan(2, 4) = ");
    hexdump(sub.data(), static_cast<uint32_t>(sub.size()));

    // ── 6. wrap — zero-copy view 
    printf("\n[6] Buffer::wrap() — zero-copy view\n");

    auto owner = std::shared_ptr<uint8_t[]>(new uint8_t[16]{});
    for (int i = 0; i < 16; ++i) owner[i] = static_cast<uint8_t>(0xA0 + i);

    Buffer wrapped = Buffer::wrap(owner, 4, 8);  // offset=4, length=8
    printf("  offset() : %u\n", wrapped.offset());
    printf("  len()    : %u\n", wrapped.len());
    printf("  cap()    : %u (== len for wrapped)\n", wrapped.cap());
    printf("  data:\n  ");
    hexdump(wrapped.begin(), wrapped.len());

    // ── 7. reset 
    printf("\n[7] reset()\n");

    printf("  before reset: len=%u\n", buf3.len());
    buf3.reset();
    printf("  after  reset: len=%u (cursor rewound, no dealloc)\n", buf3.len());

    // ── 8. error cases 
    printf("\n[8] Error cases\n");

    Buffer bad1 = Buffer::alloc(0);
    printf("  alloc(0): ok=%s status=%s\n",
           bad1.ok() ? "true" : "false", status_str(bad1.status()));

    Buffer small = Buffer::alloc(4);
    const uint8_t big[8] = {};
    small.write(big, 8);
    printf("  write(8) to cap=4: ok=%s status=%s\n",
           small.ok() ? "true" : "false", status_str(small.status()));

    // recover
    small.clear_error();
    printf("  after clear_error: ok=%s\n", small.ok() ? "true" : "false");

    // ── 9. owner() 
    printf("\n[9] owner() — shared ownership\n");
    auto own = buf.owner();
    printf("  owner non-null: %s\n", own ? "true" : "false");

    printf("\ndone.\n");
    return 0;
}

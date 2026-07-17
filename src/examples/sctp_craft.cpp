//  11 — SCTP packet crafting with chunks
//
//  demonstrates:
//    • SCTP common header (src/dst port, vtag)
//    • adding chunks: DATA, INIT, HEARTBEAT
//    • chunk walking: chunk_reset() / chunk_next()
//    • CRC-32c checksum (not inet checksum)
//    • all SCTP chunk type constants
//    • HdrSCTPChunk / HdrSCTPData / HdrSCTPInit structs

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
    printf("=== Example 11: SCTP Packet Crafting ===\n\n");

    // ── 1. SCTP with DATA chunk 
    printf("[1] SCTP with DATA chunk\n");

    SCTP sctp;
    sctp.hdr()->src_port = 36412;
    sctp.hdr()->dst_port = 36412;
    sctp.hdr()->vtag     = 0xDEADBEEF;

    printf("  src_port : %u\n", sctp.hdr()->src_port);
    printf("  dst_port : %u\n", sctp.hdr()->dst_port);
    printf("  vtag     : 0x%08X\n", sctp.hdr()->vtag);
    printf("  hdr_size : %u bytes\n", sctp.hdr_size());
    printf("  proto()  : %u (SCTP)\n", sctp.proto());

    // DATA chunk: TSN(4) + stream_id(2) + stream_seq(2) + ppid(4) + user_data
    uint8_t data_val[] = {
        // TSN = 1
        0x00, 0x00, 0x00, 0x01,
        // stream_id = 0
        0x00, 0x00,
        // stream_seq = 0
        0x00, 0x00,
        // payload proto = 0
        0x00, 0x00, 0x00, 0x00,
        // user data
        'H', 'e', 'l', 'l', 'o'
    };
    uint8_t data_flags = SCTP_DATA_FLAG_B | SCTP_DATA_FLAG_E;  // complete msg
    sctp.add_chunk(SCTP_CHUNK_DATA, data_flags, data_val, sizeof(data_val));
    printf("  added DATA chunk (%zu bytes value)\n", sizeof(data_val));

    // serialize (checksum auto-computed as CRC-32c)
    Buffer buf1 = Buffer::alloc(sctp.size());
    sctp.serialize(buf1);
    printf("  checksum : 0x%08X (CRC-32c)\n", sctp.hdr()->checksum);
    printf("  serialized (%u bytes):\n  ", buf1.len());
    hexdump(buf1.begin(), buf1.len());

    // ── 2. walk chunks 
    printf("\n[2] Walking chunks\n");

    sctp.chunk_reset();
    int idx = 0;
    for (;;) {
        auto chunk = sctp.chunk_next();
        if (chunk.length == 0) break;
        printf("  chunk[%d]: type=%u flags=0x%02X length=%u value=%zu bytes\n",
               idx++, chunk.type, chunk.flags, chunk.length, chunk.value.size());
    }

    // ── 3. SCTP with INIT chunk 
    printf("\n[3] SCTP with INIT chunk\n");

    SCTP sctp_init;
    sctp_init.hdr()->src_port = 2905;
    sctp_init.hdr()->dst_port = 2905;
    sctp_init.hdr()->vtag     = 0;  // INIT always has vtag=0

    // INIT fixed params: init_tag(4) + a_rwnd(4) + out_streams(2)
    //                    + in_streams(2) + init_tsn(4)
    uint8_t init_val[16] = {};
    // init_tag = 0x12345678
    init_val[0] = 0x12; init_val[1] = 0x34;
    init_val[2] = 0x56; init_val[3] = 0x78;
    // a_rwnd = 106496
    uint32_t rwnd = SCTP_DEFAULT_RWND;
    init_val[4] = (rwnd >> 24) & 0xFF;
    init_val[5] = (rwnd >> 16) & 0xFF;
    init_val[6] = (rwnd >>  8) & 0xFF;
    init_val[7] = rwnd & 0xFF;
    // out_streams = 10
    init_val[8]  = 0; init_val[9]  = SCTP_DEFAULT_OUT_STREAMS;
    // in_streams = 65535
    init_val[10] = 0xFF; init_val[11] = 0xFF;
    // init_tsn = 1
    init_val[12] = 0; init_val[13] = 0;
    init_val[14] = 0; init_val[15] = 1;

    sctp_init.add_chunk(SCTP_CHUNK_INIT, 0, init_val, sizeof(init_val));
    printf("  added INIT chunk\n");

    Buffer buf3 = Buffer::alloc(sctp_init.size());
    sctp_init.serialize(buf3);
    printf("  serialized (%u bytes):\n  ", buf3.len());
    hexdump(buf3.begin(), buf3.len());

    // ── 4. SCTP chunk types 
    printf("\n[4] SCTP chunk type constants\n");
    printf("  DATA          = %u\n", SCTP_CHUNK_DATA);
    printf("  INIT          = %u\n", SCTP_CHUNK_INIT);
    printf("  INIT_ACK      = %u\n", SCTP_CHUNK_INIT_ACK);
    printf("  SACK          = %u\n", SCTP_CHUNK_SACK);
    printf("  HEARTBEAT     = %u\n", SCTP_CHUNK_HEARTBEAT);
    printf("  HEARTBEAT_ACK = %u\n", SCTP_CHUNK_HEARTBEAT_ACK);
    printf("  ABORT         = %u\n", SCTP_CHUNK_ABORT);
    printf("  SHUTDOWN      = %u\n", SCTP_CHUNK_SHUTDOWN);
    printf("  COOKIE_ECHO   = %u\n", SCTP_CHUNK_COOKIE_ECHO);
    printf("  COOKIE_ACK    = %u\n", SCTP_CHUNK_COOKIE_ACK);

    printf("\ndone.\n");
    return 0;
}

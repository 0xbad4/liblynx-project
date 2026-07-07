#pragma once

#include "core/common.hpp"

namespace lynx::hdrs
{
    // SCTP common header (12 bytes, fixed)
    // present at the start of every SCTP packet, exactly once.
    // checksum covers the ENTIRE packet (header + all chunks).
    // NOTE: checksum uses CRC-32c not the RFC 1071 one's-complement sum used by IPv4/TCP/UDP/ICMP.

    LYNX_PACKED HdrSCTP {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t vtag;       // verification tag — agreed during INIT handshake
        uint32_t checksum;   // CRC-32c over entire SCTP packet, zeroed during calc
    };

    // SCTP chunk header (4 bytes, fixed)
    // every chunk starts with this header. length includes the header
    // itself and is NOT padded — chunks are padded to a 4-byte boundary
    // on the wire, but the length field reflects the un-padded size.

    LYNX_PACKED HdrSCTPChunk {
        uint8_t      type;    // SCTP_CHUNK_*
        uint8_t      flags;   // chunk-type-specific — e.g. SCTP_DATA_FLAG_* for DATA
        uint16_t     length;  // total chunk length. NOTE: including this 4-byte header
        const_view_t value{}; // chunk-type-specific body, excludes 4B header

        [[nodiscard]] uint32_t padded_length() const noexcept {
            return (length + 3u) & ~3u;   // round up to next multiple of 4
        }
    };

    // DATA chunk fixed fields (follow HdrSCTPChunk)
    LYNX_PACKED HdrSCTPData {
        uint32_t tsn;          // transmission sequence number
        uint16_t stream_id;
        uint16_t stream_seq;   // stream sequence number — ignored if unordered
        uint32_t payload_proto; // payload protocol identifier (often 0 = unspecified)
        // user data follows, length = chunk.length - sizeof(HdrSCTPChunk) - sizeof(HdrSCTPData)
    };

    // INIT / INIT-ACK chunk fixed fields (follow HdrSCTPChunk) 
    LYNX_PACKED HdrSCTPInit {
        uint32_t init_tag;       // becomes the verification tag for this direction
        uint32_t a_rwnd;         // advertised receiver window credit
        uint16_t out_streams;    // number of outbound streams requested
        uint16_t in_streams;     // number of inbound streams supported
        uint32_t init_tsn;       // initial transmission sequence number
        // optional parameters (TLV) follow for INIT-ACK (state cookie, etc.)
    };


} // namespace lynx::hdrs

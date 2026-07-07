#pragma once

#include "protocols/l4/segment.hpp"
#include "hdrs.hpp"
#include "const.hpp"
#include "core/utils.hpp"


namespace lynx::proto
{
    class SCTP LYNX_INHERITANCE_POLICY : public Segment {
        public:

            SCTP() noexcept {
                hdr_.src_port = 0;
                hdr_.dst_port = 0;
                hdr_.vtag     = 0;
                hdr_.checksum = 0;
            }

            explicit SCTP(const hdrs::HdrSCTP& h) noexcept : hdr_(h) {}

            ~SCTP() = default;

            // ── serialize
            // checksum is computed by patch_checksum() — called here so a
            // single serialize() call always produces a wire-correct packet.
            // src_port, dst_port, vtag, checksum all swapped on the wire copy.

            void serialize(Buffer& buf) const noexcept override
            {
                const_cast<SCTP*>(this)->patch_checksum();

                hdrs::HdrSCTP wire = hdr_;
                swap_hdr_byte_order(wire);

                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrSCTP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            // ── dissect
            // load_ spans every chunk after the 12-byte common header.
            // individual chunks are NOT parsed here — walked lazily via
            // chunk_next(), same lazy-on-demand pattern as PPPoE TLV tags.

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < constants::SCTP_HDR_LEN) {
                    set_error(Status::MalformedPacket, "SCTP header too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrSCTP));
                swap_hdr_byte_order(hdr_);

                load_ = { data + constants::SCTP_HDR_LEN,
                          len  - constants::SCTP_HDR_LEN };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::SCTP_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrSCTP* hdr() noexcept override { return &hdr_; }

            [[nodiscard]] uint8_t proto() const noexcept override {
                return constants::IP_PROTO_SCTP;
            }

            // ── checksum — CRC-32c over the ENTIRE packet, not RFC 1071.
            // unlike TCP/UDP, SCTP needs no pseudo-header and no underlayer_ —
            // the checksum covers only bytes that belong to this layer.
            // hdr_.checksum is zeroed during the calculation, same convention
            // as every other patch_checksum() in this library.

            void patch_checksum() noexcept override
            {
                hdr_.checksum = 0;

                uint32_t total = sizeof(hdrs::HdrSCTP) + static_cast<uint32_t>(load_.size());

                Buffer tmp = Buffer::alloc(total);
                if (!tmp.ok()) {
                    set_error(Status::BufferAllocFail, "SCTP: checksum buffer alloc failed");
                    return;
                }

                hdrs::HdrSCTP wire = hdr_;
                swap_hdr_byte_order(wire);
                wire.checksum = 0;

                tmp.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrSCTP));
                if (!load_.empty())
                    tmp.write(load_.data(), static_cast<uint32_t>(load_.size()));

                hdr_.checksum = utils::crc32c(tmp.begin(), tmp.len());
            }

            void swap_hdr_byte_order(hdrs::HdrSCTP& hdr) const noexcept {
                hdr.src_port = swap16(hdr.src_port);
                hdr.dst_port = swap16(hdr.dst_port);
                hdr.vtag     = swap32(hdr.vtag);
                hdr.checksum = swap32(hdr.checksum);
            }

            // ── chunk cursor
            // same lazy walking pattern as LCP/IPCP option TLVs and PPPoE
            // discovery tags — chunk_pos_ tracks the byte offset into load_,
            // chunk_next() reads the chunk there and advances past it
            // (including 4-byte alignment padding, which is NOT part of
            // the next chunk's data).

            void chunk_reset() noexcept { chunk_pos_ = 0; }

            [[nodiscard]] hdrs::HdrSCTPChunk chunk_next() noexcept {
                if (chunk_pos_ + constants::SCTP_CHUNK_HDR_LEN > load_.size())
                    return {};

                const uint8_t* p = load_.data() + chunk_pos_;

                // [TYPE:1] [FLAGS:1] [LENGTH:2] [VALUE:LENGTH]
                uint8_t  type   = p[0];
                uint8_t  flags  = p[1];
                uint16_t length = static_cast<uint16_t>((p[2] << 8) | p[3]);

                if (length < constants::SCTP_CHUNK_HDR_LEN) {
                    set_error(Status::MalformedPacket, "SCTP: chunk header too short");
                    return {};
                }

                if (chunk_pos_ + length > load_.size()) {
                    set_error(Status::MalformedPacket, "SCTP: chunk length exceeds load size");
                    return {};
                }

                hdrs::HdrSCTPChunk chunk{
                    type, flags, length,
                    { p + constants::SCTP_CHUNK_HDR_LEN,
                      length - constants::SCTP_CHUNK_HDR_LEN }
                };

                // advance past padded length — chunks are 4-byte aligned on
                // the wire even though `length` itself is un-padded.
                uint32_t padded = (length + 3u) & ~3u;
                chunk_pos_ += padded;

                return chunk;
            }

            // appends one chunk to load_: type(1) | flags(1) | length(2) | value
            // value is padded to a 4-byte boundary with zero bytes — the
            // length field itself stays un-padded per RFC 4960 §3.2.
            // grows load_buf_ in place, same lazy-promotion pattern used by
            // LCP::add_option() — first call allocates, later calls append.

            bool add_chunk(uint8_t type, uint8_t flags,
                            const uint8_t* value, uint16_t value_size) noexcept
            {
                uint32_t chunk_len = constants::SCTP_CHUNK_HDR_LEN + value_size;
                uint32_t padded    = (chunk_len + 3u) & ~3u;

                uint32_t old_size = static_cast<uint32_t>(load_.size());

                if (!load_buf_.ok() || load_buf_.cap() < old_size + padded) {
                    uint32_t reserve = old_size + padded + 256; // headroom for more chunks
                    Buffer fresh = Buffer::alloc(reserve);
                    if (!fresh.ok()) {
                        set_error(Status::BufferAllocFail, "SCTP: add_chunk alloc failed");
                        return false;
                    }
                    if (old_size)
                        fresh.write(load_.data(), old_size);
                    load_buf_ = std::move(fresh);
                }
                uint8_t hdr[4] = {
                    type, flags,
                    static_cast<uint8_t>(chunk_len >> 8),
                    static_cast<uint8_t>(chunk_len & 0xFF)
                };
                load_buf_.write(hdr, 4);
                if (value_size)
                    load_buf_.write(value, value_size);

                uint32_t pad_bytes = padded - chunk_len;
                if (pad_bytes) {
                    uint8_t zero[3] = {0, 0, 0};
                    load_buf_.write(zero, pad_bytes);
                }

                load_ = { load_buf_.begin(), load_buf_.len() };
                return true;
            }

        protected:
            hdrs::HdrSCTP hdr_{};
            uint32_t      chunk_pos_ = 0;
    };
} // namespace lynx::proto

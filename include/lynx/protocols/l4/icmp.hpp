#pragma once

#include "segment.hpp"

namespace lynx::proto
{
    class ICMP LYNX_INHERITANCE_POLICY : public Segment {
        public:
            ICMP() = default;

            ICMP(
                uint8_t type, uint8_t code, uint16_t id=0, uint16_t seq=0
            ) noexcept {
                hdr_.type = type;
                hdr_.code = code;
                hdr_.checksum = 0;
                hdr_.set_id_seq(id, seq);
            }

            explicit ICMP(const hdrs::HdrICMP &h) noexcept : hdr_(h) {}

            ~ICMP() = default;

            void serialize(Buffer&buf) const noexcept override {
                hdrs::HdrICMP wire = hdr_;
                swap_hdr_byte_order(wire);

                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrICMP)
                );

                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size())
                );
            }

            void dissect(const uint8_t *data, uint32_t len) noexcept override {
                if (!data || len < constants::ICMP_HDR_LEN) {
                    set_error(Status::MalformedPacket, "ICMP header too short");
                    return;
                }

                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrICMP));

                swap_hdr_byte_order(hdr_);

                uint32_t hdr_bytes = hdr_size();

                load_ = { data + hdr_bytes, len - hdr_bytes };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::ICMP_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrICMP* hdr() noexcept override { return &hdr_; }

            void swap_hdr_byte_order(hdrs::HdrICMP& hdr) const noexcept {
                hdr.rest      = __builtin_bswap32(hdr.rest);
                hdr.checksum  = __builtin_bswap16(hdr.checksum);
            }
            
            void patch_checksum() noexcept override {
                hdrs::HdrICMP wire = hdr_;
                swap_hdr_byte_order(wire);
                
                wire.checksum = 0;

                // combine header + load into one stack buffer
                uint32_t total = sizeof(hdrs::HdrICMP) + static_cast<uint32_t>(load_.size());
                
                // stack buffer — ICMP max is small, safe here
                uint8_t buf[total];
                __builtin_memcpy(buf, &wire, sizeof(hdrs::HdrICMP));

                if (!load_.empty())
                    __builtin_memcpy(buf + sizeof(hdrs::HdrICMP), load_.data(), load_.size());

                hdr_.checksum = utils::inet_checksum(buf, total);
            }

            [[nodiscard]] uint8_t proto() const noexcept { return constants::IP_PROTO_ICMP; }            

        protected:
            hdrs::HdrICMP hdr_;

    };
} // namespace lynx::proto

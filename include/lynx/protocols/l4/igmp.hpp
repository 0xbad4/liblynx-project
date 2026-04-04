#pragma once

#include "segment.hpp"

namespace lynx::proto
{
    class IGMP LYNX_INHERITANCE_POLICY : public Segment {
        public:

            IGMP() = default;

            IGMP(uint8_t type, uint8_t maxr, const uint8_t gaddr[4]) {
                hdr_.type = type;
                hdr_.type = maxr;
                hdr_.checksum = 0;
                std::memcpy(hdr_.group_addr, gaddr, 4);
            }

            explicit IGMP(const hdrs::HdrIGMP& h) noexcept : hdr_(h) {}

            void serialize(Buffer&buf) const noexcept override {
                hdrs::HdrIGMP wire = hdr_;

                wire.checksum = __builtin_bswap16(wire.checksum);

                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrIGMP)
                );

                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size())
                );
            }

            void dissect(const uint8_t *data, uint32_t len) noexcept override {
                if (!data || len < constants::IGMP_HDR_LEN) {
                    set_error(Status::MalformedPacket, "IGMP header too short");
                    return;
                }

                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrIGMP));

                hdr_.checksum  = __builtin_bswap16(hdr_.checksum);

                uint32_t hdr_bytes = hdr_size();

                if (hdr_bytes < constants::IGMP_HDR_LEN || hdr_bytes > len) {
                    set_error(Status::MalformedPacket, "IGMP: header length out of range");
                    return;
                }
                load_ = { data + hdr_bytes, len - hdr_bytes };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::IGMP_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrIGMP* hdr() noexcept override { return &hdr_; }
            
            void patch_checksum() noexcept override {
                hdr_.checksum = 0;

                uint32_t total = size();
                
                uint8_t buf[total];
                __builtin_memcpy(buf, &hdr_, sizeof(hdrs::HdrIGMP));

                if (!load_.empty())
                    __builtin_memcpy(buf + sizeof(hdrs::HdrIGMP), load_.data(), load_.size());

                hdr_.checksum = utils::inet_checksum(buf, total);
            }

            [[nodiscard]] uint8_t proto() const noexcept { return constants::IP_PROTO_IGMP; }            


        protected:
            hdrs::HdrIGMP hdr_;

    };
} // namespace lynx::proto

#pragma once


//  IPv6 — L3 concrete implementation, inherits Packet.

#include "packet.hpp"

namespace lynx::proto
{
    class IPv6 LYNX_INHERITANCE_POLICY : public Packet {
        public:

            explicit IPv6(const hdrs::HdrIPv6& h) noexcept : hdr_(h) {}

            IPv6(uint32_t vtc_flow,
                uint16_t payload_len,
                uint8_t next_header,
                uint8_t hop_limit,
                const uint8_t src[16],
                const uint8_t dst[16]) noexcept
            {
                hdr_.ver_tc_fl = vtc_flow;
                hdr_.payload_len = payload_len;
                hdr_.next_hdr = next_header;
                hdr_.hop_limit = hop_limit;

                std::memcpy(hdr_.src_ip, src, 16);
                std::memcpy(hdr_.dst_ip, dst, 16);
            }
            
            IPv6() noexcept {
                hdr_.ver_tc_fl   = (6u << 28); // version = 6, rest = 0
                hdr_.payload_len = 0;  // will be set later
                hdr_.next_hdr    = constants::IPV6_PROTO_NONXT;  // No Next Header
                hdr_.hop_limit   = constants::IPV6_HOP_DEF;
            }

            ~IPv6() = default;

            void serialize(Buffer& buf) const noexcept override {
                // use new header copy, as the bytes order will be swapped
                hdrs::HdrIPv6 wire = hdr_;
                
                wire.ver_tc_fl = __builtin_bswap32(hdr_.ver_tc_fl);
                wire.payload_len = __builtin_bswap16(
                    static_cast<uint16_t>(load_.size())  // IPv6 payload_len excludes the header
                );
                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrIPv6)
                );

                // if there is data add it too
                if (!load_.empty()) {
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
                }
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept {
                if (!data || len < constants::IPV6_HDR_LEN) {
                    set_error(Status::MalformedPacket, "IPv6 header too short");
                    return;
                }

                // copy header
                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrIPv6));

                hdr_.ver_tc_fl = __builtin_bswap32(hdr_.ver_tc_fl);
                hdr_.payload_len = __builtin_bswap16(hdr_.payload_len);

                if (hdr_.version() != constants::IPV6_VERSION) {
                    set_error(Status::MalformedPacket, "IPv6: version != 6");
                    return;
                }

                // move view cursor forward by IPv6 header length (40)
                load_ = {data + constants::IPV6_HDR_LEN, len - constants::IPV6_HDR_LEN};
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::IPV6_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrIPv6* hdr() noexcept override {
                return &hdr_;
            }

            [[nodiscard]] uint16_t ethertype() const noexcept override {
                return constants::ETH_TYPE_IPV6;
            }

            [[nodiscard]] const uint8_t* dst() const noexcept override {
                return hdr_.dst_ip;
            }

        protected:
            hdrs::HdrIPv6 hdr_;
    };
} // namespace lynx::proto

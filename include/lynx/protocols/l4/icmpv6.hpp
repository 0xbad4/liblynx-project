#pragma once
#include "segment.hpp"
#include "lynx/protocols/l3/ipv6.hpp"

namespace lynx::proto {

    class ICMPv6 LYNX_INHERITANCE_POLICY : public Segment {
        public:

            ICMPv6() = default;

            ICMPv6(uint8_t type, uint8_t code, uint16_t id=0, uint16_t seq=0) noexcept {
                hdr_.type     = type;
                hdr_.code     = code;
                hdr_.checksum = 0;
                hdr_.set_id_seq(id, seq);
            }

            explicit ICMPv6(const hdrs::HdrICMP& h) noexcept : hdr_(h) {}
            
            ~ICMPv6() = default;

            void serialize(Buffer& buf) const noexcept override {
                hdrs::HdrICMP wire = hdr_;
                swap_hdr_byte_order(wire);
                
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrICMP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override {
                if (!data || len < constants::ICMPV6_HDR_LEN) {
                    set_error(Status::MalformedPacket, "ICMPv6 header too short");
                    return;
                }
                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrICMP));
                swap_hdr_byte_order(hdr_);

                load_ = { data + constants::ICMPV6_HDR_LEN,
                        len  - constants::ICMPV6_HDR_LEN };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::ICMPV6_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrICMP* hdr() noexcept override { return &hdr_; }

            void swap_hdr_byte_order(hdrs::HdrICMP& hdr) const noexcept {
                hdr.rest      = __builtin_bswap32(hdr.rest);
                hdr.checksum  = __builtin_bswap16(hdr.checksum);
            }

            // ICMPv6 pseudo-header needs IPv6 src/dst from underlayer_
            void patch_checksum() noexcept override {
                auto* ip = static_cast<proto::Packet*>(underlayer_);
                if (!ip) {
                    set_error(Status::MissingLayer, "ICMPv6: no IP underlayer");
                    return;
                }

                // wire copy — network byte order, checksum zeroed
                hdrs::HdrICMP wire = hdr_;
                wire.rest     = __builtin_bswap32(hdr_.rest);
                wire.checksum = 0;

                uint32_t icmp6_len = sizeof(hdrs::HdrICMP)
                                + static_cast<uint32_t>(load_.size());
                uint32_t total     = 40 + icmp6_len;

                uint8_t buf[total]{};

                // IPv6 pseudo-header (RFC 4443)
                auto* ip6 = static_cast<proto::IPv6*>(ip);
                __builtin_memcpy(buf +  0, ip6->hdr()->src_ip, 16);
                __builtin_memcpy(buf + 16, ip6->hdr()->dst_ip, 16);
                buf[32] = static_cast<uint8_t>(icmp6_len >> 24);
                buf[33] = static_cast<uint8_t>(icmp6_len >> 16);
                buf[34] = static_cast<uint8_t>(icmp6_len >> 8);
                buf[35] = static_cast<uint8_t>(icmp6_len & 0xff);
                // buf[36..38] = 0 (zero-initialized)
                buf[39] = constants::IP_PROTO_ICMPV6;

                __builtin_memcpy(buf + 40, &wire, sizeof(hdrs::HdrICMP));
                if (!load_.empty())
                    __builtin_memcpy(buf + 40 + sizeof(hdrs::HdrICMP),
                                    load_.data(), load_.size());

                // compute and store back into hdr_ — serialize() will bswap it to wire order
                hdr_.checksum = utils::inet_checksum(buf, total);
            }

            [[nodiscard]] uint8_t proto() const noexcept override {
                return constants::IP_PROTO_ICMPV6;
            }

        protected:
            hdrs::HdrICMP hdr_{};
    };

} // namespace lynx::proto
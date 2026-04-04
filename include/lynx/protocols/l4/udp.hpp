#pragma once


#include "segment.hpp"
#include "lynx/protocols/l3/ipv4.hpp"
#include "lynx/protocols/l3/ipv6.hpp"


namespace lynx::proto
{
    class UDP LYNX_INHERITANCE_POLICY : public Segment {
        public:
            UDP() noexcept {
                // defaults
                hdr_.src_port = 0;
                hdr_.dst_port = 0;
                hdr_.length = 0;
                hdr_.checksum = 0;
            }

            ~UDP() = default;

            void serialize(Buffer&buf) const noexcept override {
                hdrs::HdrUDP wire = hdr_;
                swap_hdr_byte_order(wire);

                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrUDP)
                );

                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size())
                );
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override {
                if (!data || len < constants::UDP_HDR_LEN) {
                    set_error(Status::MalformedPacket, "UDP header too short");
                    return;
                }

                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrUDP));
                swap_hdr_byte_order(hdr_);

                uint32_t hdr_bytes = hdr_size();

                load_ = { data + hdr_bytes, len - hdr_bytes };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::UDP_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrUDP* hdr() noexcept override { return &hdr_; }

            void swap_hdr_byte_order(hdrs::HdrUDP& hdr) const noexcept {
                hdr.src_port = __builtin_bswap16(hdr.src_port);
                hdr.dst_port = __builtin_bswap16(hdr.dst_port);
                hdr.length = __builtin_bswap16(hdr.length);
                hdr.checksum = __builtin_bswap16(hdr.checksum);
            }
            
            void patch_checksum() noexcept override {
                hdrs::HdrUDP wire = hdr_;
                swap_hdr_byte_order(wire);

                hdr_.checksum = 0;

                auto* ip = static_cast<proto::Packet*>(underlayer_);
                if (!ip) { set_error(Status::MissingLayer, "UDP: no IP underlayer"); return; }

                uint32_t udp_len = sizeof(hdrs::HdrUDP) + static_cast<uint32_t>(load_.size());

                if (ip->ethertype() == constants::ETH_TYPE_IPV4) {
                    auto* ip4 = static_cast<proto::IPv4*>(ip);
                    uint32_t total = 12 + udp_len;
                    uint8_t  buf[total];

                    __builtin_memcpy(buf + 0, ip4->hdr()->src_ip, 4);
                    __builtin_memcpy(buf + 4, ip4->hdr()->dst_ip, 4);
                    buf[8]  = 0;
                    buf[9]  = constants::IP_PROTO_UDP;
                    buf[10] = static_cast<uint8_t>(udp_len >> 8);
                    buf[11] = static_cast<uint8_t>(udp_len & 0xff);

                    __builtin_memcpy(buf + 12, &hdr_, sizeof(hdrs::HdrUDP));
                    if (!load_.empty())
                        __builtin_memcpy(buf + 12 + sizeof(hdrs::HdrUDP),
                                        load_.data(), load_.size());

                    uint16_t chk  = utils::inet_checksum(buf, total);
                    hdr_.checksum = (chk == 0) ? 0xffff : chk;

                } else if (ip->ethertype() == constants::ETH_TYPE_IPV6) {
                    auto* ip6 = static_cast<proto::IPv6*>(ip);
                    uint32_t total = 40 + udp_len;
                    uint8_t  buf[total]{};

                    __builtin_memcpy(buf +  0, ip6->hdr()->src_ip, 16);
                    __builtin_memcpy(buf + 16, ip6->hdr()->dst_ip, 16);

                    buf[32] = static_cast<uint8_t>(udp_len >> 24);
                    buf[33] = static_cast<uint8_t>(udp_len >> 16);
                    buf[34] = static_cast<uint8_t>(udp_len >> 8);
                    buf[35] = static_cast<uint8_t>(udp_len & 0xff);
                    buf[39] = constants::IP_PROTO_UDP;

                    __builtin_memcpy(buf + 40, &hdr_, sizeof(hdrs::HdrUDP));
                    if (!load_.empty())
                        __builtin_memcpy(buf + 40 + sizeof(hdrs::HdrUDP),
                                        load_.data(), load_.size());

                    uint16_t chk  = utils::inet_checksum(buf, total);
                    hdr_.checksum = (chk == 0) ? 0xffff : chk;   // mandatory in IPv6

                } 
                // HERE: add support for other protocols
                else {
                    set_error(Status::NotImplemented, "UDP: unsupported IP underlayer");
                }
            }

            [[nodiscard]] uint8_t proto() const noexcept { return constants::IP_PROTO_UDP; }

        protected:
            hdrs::HdrUDP hdr_;

    };
    
} // namespace lynx::proto

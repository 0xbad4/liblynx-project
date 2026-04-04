#pragma once


#include "segment.hpp"

namespace lynx::proto
{
    class TCP LYNX_INHERITANCE_POLICY : public Segment {
        public:
            TCP(uint16_t src_port,
                uint16_t dst_port,
                uint32_t seq,
                uint32_t ack,
                uint8_t flags,
                uint16_t window,
                uint16_t urg_ptr = 0,
                uint8_t hdr_words = 5) noexcept
            {
                hdr_.src_port = src_port;
                hdr_.dst_port = dst_port;
                hdr_.seq = seq;
                hdr_.ack = ack;

                hdr_.flags = flags;

                hdr_.set_data_off(5);
                hdr_.window = window;
                hdr_.checksum = 0;
                hdr_.urg_ptr = urg_ptr;
            }

            explicit TCP(const hdrs::HdrTCP& h) noexcept
                : hdr_(h) {}
                
            TCP() noexcept {
                hdr_.src_port = 0;
                hdr_.dst_port = 0;
                hdr_.seq = 0;
                hdr_.ack = 0;
                hdr_.data_off = 0;
                hdr_.flags = 0;
                hdr_.window = 0;
                hdr_.checksum = 0;
                hdr_.urg_ptr = 0;
            }

            ~TCP() = default;

            void serialize(Buffer&buf) const noexcept override {
                hdrs::HdrTCP wire = hdr_;

                wire.src_port = __builtin_bswap16(wire.src_port);
                wire.dst_port = __builtin_bswap16(wire.dst_port);
                wire.ack      = __builtin_bswap32(wire.ack);
                wire.seq      = __builtin_bswap32(wire.seq);
                wire.window   = __builtin_bswap16(wire.window);
                wire.checksum = __builtin_bswap16(wire.checksum);
                wire.urg_ptr  = __builtin_bswap16(wire.urg_ptr);

                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrTCP)
                );

                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size())
                );
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override {
                if (!data || len < constants::TCP_HDR_LEN) {
                    set_error(Status::MalformedPacket, "TCP header too short");
                    return;
                }

                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrTCP));

                swap_hdr_byte_order(hdr_);

                uint32_t hdr_bytes = hdr_.hdr_len();

                if (hdr_bytes < constants::TCP_HDR_LEN || hdr_bytes > len) {
                    set_error(Status::MalformedPacket, "TCP: header length out of range");
                    return;
                }
                load_ = { data + hdr_bytes, len - hdr_bytes };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return hdr_.hdr_len() * 4u; // data_off is in 32-bit words, convert to bytes
            }

            [[nodiscard]] hdrs::HdrTCP* hdr() noexcept override { return &hdr_; }

            void swap_hdr_byte_order(hdrs::HdrTCP& hdr) const noexcept {
                hdr.src_port = __builtin_bswap16(hdr.src_port);
                hdr.dst_port = __builtin_bswap16(hdr.dst_port);
                hdr.seq = __builtin_bswap32(hdr.seq);
                hdr.ack = __builtin_bswap32(hdr.ack);
                hdr.window = __builtin_bswap16(hdr.window);
                hdr.checksum = __builtin_bswap16(hdr.checksum);
                hdr.urg_ptr = __builtin_bswap16(hdr.urg_ptr);
            }
            
            void patch_checksum() noexcept override {
                hdrs::HdrTCP wire = hdr_;
                swap_hdr_byte_order(wire);

                wire.checksum = 0;

                auto* ip = static_cast<proto::Packet*>(underlayer_);
                if (!ip) { set_error(Status::MissingLayer, "TCP: no IP underlayer"); return; }

                uint32_t tcp_len = sizeof(hdrs::HdrTCP) + static_cast<uint32_t>(load_.size());

                if (ip->ethertype() == constants::ETH_TYPE_IPV4) {
                    auto* ip4 = static_cast<proto::IPv4*>(ip);
                    uint32_t total = 12 + tcp_len;
                    uint8_t  buf[total];

                    __builtin_memcpy(buf + 0, ip4->hdr()->src_ip, 4);
                    __builtin_memcpy(buf + 4, ip4->hdr()->dst_ip, 4);

                    buf[8]  = 0;
                    buf[9]  = constants::IP_PROTO_TCP;
                    buf[10] = static_cast<uint8_t>(tcp_len >> 8);
                    buf[11] = static_cast<uint8_t>(tcp_len & 0xff);

                    __builtin_memcpy(buf + 12, &wire, sizeof(hdrs::HdrTCP));
                    if (!load_.empty())
                        __builtin_memcpy(buf + 12 + sizeof(hdrs::HdrTCP),
                                        load_.data(), load_.size());

                    hdr_.checksum = utils::inet_checksum(buf, total);

                } else if (ip->ethertype() == constants::ETH_TYPE_IPV6) {
                    auto* ip6 = static_cast<proto::IPv6*>(ip);
                    uint32_t total = 40 + tcp_len;
                    uint8_t  buf[total]{};

                    __builtin_memcpy(buf +  0, ip6->hdr()->src_ip, 16);
                    __builtin_memcpy(buf + 16, ip6->hdr()->dst_ip, 16);

                    buf[32] = static_cast<uint8_t>(tcp_len >> 24);
                    buf[33] = static_cast<uint8_t>(tcp_len >> 16);
                    buf[34] = static_cast<uint8_t>(tcp_len >> 8);
                    buf[35] = static_cast<uint8_t>(tcp_len & 0xff);

                    buf[39] = constants::IP_PROTO_TCP;

                    __builtin_memcpy(buf + 40, &wire, sizeof(hdrs::HdrTCP));
                    if (!load_.empty())
                        __builtin_memcpy(buf + 40 + sizeof(hdrs::HdrTCP),
                                        load_.data(), load_.size());

                    hdr_.checksum = utils::inet_checksum(buf, total);

                } 
                // HERE: add support for other protocols
                else {
                    set_error(Status::NotImplemented, "TCP: unsupported IP underlayer");
                }
            }

            [[nodiscard]] uint8_t proto() const noexcept { return constants::IP_PROTO_TCP; }


        protected:
            hdrs::HdrTCP hdr_;
    };
} // namespace lynx::proto

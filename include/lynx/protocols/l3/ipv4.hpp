#pragma once

//  IPv4 — L3 concrete implementation, inherits Packet.

#include "packet.hpp"

namespace lynx::proto 
{
    class IPv4 LYNX_INHERITANCE_POLICY : public Packet {
        public:

            explicit IPv4(const hdrs::HdrIPv4& h) noexcept : hdr_(h) {}

            IPv4(const uint8_t src[4],
                const uint8_t dst[4],
                uint8_t proto,
                uint16_t total_len = 0,
                uint16_t id = 0,
                uint16_t flags_frag = 0,
                uint8_t ttl = 64,
                uint8_t dscp_ecn = 0) noexcept
            {
                hdr_.set_ver_ihl(4, 5);
                hdr_.dscp_ecn   = dscp_ecn;
                hdr_.total_len  = total_len;
                hdr_.id         = id;
                hdr_.flags_frag = flags_frag;
                hdr_.ttl        = ttl;
                hdr_.proto      = proto;
                hdr_.checksum   = 0;

                std::memcpy(hdr_.src_ip, src, 4);
                std::memcpy(hdr_.dst_ip, dst, 4);
            }

            IPv4() noexcept {
                hdr_.set_ver_ihl(4, 5);          // version=4, ihl=5 (20B, no options)
                hdr_.set_dscp_ecn(0, 0);
                hdr_.id         = 0;
                hdr_.set_flags_frag(0x02, 0);    // DF=1, MF=0, frag_offset=0
                hdr_.ttl        = constants::IPV4_TTL_DEF;
                hdr_.proto      = 0;             // caller sets: IP_PROTO_TCP/UDP/ICMP
                hdr_.checksum   = 0;             // patched post-serialize
            }

            ~IPv4() = default;

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrIPv4 wire = hdr_;
                swap_hdr_byte_order(wire);

                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrIPv4)
                );

                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size())
                );
            }

            // parse
            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < constants::IPV4_HDR_LEN) {
                    set_error(Status::MalformedPacket, "IPv4 header too short");
                    return;
                }

                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrIPv4));

                swap_hdr_byte_order(hdr_);

                if (hdr_.version() != constants::IPV4_VERSION) {
                    set_error(Status::MalformedPacket, "IPv4: version != 4");
                    return;
                }

                uint32_t hdr_bytes = hdr_.hdr_len();

                if (hdr_bytes < constants::IPV4_HDR_LEN || hdr_bytes > len) {
                    set_error(Status::MalformedPacket, "IPv4: ihl out of range");
                    return;
                }
                load_ = { data + hdr_bytes, len - hdr_bytes };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                uint32_t h = hdr_.hdr_len();
                return (h >= constants::IPV4_HDR_LEN) ? h : constants::IPV4_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrIPv4* hdr() noexcept override { return &hdr_; }

            [[nodiscard]] uint16_t ethertype() const noexcept override {
                return constants::ETH_TYPE_IPV4;
            }

            [[nodiscard]] const uint8_t* dst() const noexcept override {
                return hdr_.dst_ip;
            }

            void swap_hdr_byte_order(hdrs::HdrIPv4& hdr) const noexcept {
                hdr.total_len  = __builtin_bswap16(hdr.total_len);
                hdr.id         = __builtin_bswap16(hdr.id);
                hdr.flags_frag = __builtin_bswap16(hdr.flags_frag);
                hdr.checksum   = __builtin_bswap16(hdr.checksum);
            }
            
            void patch_checksum() noexcept override {
                hdrs::HdrIPv4 wire = hdr_;
                swap_hdr_byte_order(wire);
                
                wire.checksum = 0;
                hdr_.checksum = utils::inet_checksum(
                    reinterpret_cast<const uint8_t*>(&wire),
                    wire.hdr_len()   // ihl * 4 — handles options
                );
            }

        protected:
            hdrs::HdrIPv4              hdr_{};
};

} // namespace lynx::proto

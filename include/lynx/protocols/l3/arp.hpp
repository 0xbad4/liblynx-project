#pragma once


#include "packet.hpp"

namespace lynx::proto
{
    class ARP LYNX_INHERITANCE_POLICY : public Packet {
        public:

            explicit ARP(const hdrs::HdrARP& h) noexcept : hdr_(h) {}

            ARP(uint16_t hrd,
                uint16_t pro,
                uint8_t hln,
                uint8_t pln,
                uint16_t op,
                const uint8_t sha[6],
                const uint8_t spa[4],
                const uint8_t tha[6],
                const uint8_t tpa[4]) noexcept
            {
                hdr_.htype = hrd;
                hdr_.ptype = pro;
                hdr_.hlen  = hln;
                hdr_.plen  = pln;
                hdr_.oper  = op;

                std::memcpy(hdr_.sha, sha, 6);
                std::memcpy(hdr_.spa, spa, 4);
                std::memcpy(hdr_.tha, tha, 6);
                std::memcpy(hdr_.tpa, tpa, 4);
            }

            ARP() noexcept {
                hdr_.htype = constants::ARP_HRD_ETHER;
                hdr_.ptype = constants::ETH_TYPE_IPV4;
                hdr_.hlen  = constants::ARP_HLEN_ETH;
                hdr_.plen  = constants::ARP_PLEN_IPV4;
                hdr_.oper = constants::ARP_OP_REQUEST;
            }

            ~ARP() = default;
            
            void serialize(Buffer&buf) const noexcept override {
                hdrs::HdrARP wire = hdr_;

                // byte order (network order = big endian)
                swap_hdr_byte_order(wire);

                // hlen / plen are 1 byte → no swap
                buf.write(
                    reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrIPv4)
                );
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override{
                if (!data || len < constants::ARP_HDR_LEN) {
                    set_error(Status::MalformedPacket, "ARP header too short");
                    return;
                }

                __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrIPv4));
                swap_hdr_byte_order(hdr_);

                if (hdr_.hlen != constants::ARP_HLEN_ETH || hdr_.plen != constants::ARP_PLEN_IPV4) {
                    set_error(Status::MalformedPacket, "ARP: invalid address lengths");
                    return;
                }
                // no load in ARP
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return constants::ARP_HDR_LEN;
            }

            [[nodiscard]] hdrs::HdrARP* hdr() noexcept override {
                return &hdr_;
            }

            [[nodiscard]] uint16_t ethertype() const noexcept override {
                return constants::ETH_TYPE_ARP;
            }

            [[nodiscard]] const uint8_t* dst() const noexcept override {
                return nullptr;
            }

            template<typename T> std::unique_ptr<T> as() const noexcept {
                // ARP has no next layer
                return nullptr;
            }

            void set_load(const_view_t payload) noexcept {
                set_error(Status::NotImplemented, "ARP has no payload");
            }

            void swap_hdr_byte_order(hdrs::HdrARP& hdr) const noexcept {
                hdr.htype = __builtin_bswap16(hdr.htype);
                hdr.ptype = __builtin_bswap16(hdr.ptype);
                hdr.oper  = __builtin_bswap16(hdr.oper);
            }

        protected:
            hdrs::HdrARP hdr_;
    };
} // namespace lynx::proto

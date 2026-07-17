#pragma once

//  Dot1Q — concrete 802.1Q VLAN-tagged Ethernet frame implementation.
//
//  wire layout (18 bytes total header):
//    [ dst_mac(6) | src_mac(6) | tpid(2)=0x8100 | tci(2) | ethertype(2) ]
//
//  tci breakdown (2 bytes):
//    [15:13] pcp     — 3 bits priority code point
//    [12]    dei     — 1 bit  drop eligible indicator
//    [11:0]  vlan_id — 12 bits VLAN identifier (0-4094)

#include "lynx/protocols/l2/frame.hpp"
#include "hdrs.hpp"
#include "const.hpp"

namespace lynx::proto {

    class Dot1Q LYNX_INHERITANCE_POLICY : public Frame {
        public:
            explicit Dot1Q(const hdrs::HdrDot1Q& h) noexcept : hdr_(h) {}

            Dot1Q(const uint8_t dst[6],
                const uint8_t src[6],
                uint16_t tpid,
                uint16_t tci,
                uint16_t ethertype) noexcept
            {
                std::memcpy(hdr_.dst_mac, dst, 6);
                std::memcpy(hdr_.src_mac, src, 6);
                hdr_.tpid = tpid;
                hdr_.tci = tci;
                hdr_.ethertype = ethertype;
            }

            Dot1Q()  = default;
            ~Dot1Q() = default;

            // writes hdr_ then load_ into buf.
            // tpid, tci, ethertype converted to network byte order on wire.
            // FCS NOT written — NIC appends on transmit.

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrDot1Q wire = hdr_;
                swap_hdr_byte_order(wire);

                buf.write(reinterpret_cast<const uint8_t*>(&wire),
                        sizeof(hdrs::HdrDot1Q));

                if (!load_.empty())
                    buf.write(load_.data(),
                            static_cast<uint32_t>(load_.size()));
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrDot1Q)) {
                    set_error(Status::MalformedPacket, "Dot1Q frame too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrDot1Q));

                swap_hdr_byte_order(hdr_);

                // sanity check — tpid should always be 0x8100
                if (hdr_.tpid != constants::ETH_TYPE_VLAN) {
                    set_error(Status::MalformedPacket,
                            "Dot1Q: tpid is not 0x8100");
                    return;
                }

                load_ = { data + sizeof(hdrs::HdrDot1Q),
                        len  - sizeof(hdrs::HdrDot1Q) };
            }
            
            void swap_hdr_byte_order(hdrs::HdrDot1Q& hdr) const noexcept {
                hdr.tpid      = swap16(hdr.tpid);
                hdr.tci       = swap16(hdr.tci);
                hdr.ethertype = swap16(hdr.ethertype);
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrDot1Q));
            }

            [[nodiscard]] hdrs::HdrDot1Q* hdr() noexcept override { return &hdr_; }

            FrameType type() const noexcept override { return FrameType::Dot1Q; }

        protected:
            hdrs::HdrDot1Q             hdr_{};         // packed header, all fields in host order
    };

} // namespace lynx::proto

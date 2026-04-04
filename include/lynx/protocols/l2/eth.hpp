#pragma once

//  Ether — concrete L2 Ethernet II implementation.
#include "frame.hpp"
#include "lynx/protocols/hdrs.hpp"

namespace lynx::proto 
{

class Ether LYNX_INHERITANCE_POLICY : public Frame {
    public:
    
        static constexpr FrameType frame_type = FrameType::Eth;

        explicit Ether(const hdrs::HdrEth& h) noexcept
            : hdr_(h) {}

        Ether(const uint8_t dst[6], const uint8_t src[6], uint16_t ethertype) noexcept {
            std::memcpy(hdr_.dst_mac, dst, 6);
            std::memcpy(hdr_.src_mac, src, 6);

            hdr_.ethertype = ethertype;
        }

        Ether()  = default;

        ~Ether() = default;
    
        // writes hdr_ then load_ into buf.
        // ethertype is converted to network byte order here — store in host order.
        // FCS is NOT written — NIC appends it on transmit.
    
        void serialize(Buffer& buf) const noexcept override
        {
            // ethertype stored in host order — swap to network order on wire
            hdrs::HdrEth wire = hdr_;
            wire.ethertype = __builtin_bswap16(hdr_.ethertype);
    
            buf.write(reinterpret_cast<const uint8_t*>(&wire),
                    sizeof(hdrs::HdrEth));
    
            if (!load_.empty())
                buf.write(load_.data(),
                        static_cast<uint32_t>(load_.size()));
        }
    
        void dissect(const uint8_t* data, uint32_t len) noexcept override
        {
            if (!data || len < sizeof(hdrs::HdrEth)) {
                set_error(Status::MalformedPacket, "Ethernet frame too short");
                return;
            }
    
            __builtin_memcpy(&hdr_, data, sizeof(hdrs::HdrEth));
    
            // host byte order — no bswap needed at comparison sites
            hdr_.ethertype = __builtin_bswap16(hdr_.ethertype);
    
            load_ = { data + sizeof(hdrs::HdrEth),
                    len  - sizeof(hdrs::HdrEth) };
        }
    
        [[nodiscard]] uint32_t hdr_size() const noexcept override {
            return static_cast<uint32_t>(sizeof(hdrs::HdrEth));
        }
    
        [[nodiscard]] hdrs::HdrEth* hdr() noexcept override { return &hdr_; }
    
    protected:
        hdrs::HdrEth               hdr_{};         // packed header, ethertype in host order
};

}  // lynx::proto

#pragma once

//  IPv6CP — IPv6 Control Protocol (PPP_PROTO_IPV6CP = 0x8057)
//
//  negotiates IPv6 parameters. the primary option is the 8-byte interface
//  identifier (IPV6CP_OPT_IFACE_ID) used to form the link-local address.
//
//  same header layout as LCP and IPCP.

#include "lynx/protocols/l2/ppp/tlv_base.hpp"

namespace lynx::proto
{
    class IPv6CP LYNX_INHERITANCE_POLICY : public ProtocolBaseObject, TLVProtocolBaseClass {
        public:

            IPv6CP() noexcept {
                hdr_.code   = constants::PPP_CODE_CONF_REQ;
                hdr_.id     = 0;
                hdr_.length = 0;
            }

            IPv6CP(uint8_t code, uint8_t id) noexcept {
                hdr_.code   = code;
                hdr_.id     = id;
                hdr_.length = 0;
            }

            explicit IPv6CP(const hdrs::HdrIPv6CP& h) noexcept : hdr_(h) {}
            ~IPv6CP() = default;

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrIPv6CP wire = hdr_;
                wire.length = swap16(
                    static_cast<uint16_t>(hdr_size() + load_.size()));
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrIPv6CP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrIPv6CP)) {
                    set_error(Status::MalformedPacket, "IPv6CP header too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrIPv6CP));
                hdr_.length = swap16(hdr_.length);

                uint32_t payload_len =
                    hdr_.length - static_cast<uint32_t>(sizeof(hdrs::HdrIPv6CP));
                if (payload_len > len - sizeof(hdrs::HdrIPv6CP))
                    payload_len = len - sizeof(hdrs::HdrIPv6CP);

                load_ = { data + sizeof(hdrs::HdrIPv6CP), payload_len };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrIPv6CP));
            }

            [[nodiscard]] hdrs::HdrIPv6CP* hdr() noexcept override { return &hdr_; }

            void patch_checksum() noexcept override {}
            
            
            [[nodiscard]] hdrs::HdrIPv6CPOpt tlv_next() noexcept {
                return base_tlv_next(load_);
            }

            // just a macro (check helpcls.hpp)
            INCLUDE_ADD_OPTION


        protected:
            hdrs::HdrIPv6CP hdr_{};
            size_t tlv_pos_ = 0;
        };

    
} // namespace lynx::proto

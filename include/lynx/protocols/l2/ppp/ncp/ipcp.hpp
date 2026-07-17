#pragma once

// IPCP — IP Control Protocol (PPP_PROTO_IPCP = 0x8021)
//
//  negotiates IPv4 parameters over a PPP link.
//  options include the local IP address (IPCP_OPT_ADDR) and DNS servers
//  (IPCP_OPT_DNS1 / IPCP_OPT_DNS2).
//
//  IPCP shares the exact same 4-byte header layout as LCP — the class below
//  is structurally identical to LCP. it exists as a separate type so that
//  as<IPCP>() and as<LCP>() dispatch correctly based on the PPP protocol field.
//
//  dissection:
//    auto ipcp = ppp->as<IPCP>();   // when ppp->hdr()->is_ipcp()
//
//  crafting (request an IP address):
//    // IPCP_OPT_ADDR: type(1B) | length(1B) | ip(4B)
//    const uint8_t addr_opt[] = { IPCP_OPT_ADDR, 6, 0,0,0,0 };
//    IPCP ipcp(PPP_CODE_CONF_REQ, 1);
//    ipcp / Raw(addr_opt, sizeof(addr_opt));
//    PPP ppp(PPP_ADDRESS, PPP_CONTROL, PPP_PROTO_IPCP);
//    ppp / ipcp;

#include "lynx/protocols/l2/ppp/tlv_base.hpp"



namespace lynx::proto
{
    class IPCP LYNX_INHERITANCE_POLICY : public ProtocolBaseObject, public TLVProtocolBaseClass {
        public:

            IPCP() noexcept {
                hdr_.code   = constants::PPP_CODE_CONF_REQ;
                hdr_.id     = 0;
                hdr_.length = 0;
            }

            IPCP(uint8_t code, uint8_t id) noexcept {
                hdr_.code   = code;
                hdr_.id     = id;
                hdr_.length = 0;
            }

            explicit IPCP(const hdrs::HdrLCP& h) noexcept : hdr_(h) {}
            ~IPCP() = default;

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrLCP wire = hdr_;
                wire.length = swap16(static_cast<uint16_t>(hdr_size() + load_.size()));
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrLCP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrLCP)) {
                    set_error(Status::MalformedPacket, "IPCP header too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrLCP));
                hdr_.length = swap16(hdr_.length);

                uint32_t payload_len =
                    hdr_.length - static_cast<uint32_t>(sizeof(hdrs::HdrLCP));
                if (payload_len > len - sizeof(hdrs::HdrLCP))
                    payload_len = len - sizeof(hdrs::HdrLCP);

                load_ = { data + sizeof(hdrs::HdrLCP), payload_len };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrLCP));
            }

            [[nodiscard]] hdrs::HdrLCP* hdr() noexcept override { return &hdr_; }

            void patch_checksum() noexcept override {}

            [[nodiscard]] hdrs::HdrIPCPOpt tlv_next() noexcept {
                return base_tlv_next(load_);
            }

            // just a macro (check helpcls.hpp)
            INCLUDE_ADD_OPTION

        protected:
            hdrs::HdrLCP hdr_{};
            size_t tlv_pos_ = 0;
        };
} // namespace lynx::proto

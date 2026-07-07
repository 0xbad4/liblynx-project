#pragma once

//  LCP — Link Control Protocol (PPP_PROTO_LCP = 0xC021)
//
//  LCP establishes, configures, authenticates, and terminates PPP links.
//  it is exchanged before any network-layer traffic and must reach the
//  "opened" state before IPCP or IPv6CP negotiation can begin.
//
//  options are encoded as TLVs in the payload of Configure-Request /
//  Configure-Ack / Configure-Nak / Configure-Reject messages.
//  callers parse individual options from load_ as HdrLCPOpt structs.
//
//  dissection:
//    auto lcp = ppp->as<LCP>();   // when ppp->hdr()->is_lcp()
//    if (lcp->hdr()->code == PPP_CODE_ECHO_REQ) { ... }
//
//  crafting:
//    LCP lcp(PPP_CODE_CONF_REQ, 1);
//    // MRU option: type(1B) | length(1B) | value(2B)
//    const uint8_t mru[] = { LCP_OPT_MRU, 4,
//        static_cast<uint8_t>(PPP_DEFAULT_MRU >> 8),
//        static_cast<uint8_t>(PPP_DEFAULT_MRU & 0xFF) };
//    lcp / Raw(mru, sizeof(mru));
//    PPP ppp(PPP_ADDRESS, PPP_CONTROL, PPP_PROTO_LCP);
//    ppp / lcp;

#include "protocols/l2/ppp/tlv_base.hpp"

namespace lynx::proto
{
    class LCP LYNX_INHERITANCE_POLICY : public ProtocolBaseObject, TLVProtocolBaseClass {
        public:

            LCP() noexcept {
                hdr_.code   = constants::PPP_CODE_CONF_REQ;
                hdr_.id     = 0;
                hdr_.length = 0;  // computed in serialize()
            }

            LCP(uint8_t code, uint8_t id) noexcept {
                hdr_.code   = code;
                hdr_.id     = id;
                hdr_.length = 0;
            }

            explicit LCP(const hdrs::HdrLCP& h) noexcept : hdr_(h) {}
            ~LCP() = default;

            // ── serialize
            // length computed from hdr_size() + load_.size() — do not set manually.

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrLCP wire = hdr_;
                wire.length = swap16(static_cast<uint16_t>(hdr_size() + load_.size()));
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrLCP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            // ── dissect
            // data[0] is the code byte. load_ spans the option / data bytes after
            // the 4-byte header up to hdr_.length — any trailing bytes are ignored.

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrLCP)) {
                    set_error(Status::MalformedPacket, "LCP header too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrLCP));
                hdr_.length = swap16(hdr_.length);

                if (hdr_.length < sizeof(hdrs::HdrLCP)) {
                    set_error(Status::MalformedPacket, "LCP: length field too small");
                    return;
                }

                uint32_t payload_len = hdr_.length - static_cast<uint32_t>(sizeof(hdrs::HdrLCP));

                // clamp to bytes actually present — handles truncated captures
                if (payload_len > len - sizeof(hdrs::HdrLCP))
                    payload_len = len - sizeof(hdrs::HdrLCP);

                load_ = { data + sizeof(hdrs::HdrLCP), payload_len };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrLCP));
            }

            [[nodiscard]] hdrs::HdrLCP* hdr() noexcept override { return &hdr_; }

            void patch_checksum() noexcept override {}

            [[nodiscard]] hdrs::HdrLCPOpt tlv_next() noexcept {
                return base_tlv_next(load_);
            }

            // just a macro (check helpcls.hpp)
            INCLUDE_ADD_OPTION

        protected:
            hdrs::HdrLCP hdr_{};
            size_t tlv_pos_ = 0;
};
    
} // namespace lynx::proto

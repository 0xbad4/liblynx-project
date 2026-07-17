#pragma once

//  PPP — Point-to-Point Protocol
//
//  the full uncompressed header is 4 bytes: address(1) + control(1) +
//  protocol(2). address is always 0xFF and control is always 0x03.
//  LCP negotiation may compress the header — ACFC removes address+control,
//  PFC compresses the protocol field to 1 byte when its high byte is 0x00.
//
//  dissection:
//    auto ppp = some_layer->as<PPP>();
//    if (ppp->hdr()->is_ipv4())
//        auto ip = ppp->as<IPv4>();
//    if (ppp->hdr()->is_lcp())
//        auto lcp = ppp->as<LCP>();
//
//  crafting:
//    PPP ppp;
//    ppp.hdr()->protocol = PPP_PROTO_IP;
//    ppp / ip;

#include "lynx/protocols/l2/frame.hpp"
#include "hdrs.hpp"
#include "const.hpp"


namespace lynx::proto
{
    class PPP LYNX_INHERITANCE_POLICY : public Frame {
        public:
            PPP() noexcept {
                hdr_.address  = constants::PPP_ADDRESS;
                hdr_.control  = constants::PPP_CONTROL;
                hdr_.protocol = constants::PPP_PROTO_IP;  // caller overrides before chaining
            }

            explicit PPP(const hdrs::HdrPPP& h) noexcept : hdr_(h) {}

            PPP(uint8_t address, uint8_t control, uint16_t protocol) noexcept {
                hdr_.address  = address;
                hdr_.control  = control;
                hdr_.protocol = protocol;
            }

            ~PPP() = default;

            // ── serialize
            // address, control, and protocol stored in host byte order internally.
            // protocol is the only multi-byte field — swapped to network byte order
            // on the wire copy. address and control are single bytes, no swap needed.

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrPPP wire = hdr_;
                wire.protocol = swap16(hdr_.protocol);
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrPPP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            // ── dissect
            // detects ACFC compression: if data[0] == 0xFF the full header is present.
            // if data[0] & 0x01 == 1 the address/control bytes are absent (ACFC).
            // protocol field converted to host byte order after copy regardless of form.

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < constants::PPP_HDR_LEN_MIN) {
                    set_error(Status::MalformedPacket, "PPP frame too short");
                    return;
                }

                if (data[0] == constants::PPP_ADDRESS) {
                    // full header — address (0xFF) + control (0x03) + protocol (2B)
                    if (len < constants::PPP_HDR_LEN) {
                        set_error(Status::MalformedPacket,
                                "PPP: full header present but frame too short");
                        return;
                    }
                    memory_copy(&hdr_, data, sizeof(hdrs::HdrPPP));
                    hdr_.protocol = swap16(hdr_.protocol);
                    load_ = { data + constants::PPP_HDR_LEN,
                            len  - constants::PPP_HDR_LEN };
                } else {
                    // ACFC active — first byte is the high byte of protocol field.
                    // populate address and control with their standard values for
                    // consistent access via hdr_ regardless of compression state.
                    hdr_.address = constants::PPP_ADDRESS;
                    hdr_.control = constants::PPP_CONTROL;
                    if (len < constants::PPP_HDR_LEN_ACFC) {
                        set_error(Status::MalformedPacket,
                                "PPP: ACFC form too short");
                        return;
                    }
                    hdr_.protocol = swap16(*reinterpret_cast<const uint16_t*>(data));
                    load_ = { data + constants::PPP_HDR_LEN_ACFC,
                            len  - constants::PPP_HDR_LEN_ACFC };
                }
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrPPP));
            }

            // ── header access
            // covariant return — HdrPPP* directly, no cast at call site.
            // protocol is in host byte order — serialize() handles the wire swap.

            [[nodiscard]] hdrs::HdrPPP* hdr() noexcept override { return &hdr_; }

            // ── Frame virtuals
            // PPP is a point-to-point protocol — there are no MAC addresses.

            [[nodiscard]] const uint8_t* dst_mac()   const noexcept { return nullptr; }
            [[nodiscard]] const uint8_t* src_mac()   const noexcept { return nullptr; }
            [[nodiscard]] uint16_t       ethertype() const noexcept { return 0; }

            // patch_checksum — no-op.
            // the PPP FCS (frame check sequence) is appended at the serial/modem
            // level and is not part of the protocol header written here.
            void patch_checksum() noexcept override {}

            FrameType type() const noexcept override { return FrameType::PPP; }
        protected:
            hdrs::HdrPPP hdr_{};
    };
} // namespace lynx::proto


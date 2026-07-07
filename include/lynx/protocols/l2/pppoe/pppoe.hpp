#pragma once


#include "protocols/l2/frame.hpp"
#include "hdrs.hpp"
#include "const.hpp"

namespace lynx::proto { 
    class PPPoE LYNX_INHERITANCE_POLICY : public Frame {
        public:
            PPPoE() noexcept {
                hdr_.ver_type   = constants::PPPOE_VER_TYPE;
                hdr_.code       = constants::PPPOE_CODE_SESSION;
                hdr_.session_id = 0x0000;
                hdr_.length     = 0;  // computed in serialize()
            }
        
            explicit PPPoE(const hdrs::HdrPPPoE& h) noexcept : hdr_(h) {}
        
            PPPoE(uint8_t code, uint16_t session_id) noexcept {
                hdr_.ver_type   = constants::PPPOE_VER_TYPE;
                hdr_.code       = code;
                hdr_.session_id = session_id;
                hdr_.length     = 0;
            }
        
            ~PPPoE() = default;
        
            // ── serialize
            // session_id and length swapped to network byte order on the wire copy.
            // length is computed from load_.size() — never set manually.
            // ver_type and code are single bytes, no swap needed.
        
            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrPPPoE wire = hdr_;
                wire.session_id = swap16(hdr_.session_id);
                wire.length     = swap16(
                    static_cast<uint16_t>(load_.size()));
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrPPPoE));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }
        
            // ── dissect
            // called by eth->as<PPPoE>() with eth.load() as input.
            // data[0] is ver_type — always PPPOE_VER_TYPE (0x11).
            // session_id and length converted to host byte order after memcpy.
            // load_ is clamped to hdr_.length bytes — the declared payload size.
        
            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrPPPoE)) {
                    set_error(Status::MalformedPacket, "PPPoE header too short");
                    return;
                }
        
                memory_copy(&hdr_, data, sizeof(hdrs::HdrPPPoE));
                hdr_.session_id = swap16(hdr_.session_id);
                hdr_.length     = swap16(hdr_.length);
        
                if (hdr_.version() != 1 || hdr_.type() != 1) {
                    set_error(Status::MalformedPacket, "PPPoE: invalid version or type field");
                    return;
                }
        
                if (hdr_.length > len - sizeof(hdrs::HdrPPPoE)) {
                    set_error(Status::TruncatedPayload, "PPPoE: length exceeds buffer");
                    return;
                }
        
                // session frames carry a PPP frame — use pppoe->as<PPP>() to continue
                // discovery frames carry TLV tags  — use pppoe->as<Raw>() to read them
                load_ = { data + sizeof(hdrs::HdrPPPoE), hdr_.length };
            }
        
            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrPPPoE));
            }
        
            // ── header access
            // covariant return — HdrPPPoE* directly, no cast at call site.
            // do not set hdr_.length manually — computed in serialize().
        
            [[nodiscard]] hdrs::HdrPPPoE* hdr() noexcept override { return &hdr_; }
        
            // ── Frame virtuals
            // MACs live in the outer Ether header, not here.
            // ethertype reflects whether this is a discovery or session frame.
        
            [[nodiscard]] uint16_t       ethertype() const noexcept {
                return hdr_.is_session()
                    ? constants::PPPOE_ETHERTYPE_SESSION
                    : constants::PPPOE_ETHERTYPE_DISC;
            }

            // patch_checksum — no-op, PPPoE carries no checksum field
            void patch_checksum() noexcept override {}

            FrameType type() const noexcept override { return FrameType::PPPoE; }

            // tlv ops
            bool is_session() const noexcept { return hdr_.is_session(); }

            bool is_discovery() const noexcept { return hdr_.is_discovery(); }
        
            void tlv_reset() noexcept { tlv_pos_ = 0; }

            [[nodiscard]] hdrs::PPPoETag tlv_next() noexcept {
                // if not discovery frame return empty tag
                if (!is_discovery()) return {};

                constexpr uint32_t hdr_sz = 4;  // type(2) + length(2)

                if (tlv_pos_ + hdr_sz > load_.size()) return {};

                const uint8_t* p = load_.data() + tlv_pos_;
                uint16_t type = static_cast<uint16_t>((p[0] << 8) | p[1]);
                uint16_t len  = static_cast<uint16_t>((p[2] << 8) | p[3]);

                if (tlv_pos_ + hdr_sz + len > load_.size()) return {};

                hdrs::PPPoETag tag{ type, len, { p + hdr_sz, len } };
                tlv_pos_ += hdr_sz + len;
                return tag;
            }

            // appends one TLV tag to load_: type(2B) | length(2B) | value(length bytes)
            // length in the wire format excludes the 4-byte tag header.
            // only meaningful on discovery frames (PADI/PADO/PADR/PADS/PADT) —
            // returns false and does nothing on session frames.
            //
            // owned tags (previously added via tlv_add) are released and replaced
            // when the buffer grows. borrowed bytes from the capture slab are copied
            // into the new owned buffer and left untouched in the slab — see
            // ppp/TLVBase::base_add_option() ownership note.

            bool tlv_add(uint16_t type, const uint8_t* value, uint16_t value_size) noexcept
            {
                if (!is_discovery()) return false;

                // write tag header (4 bytes, network byte order) + value into a temp
                // header block, then delegate allocation and ownership to base_add_option.
                // base_add_option expects a 2-byte header, so we build the full 4-byte
                // PPPoE tag header ourselves and pass value_size = header(4) + data - 2

                uint32_t tag_total = 4u + value_size;

                uint32_t existing = static_cast<uint32_t>(load_.size());
                uint32_t needed   = existing + tag_total;

                bool already_owned = load_buf_.ok()
                                && !load_.empty()
                                && load_.data() == load_buf_.begin();

                if (!already_owned || needed > load_buf_.cap()) {
                    Buffer fresh = Buffer::alloc(needed);
                    if (!fresh.ok()) return false;
                    if (existing)
                        fresh.write(load_.data(), existing);
                    load_buf_ = std::move(fresh);
                }

                // write tag header in network byte order
                uint8_t hdr[4] = {
                    static_cast<uint8_t>(type       >> 8),
                    static_cast<uint8_t>(type       & 0xFF),
                    static_cast<uint8_t>(value_size >> 8),
                    static_cast<uint8_t>(value_size & 0xFF)
                };
                load_buf_.write(hdr, 4);
                if (value_size)
                    load_buf_.write(value, value_size);

                load_ = { load_buf_.begin(), load_buf_.len() };
                return true;
            }
        
        protected:
            hdrs::HdrPPPoE hdr_{};
            size_t tlv_pos_ = 0;
        };

    
} // namespace lynx::proto
 

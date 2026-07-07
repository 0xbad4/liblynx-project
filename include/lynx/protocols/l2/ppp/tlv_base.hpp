#pragma once

// Functions that are shared between LCP, IPCP, and IPv6CP.


#include "protocols/l2/frame.hpp"
#include "hdrs.hpp"


namespace lynx::proto
{

    #define INCLUDE_ADD_OPTION bool add_option(uint8_t type, const uint8_t* value, uint8_t value_size) noexcept \
         {  return base_add_option(type, value, value_size, load_, load_buf_); }

    // considering LCP as base class for IPCP and IPv6CP.
    class TLVProtocolBaseClass {
        public:
            void tlv_reset() noexcept { tlv_pos_ = 0; }


        // NOTE: A virtual tlv_next() existed previously, but returning TLV objects by value
        //       prevents derived classes from overriding it with their own TLV types, since
        //       covariant return types do not apply to values and object slicing would occur.
        //       Instead, base_tlv_next() returns the common base TLV structure. Derived
        //       classes may provide their own wrappers or cast the result to a more specific
        //       TLV type when appropriate. 
        
        protected:
            // common TLV parsing state for LCP/IPCP/IPv6CP
            uint32_t tlv_pos_ = 0;  // offset of next TLV to parse within load_

            // there is no constraint stopping you (user) from parsing non-tlv data with this method,
            //      but it will return empty options or you may get bs results if you do so.
            [[nodiscard]] hdrs::HdrBaseTLV base_tlv_next(const_view_t& load_) noexcept {
                constexpr uint32_t hdr_sz = 2;  // type(1) + length(1)

                if (tlv_pos_ + hdr_sz > load_.size()) return {};

                const uint8_t* p = load_.data() + tlv_pos_;
                uint8_t type   = p[0];
                uint8_t length = p[1];  // includes this 2-byte header — RFC 1661 §6

                // length can never be smaller than the header it describes
                if (length < hdr_sz) return {};

                // total option size (length) must fit from tlv_pos_
                if (tlv_pos_ + length > load_.size()) return {};

                hdrs::HdrBaseTLV opt { type, length, { p + hdr_sz, length - hdr_sz } };
                tlv_pos_ += length;
                return opt;
            }

            // appends one option TLV to load_: type(1B) | length(1B, includes header) | value
            // length is computed as 2 + value_size — caller passes only the value bytes.
            // returns false if value_size + 2 would overflow a uint8_t length field
            // (max option size is 255 bytes) or if reallocation fails.
            //
            // usage:
            //   LCP lcp(PPP_CODE_CONF_REQ, 1);
            //   const uint8_t mru_val[] = { 0x05, 0xDC };  // 1500
            //   lcp.add_option(LCP_OPT_MRU, mru_val, 2);

            bool base_add_option(uint8_t type, const uint8_t* value, uint8_t value_size,
                     const_view_t& load_, Buffer& load_buf_) noexcept {
                // TYPE:1 | OPT_LEN:1 | VALUE:value_size*
                // length byte covers the full option including the 2-byte header.
                uint32_t opt_len = 2u + value_size;
                if (opt_len > 0xFF) return false;

                uint32_t existing = static_cast<uint32_t>(load_.size());

                // ── ownership check ───────────────────────────────────────────────────
                // load_ is "owned" when it points into load_buf_ — i.e. load_buf_ is
                // valid and load_.data() == load_buf_.begin(). in that case the backing
                // storage is exclusively ours and we can reallocate it freely.
                //
                // load_ is "borrowed" when it is a zero-copy view into the capture slab
                // (the recv loop's buffer). we must NOT free or overwrite those bytes —
                // they are owned by the capture loop and may be shared with sibling
                // layers (e.g. Ether.load_, IP.load_, TCP.load_ all view the same slab).
                // when we grow, we copy the borrowed bytes into the new owned buffer,
                // then let the slab remain untouched for the capture loop to reuse.
                //
                // NOTE: if load_ was owned (pointed into a previous load_buf_), the old
                // load_buf_ is released when we move-assign the fresh buffer below —
                // those bytes are freed. if load_ was borrowed, the slab bytes are NOT
                // freed here — their lifetime is controlled entirely by the capture loop.

                bool already_owned = load_buf_.ok()
                                && !load_.empty()
                                && load_.data() == load_buf_.begin();

                uint32_t current_cap = load_buf_.ok() ? load_buf_.cap() : 0;
                uint32_t needed      = existing + opt_len;

                if (!already_owned || needed > current_cap) {
                    // allocate exactly what we need — no speculative headroom.
                    // the next add_option call will allocate again if needed; callers
                    // who know option counts upfront should pre-size with reserve().
                    Buffer fresh = Buffer::alloc(needed);
                    if (!fresh.ok()) return false;

                    if (existing)
                        fresh.write(load_.data(), existing);

                    // old load_buf_ (if owned) is released here by move-assignment.
                    // borrowed slab bytes are unaffected — the slab pointer is not freed.
                    load_buf_ = std::move(fresh);
                }

                uint8_t hdr[2] = { type, static_cast<uint8_t>(opt_len) };
                load_buf_.write(hdr, 2);
                if (value_size)
                    load_buf_.write(value, value_size);

                load_ = { load_buf_.begin(), load_buf_.len() };
                return true;
            }

    };
} // namespace lynx::proto

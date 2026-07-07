#pragma once

//  CHAP — Challenge Handshake Authentication Protocol (PPP_PROTO_CHAP = 0xC223)
//
//  three-way handshake: authenticator sends Challenge, peer responds with
//  Response (MD5 hash of id + secret + challenge value), authenticator
//  verifies and sends Success or Failure.
//
//  the hash value in CHALLENGE and RESPONSE is preceded by a value-size
//  byte. the hash length depends on the algorithm: 16 bytes for MD5.
//
//  dissection:
//    auto chap = ppp->as<CHAP>();   // when ppp->hdr()->is_chap()
//    if (chap->hdr()->code == CHAP_CODE_CHALLENGE) {
//        // load() layout: value-size(1B) | hash-value | name
//    }
//
//  crafting (challenge):
//    uint8_t body[1 + 16 + name_len];
//    body[0] = 16;  // MD5 hash length
//    __builtin_memcpy(body + 1, challenge_hash, 16);
//    __builtin_memcpy(body + 17, name, name_len);
//    CHAP chap(CHAP_CODE_CHALLENGE, 1);
//    chap / Raw(body, sizeof(body));

#include "protocols/l2/ppp/tlv_base.hpp"

namespace lynx::proto
{
    class CHAP LYNX_INHERITANCE_POLICY : public ProtocolBaseObject {
        public:

            CHAP() noexcept {
                hdr_.code   = constants::CHAP_CODE_CHALLENGE;
                hdr_.id     = 0;
                hdr_.length = 0;
            }

            CHAP(uint8_t code, uint8_t id) noexcept {
                hdr_.code   = code;
                hdr_.id     = id;
                hdr_.length = 0;
            }

            explicit CHAP(const hdrs::HdrCHAP& h) noexcept : hdr_(h) {}
            ~CHAP() = default;

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrCHAP wire = hdr_;
                wire.length = swap16(static_cast<uint16_t>(hdr_size() + load_.size()));
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrCHAP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrCHAP)) {
                    set_error(Status::MalformedPacket, "CHAP header too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrCHAP));
                hdr_.length = swap16(hdr_.length);

                uint32_t payload_len =
                    hdr_.length - static_cast<uint32_t>(sizeof(hdrs::HdrCHAP));
                if (payload_len > len - sizeof(hdrs::HdrCHAP))
                    payload_len = len - sizeof(hdrs::HdrCHAP);

                load_ = { data + sizeof(hdrs::HdrCHAP), payload_len };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrCHAP));
            }

            [[nodiscard]] hdrs::HdrCHAP* hdr() noexcept override { return &hdr_; }

            void patch_checksum() noexcept override {}

            bool is_challenge() const noexcept { return hdr_.code == constants::CHAP_CODE_CHALLENGE; }

            bool is_response() const noexcept { return hdr_.code == constants::CHAP_CODE_RESPONSE; }

            bool is_success() const noexcept { return hdr_.code == constants::CHAP_CODE_SUCCESS; }

            bool is_failure() const noexcept { return hdr_.code == constants::CHAP_CODE_FAILURE; }

            [[nodiscard]] hdrs::CHAPChallengeResponse get_challenge_response() const noexcept {
                // if load_ is empty, too short, or packet is neither challenge nor response
                if (!(is_challenge() || is_response()) || load_.size() < 1)
                    return {};

                uint8_t value_size = load_[0];  // value size is the first byte

                if (load_.size() < 1 + value_size) return {};  // not enough data for value + name

                const_view_t value{ load_.data() + 1, value_size };
                const_view_t name { load_.data() + 1 + value_size,  // BASE + value_size
                                               load_.size() - 1 - value_size };
                return { value, name };
            }

            [[nodiscard]] const_view_t get_message() const noexcept {
                if (!is_success() && !is_failure()) return {};

                // for SUCCESS / FAILURE, the entire load is a message string
                return load_;
            }

            void set_challenge_response(
                const uint8_t* value, uint8_t value_size,
                const uint8_t* name,  uint32_t name_size
            ) {
                if (!(is_challenge() || is_response())) { 
                    set_error(Status::InvalidState, "CHAP: packet is not challenge or response");
                    return;
                }

                // structure it and through it to dumb set_message
                uint32_t total = 1u + value_size + name_size;

                uint8_t tmp[total];
                tmp[0] = value_size;

                if (value_size) {
                    memory_copy(tmp + 1, value, value_size);
                }

                if (name_size) {
                    memory_copy(tmp + 1 + value_size, name, name_size);
                }

                set_message(tmp, total);
            }

            void set_message(const uint8_t* message, uint32_t size) {
                if (!is_success() && !is_failure()) { 
                    set_error(Status::InvalidState, "CHAP: packet is not success or failure");
                    return;
                }

                // dont re-allocate only if Buffer is OK and same size 
                if (!load_buf_.ok() || load_buf_.cap() != size) {
                    
                    // 1. allocate new
                    Buffer fresh = Buffer::alloc(size);
                        
                    if (!fresh.ok()) {
                        set_error(Status::BufferAllocFail, "CHAP: alloc failed");
                        return;
                    }
                        
                    load_buf_ = std::move(fresh);
                } 
                else {
                    load_buf_.reset();   // same backing storage, length cursor rewound to 0
                }

                if (size) {
                    load_buf_.write(message, size);
                }

                load_ = { load_buf_.begin(), load_buf_.len() };
            }

        protected:
            hdrs::HdrCHAP hdr_{};
        };
} // namespace lynx::proto

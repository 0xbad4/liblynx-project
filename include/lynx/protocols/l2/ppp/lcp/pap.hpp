#pragma once

//  PAP — Password Authentication Protocol (PPP_PROTO_PAP = 0xC023)
//
//  plaintext authentication — credentials are sent in the clear.
//  superseded by CHAP and EAP in modern deployments but still common in
//  legacy ISP and DSL environments.
//
//  dissection:
//    auto pap = ppp->as<PAP>();   // when ppp->hdr()->is_pap()
//    if (pap->hdr()->code == PAP_CODE_AUTH_REQ) {
//        // peer-id and password are in pap->load() as raw bytes:
//        // peer-id-length(1B) | peer-id | passwd-length(1B) | passwd
//    }
//
//  crafting:
//    // authenticate-request body: id-len(1B) | id | pw-len(1B) | pw
//    const uint8_t user[] = "admin";
//    const uint8_t pass[] = "secret";
//    uint8_t body[1 + sizeof(user)-1 + 1 + sizeof(pass)-1];
//    body[0] = sizeof(user) - 1;
//    __builtin_memcpy(body + 1, user, sizeof(user)-1);
//    body[sizeof(user)] = sizeof(pass) - 1;
//    __builtin_memcpy(body + sizeof(user) + 1, pass, sizeof(pass)-1);
//    PAP pap(PAP_CODE_AUTH_REQ, 1);
//    pap / Raw(body, sizeof(body));


#include "lynx/protocols/l2/frame.hpp"
#include "lynx/protocols/l2/ppp/hdrs.hpp"


namespace lynx::proto
{
    
    class PAP LYNX_INHERITANCE_POLICY : public ProtocolBaseObject {
        public:

            PAP() noexcept {
                hdr_.code   = constants::PAP_CODE_AUTH_REQ;
                hdr_.id     = 0;
                hdr_.length = 0;
            }

            PAP(uint8_t code, uint8_t id) noexcept {
                hdr_.code   = code;
                hdr_.id     = id;
                hdr_.length = 0;
            }

            explicit PAP(const hdrs::HdrPAP& h) noexcept : hdr_(h) {}
            ~PAP() = default;

            void serialize(Buffer& buf) const noexcept override
            {
                hdrs::HdrPAP wire = hdr_;
                wire.length = swap16(static_cast<uint16_t>(hdr_size() + load_.size()));
                buf.write(reinterpret_cast<const uint8_t*>(&wire), sizeof(hdrs::HdrPAP));
                if (!load_.empty())
                    buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
            }

            void dissect(const uint8_t* data, uint32_t len) noexcept override
            {
                if (!data || len < sizeof(hdrs::HdrPAP)) {
                    set_error(Status::MalformedPacket, "PAP header too short");
                    return;
                }

                memory_copy(&hdr_, data, sizeof(hdrs::HdrPAP));
                hdr_.length = swap16(hdr_.length);

                uint32_t payload_len =
                    hdr_.length - static_cast<uint32_t>(sizeof(hdrs::HdrPAP));
                if (payload_len > len - sizeof(hdrs::HdrPAP))
                    payload_len = len - sizeof(hdrs::HdrPAP);

                load_ = { data + sizeof(hdrs::HdrPAP), payload_len };
            }

            [[nodiscard]] uint32_t hdr_size() const noexcept override {
                return static_cast<uint32_t>(sizeof(hdrs::HdrPAP));
            }

            [[nodiscard]] hdrs::HdrPAP* hdr() noexcept override { return &hdr_; }

            void patch_checksum() noexcept override {}

            bool is_auth_request() const noexcept { return hdr_.code == constants::PAP_CODE_AUTH_REQ; }
            bool is_auth_response()   const noexcept { return hdr_.code == constants::PAP_CODE_AUTH_ACK || hdr_.code == constants::PAP_CODE_AUTH_NAK; }

            [[nodiscard]] hdrs::PAPAuthRequest get_auth_req_creds() const noexcept {
                // if load_ is empty, too short or not authenticaton request, return empty spans
                if (!is_auth_request() || load_.size() < 1) return {};

                const uint8_t* p = load_.data();

                // peer id
                uint8_t peer_id_len = p[0];
                const_view_t peer_id{};

                if (1 + peer_id_len < load_.size()) {
                    peer_id = { p + 1, peer_id_len };
                }
                else {
                    return {};
                }

                // advance past peer id
                p += 1 + peer_id_len;

                // check if there are enough bytes to feed passwd length
                if (p - load_.data() >= load_.size()) return {};

                // password
                uint8_t passwd_len = p[0];
                const_view_t passwd{};

                if (1 + passwd_len <= load_.data() + load_.size() - p) {
                    passwd = { p + 1, passwd_len };
                }
                else {
                    return {};
                }

                return { peer_id, passwd };
            };

            [[nodiscard]] const_view_t get_auth_response_msg() const noexcept {
                // for ACK/NAK, the entire load is a message string
                if (!is_auth_response()) return {};
                return load_;
            }

            void set_auth_req_creds(
                const uint8_t* peer_id, uint8_t peer_id_size,
                const uint8_t* password,  uint32_t password_len
            ) {

                if (!is_auth_request() || !is_auth_response()) {
                    return;
                }

                uint32_t total = 2u + peer_id_size + password_len;

                uint8_t tmp[total];
                tmp[0] = peer_id_size;

                if (peer_id_size) {
                    memory_copy(tmp + 1, peer_id, peer_id_size);
                }

                tmp[peer_id_size + 1] = password_len;

                if (password_len) {
                    memory_copy(tmp + 1 + peer_id_size + 1, password, password_len);
                }

                set_message(tmp, total);
                
            }

            void set_auth_response_msg(const uint8_t* msg, uint8_t msg_len) noexcept {
                set_message(msg, msg_len);
            }

        protected:
            hdrs::HdrPAP hdr_{};

            void set_message(const uint8_t* message, uint32_t size) {
                // dont re-allocate only if Buffer is OK and same size 
                if (!load_buf_.ok() || load_buf_.cap() != size) {
                    
                    // 1. allocate new
                    Buffer fresh = Buffer::alloc(size);
                        
                    if (!fresh.ok()) {
                        set_error(Status::BufferAllocFail, "PAP: alloc failed");
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

        };

} // namespace lynx::proto

#pragma once

#include "lynx/core/base.hpp"
#include "lynx/core/proto_base.hpp"

namespace lynx::proto {
    class Raw LYNX_INHERITANCE_POLICY : public ProtocolBaseObject {
    public:

        Raw() = default;

        // construct directly from bytes — crafting path
        Raw(const uint8_t* data, uint32_t len) noexcept {
            set_load({ data, len });
        }

        explicit Raw(std::span<const uint8_t> data) noexcept {
            set_load(data);
        }

        ~Raw() = default;

        void serialize(Buffer& buf) const noexcept override {
            if (!load_.empty())
                buf.write(load_.data(), static_cast<uint32_t>(load_.size()));
        }

        void dissect(const uint8_t* data, uint32_t len) noexcept override {
            if (!data || len == 0) return;
            load_ = { data, len };
        }

        [[nodiscard]] uint32_t hdr_size() const noexcept override { return 0; }

        [[nodiscard]] void* hdr() noexcept override { return nullptr; }
    };
} // namespace lynx::proto
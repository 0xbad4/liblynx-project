#pragma once

#include "core/base.hpp"
#include "core/proto_base.hpp"

namespace lynx::proto {
    class Raw LYNX_INHERITANCE_POLICY : public ProtocolBaseObject {
    public:

        Raw() = default;

        // construct directly from bytes — crafting path
        Raw(const uint8_t* data, uint32_t len) noexcept {
            data_ = data;
            size_ = len;
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
            data_ = data;
            size_ = len;
            load_ = { data, len };
        }

        [[nodiscard]] uint32_t hdr_size() const noexcept override { return 0; }

        [[nodiscard]] void* hdr() noexcept override { return nullptr; }

        // safe read-only view of the raw bytes — no pointer arithmetic for callers
        const_view_t bytes() const noexcept {
            return {data_, size_};
        }

        // payload past a given offset
        const_view_t payload(size_t offset) const noexcept {
            if (offset >= size_) return {};
            return {data_ + offset, size_ - offset};
        }
        
    protected:
        const uint8_t* data_;
        size_t size_;
        
    };
} // namespace lynx::proto
#pragma once

//  Buffer — a ref-counted byte slab shared across protocol layers.
//
//  design rules:
//    - single allocation per packet — layers write into it at offsets,
//      never allocate their own copies
//    - shared_ptr<uint8_t[]> for shared ownership across layers
//    - BaseObject for error state — BufferTooSmall, BufferAllocFail
//    - two construction paths:
//        alloc()  — owns a fresh heap slab (crafting / send path)
//        wrap()   — view into an externally owned slab (recv path, zero-copy)

#include "base.hpp"

#include <cstdint>
#include <memory>       // std::shared_ptr — the one allowed STL component
#include <span>         // std::span       — zero-overhead non-owning view

namespace lynx {

class Buffer : public BaseObject {
    private:
        std::shared_ptr<uint8_t[]> data_;
        uint32_t offset_ = 0;      // byte offset within data_ where our view starts
        uint32_t len_    = 0;      // bytes written / valid
        uint32_t cap_    = 0;      // max bytes from offset_ (alloc size - offset_)
        
    public:

        // ── construction 

        Buffer() = default;

        // alloc() — heap-allocate a zeroed slab of `capacity` bytes.
        // use for packet crafting and send path.
        // on alloc failure, returned Buffer carries Status::BufferAllocFail.
        [[nodiscard]] static Buffer alloc(uint32_t capacity) noexcept {
            if (capacity == 0) {
                Buffer b;
                b.set_error(Status::InvalidArgument, "alloc capacity must be > 0");
                return b;
            }

            Buffer b;
            b.data_ = std::shared_ptr<uint8_t[]>(new (std::nothrow) uint8_t[capacity]{});
            
            if (!b.data_) {
                b.set_error(Status::BufferAllocFail, "Buffer::alloc() — new returned null");
                return b;
            }
            b.cap_ = capacity;
            b.len_ = 0;
            return b;
        }

        // wrap() — take shared ownership of an existing slab at a given offset.
        // use for zero-copy recv path: the recv slab is shared, each protocol
        // layer wraps a view into it at its own offset without copying.
        // `owner`  — the shared_ptr keeping the slab alive
        // `offset` — byte offset within owner where this buffer's data starts
        // `length` — number of valid bytes from offset
        [[nodiscard]] static Buffer wrap(std::shared_ptr<uint8_t[]> owner,
                                        uint32_t                   offset,
                                        uint32_t                   length) noexcept {
            Buffer b;
            b.data_   = std::move(owner);
            b.offset_ = offset;
            b.len_    = length;
            b.cap_    = length;   // wrap is read-only — cap == len, no room to grow
            return b;
        }

        // ── write (crafting path) 

        // append `n` bytes from `src` at the current write cursor (len_).
        // advances len_ by n on success.
        // sets BufferTooSmall if n would exceed cap_.
        bool write(const uint8_t* src, uint32_t n) noexcept {
            if (!src) {
                set_error(Status::InvalidArgument, "Buffer::write() — null src");
                return false;
            }
            if (len_ + n > cap_) {
                set_error(Status::BufferTooSmall,
                        "Buffer::write() — write would exceed capacity");
                return false;
            }
            __builtin_memcpy(data_.get() + offset_ + len_, src, n);
            len_ += n;
            return true;
        }

        // write a single byte at the current cursor.
        bool write_u8(uint8_t byte) noexcept {
            return write(&byte, 1);
        }

        // write a uint16 in network byte order (big-endian).
        bool write_u16be(uint16_t val) noexcept {
            uint8_t buf[2] = {
                static_cast<uint8_t>(val >> 8),
                static_cast<uint8_t>(val & 0xff)
            };
            return write(buf, 2);
        }

        // write a uint32 in network byte order (big-endian).
        bool write_u32be(uint32_t val) noexcept {
            uint8_t buf[4] = {
                static_cast<uint8_t>((val >> 24) & 0xff),
                static_cast<uint8_t>((val >> 16) & 0xff),
                static_cast<uint8_t>((val >>  8) & 0xff),
                static_cast<uint8_t>( val        & 0xff)
            };
            return write(buf, 4);
        }

        // reserve `n` bytes at current cursor without writing — returns pointer
        // to the reserved region so caller can write directly (e.g. for
        // __attribute__((packed)) struct overlay).
        // advances len_ by n. returns nullptr on overflow.
        [[nodiscard]] uint8_t* reserve(uint32_t n) noexcept {
            if (len_ + n > cap_) {
                set_error(Status::BufferTooSmall,
                        "Buffer::reserve() — reserve would exceed capacity");
                return nullptr;
            }
            uint8_t* ptr = data_.get() + offset_ + len_;
            len_ += n;
            return ptr;
        }

        // overwrite `n` bytes at absolute `pos` within the slab.
        // used for checksum patching after full serialization.
        // does not advance len_.
        bool patch(uint32_t pos, const uint8_t* src, uint32_t n) noexcept {
            if (!src) {
                set_error(Status::InvalidArgument, "Buffer::patch() — null src");
                return false;
            }
            if (pos + n > cap_) {
                set_error(Status::BufferTooSmall,
                        "Buffer::patch() — patch range exceeds capacity");
                return false;
            }
            __builtin_memcpy(data_.get() + offset_ + pos, src, n);
            return true;
        }

        // patch a uint16 in network byte order at absolute pos.
        // primary use: write computed checksum back into serialized header.
        bool patch_u16be(uint32_t pos, uint16_t val) noexcept {
            uint8_t buf[2] = {
                static_cast<uint8_t>(val >> 8),
                static_cast<uint8_t>(val & 0xff)
            };
            return patch(pos, buf, 2);
        }

        // ── read (dissection path) 

        // read `n` bytes from absolute `pos` into `dst`.
        bool read(uint32_t pos, uint8_t* dst, uint32_t n) const noexcept {
            if (!dst) {
                return false;
            }
            if (pos + n > len_) {
                return false;
            }
            __builtin_memcpy(dst, data_.get() + offset_ + pos, n);
            return true;
        }

        // read uint16 in network byte order from absolute pos.
        [[nodiscard]] uint16_t read_u16be(uint32_t pos) const noexcept {
            if (pos + 2 > len_) return 0;
            const uint8_t* p = data_.get() + offset_ + pos;
            return static_cast<uint16_t>((p[0] << 8) | p[1]);
        }

        // read uint32 in network byte order from absolute pos.
        [[nodiscard]] uint32_t read_u32be(uint32_t pos) const noexcept {
            if (pos + 4 > len_) return 0;
            const uint8_t* p = data_.get() + offset_ + pos;
            return (static_cast<uint32_t>(p[0]) << 24)
                | (static_cast<uint32_t>(p[1]) << 16)
                | (static_cast<uint32_t>(p[2]) <<  8)
                |  static_cast<uint32_t>(p[3]);
        }

        // ── views 

        // raw pointer to start of valid data (offset applied).
        [[nodiscard]] uint8_t*       begin()       noexcept { return data_.get() + offset_; }
        [[nodiscard]] const uint8_t* begin() const noexcept { return data_.get() + offset_; }

        // raw pointer past last valid byte.
        [[nodiscard]] uint8_t*       end()         noexcept { return data_.get() + offset_ + len_; }
        [[nodiscard]] const uint8_t* end()   const noexcept { return data_.get() + offset_ + len_; }

        // pointer at absolute offset `pos` within valid data — no bounds check.
        // caller is responsible for ensuring pos < len_.
        [[nodiscard]] uint8_t*       at(uint32_t pos)       noexcept { return data_.get() + offset_ + pos; }
        [[nodiscard]] const uint8_t* at(uint32_t pos) const noexcept { return data_.get() + offset_ + pos; }

        // std::span view of valid bytes — for passing to checksum, sendto, etc.
        [[nodiscard]] view_t       span()       noexcept { return { begin(), len_ }; }
        [[nodiscard]] const_view_t span() const noexcept { return { begin(), len_ }; }

        // sub-span from absolute `pos` for `n` bytes — used by dissector to
        // hand a layer view to the next protocol without copying.
        [[nodiscard]] const_view_t subspan(uint32_t pos,
                                                        uint32_t n) const noexcept {
            if (pos + n > len_) return {};
            return { begin() + pos, n };
        }

        // shared ownership handle — pass to wrap() for zero-copy layer views.
        [[nodiscard]] std::shared_ptr<uint8_t[]> owner() const noexcept { return data_; }

        // ── state

        [[nodiscard]] uint32_t len()      const noexcept { return len_; }
        [[nodiscard]] uint32_t cap()      const noexcept { return cap_; }
        [[nodiscard]] uint32_t offset()   const noexcept { return offset_; }
        [[nodiscard]] uint32_t remaining()const noexcept { return cap_ - len_; }
        [[nodiscard]] bool     empty()    const noexcept { return len_ == 0; }
        [[nodiscard]] bool     valid()    const noexcept { return data_ != nullptr; }

        // reset write cursor — does not zero memory, does not reallocate.
        void reset() noexcept { len_ = 0; }
    };
} // namespace lynx

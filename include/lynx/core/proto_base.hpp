#pragma once

#include "buffer.hpp"


// ── memory model: capture, edit, resend ─────────────────────────────────
//
// when a packet is captured, every dissected layer's load_ is a *borrowed*
// span into the single recv buffer owned by the capture loop (or by
// RawFrame, if you hold one). no bytes are copied at dissect time — this
// is what makes capture cheap regardless of how many layers you walk with
// as<T>(). it also means load_ is only valid for as long as that root
// buffer is alive, which in practice means: for the duration of the
// capture() callback that produced it.
//
// editing a layer (add_option(), set_message(), or any mutator)
// never writes through that borrowed view. instead it allocates a fresh,
// independently-owned buffer, writes the new content into it, and
// re-points this layer's load_ at the new buffer. the bytes the old
// load_ used to reference are left completely untouched in the original
// slab — they are not freed, not modified, not reused by this call.
// their lifetime is governed entirely by whoever owns that slab (the
// capture loop, typically), not by this object.
//
// this is a deliberate design choice, not an oversight. an in-place
// editable view would require every layer's bytes to live in disjoint,
// independently-sized regions, but they don't — Eth.load_, IP.load_, and
// TCP.load_ are all views over the *same* shared bytes at increasing
// offsets, not separate allocations. if you swap IPv4 for a
// differently-sized header (e.g. ARP, or IPv4 with options) and write
// the replacement through an in-place view, you silently overwrite
// whatever sits immediately after it in the slab — typically the next
// layer's header or payload — with no mechanism to detect or prevent it.
// allocating a new owned buffer on every edit removes this hazard
// entirely: a layer can never corrupt memory another layer believes it
// owns, regardless of how header sizes change across the edit.
//
// practical consequence — capture/edit/resend within one callback is
// always safe and requires no special handling:
//
//   iface.capture([&](const RawFrame& raw) {
//       auto chap = ppp->as<CHAP>();
//       chap->set_message(reply, reply_len);   // owned buffer, safe
//       iface.send(*chap);                      // slab still alive here
//       return RecvAction::Continue;
//   });
//
// if you need to retain a dissected object — or resend it — *outside*
// the callback that produced it, the root slab may already have been
// reused or freed by then, and any layer still borrowing from it (one
// you never called a mutator on) would read stale or invalid memory.
// call materialize() before storing the object anywhere longer-lived:
//
//   auto chap = ppp->as<CHAP>();
//   chap->materialize();      // copies load_ into owned storage now
//   stash_for_later(std::move(chap));
//
// materialize() is a cheap no-op if load_ is already owned (e.g. you
// already called a mutator on this object) — it only allocates when
// load_ is still a borrowed view.


namespace lynx
{
    //  ProtocolBaseObject
    //  root contract for all concrete protocol classes (L2 Frame subclasses,
    //  and future L3 / L4 classes).

    class ProtocolBaseObject : public BaseObject {
        public:
            virtual ~ProtocolBaseObject() = default;
        
            virtual void serialize(Buffer& buf)                     const noexcept = 0;
            virtual void dissect(const uint8_t* data, uint32_t len)       noexcept = 0;
        
            [[nodiscard]] uint32_t size()     const noexcept {
                return hdr_size() + static_cast<uint32_t>(load_.size());
            }

            [[nodiscard]] virtual uint32_t hdr_size() const noexcept = 0;
        
            // returns void* — mutable, subclasses covariant-return their HdrXxx*:
            //   HdrTcp* hdr() noexcept override { return &hdr_; }
            
            [[nodiscard]] virtual void* hdr() noexcept = 0;
        
            // payload

            [[nodiscard]] const_view_t load() const noexcept {
                return load_;
            }

            // promotes load_ from a borrowed view into owned storage.
            // call this if you need to keep this object, or resend it, beyond the
            // scope of the capture callback that produced it. cheap no-op if load_
            // is already owned (e.g. after add_option / set_message).
            void materialize() noexcept
            {
                if (load_.empty() || load_buf_.ok()) return;   // nothing to do, or already owned

                Buffer fresh = Buffer::alloc(static_cast<uint32_t>(load_.size()));
                
                if (!fresh.ok()) { 
                    set_error(Status::BufferAllocFail, "materialize failed"); 
                    return; 
                }
                fresh.write(load_.data(), static_cast<uint32_t>(load_.size()));
                load_buf_ = std::move(fresh);
                load_     = { load_buf_.begin(), load_buf_.len() };
            }

            void set_load(const_view_t payload) noexcept {
                if (payload.empty()) {
                        load_ = {};
                        return;
                    }

                    owned_load_ = std::shared_ptr<uint8_t[]>(
                        new (std::nothrow) uint8_t[payload.size()]{}
                    );
                    if (!owned_load_) {
                        set_error(Status::BufferAllocFail, "ProtoBase::set_load alloc failed");
                        return;
                    }

                    memory_copy(owned_load_.get(), payload.data(), payload.size());
                    load_ = { owned_load_.get(), payload.size() };
            }
        
            // allocates T, calls T::dissect(load()) — zero-copy span passed down.
            // returns nullptr if load empty, alloc fails, or dissect errors.
        
            template<typename T>
            [[nodiscard]] std::unique_ptr<T> as() const noexcept
            {
                static_assert(std::is_base_of_v<ProtocolBaseObject, T>,
                            "T must inherit from ProtocolBaseObject");
        
                auto payload = load();
                if (payload.empty()) return nullptr;
        
                std::unique_ptr<T> t(new (std::nothrow) T{});
                if (!t) return nullptr;
        
                t->dissect(payload.data(), static_cast<uint32_t>(payload.size()));

                return t;
            }
        
            // crafting path: eth / ip / tcp
            //   1. serialize rhs (which recursively includes rhs's own load) into
            //      a fresh Buffer of rhs.size() bytes
            //   2. store that Buffer as this layer's load via set_load()
            //   3. return *this so chaining works left-to-right
            // if a change made in upper layer it wont affect this load

            ProtocolBaseObject& operator/(ProtocolBaseObject& rhs) noexcept {
                Buffer buf = Buffer::alloc(rhs.size());

                if (!buf.ok()) {
                    set_error(Status::BufferAllocFail,
                            "operator/: failed to allocate rhs buffer");
                    return *this;
                }

                rhs.underlayer_ = this;      // rhs knows who is beneath it

                // patch checksum before serializing
                rhs.patch_checksum();
        
                rhs.serialize(buf);

                if (!buf.ok()) {
                    set_error(Status::SerializeFail,
                            "operator/: rhs serialize failed" );
                    return *this;
                }
        
                set_load({ buf.begin(), buf.len() });

                return *this;
            }

            // called after full serialization — buf contains the complete frame,
            // offset is the byte position of this layer's header within buf.
            // default no-op — layers that need no checksum (Ether, Dot1Q) skip override.
            virtual void patch_checksum() noexcept {}

            // swap
            [[nodiscard]] uint16_t swap16(uint16_t value) const noexcept {
                return utils::bswap(value);
            }

            [[nodiscard]] uint32_t swap32(uint32_t value) const noexcept {
                return utils::bswap(value);
            }

            [[nodiscard]] uint64_t swap64(uint64_t value) const noexcept {
                return utils::bswap(value);
            }

            void memory_copy(void* dst, const void* src, size_t size) const noexcept {
                utils::mcopy(dst, src, size);
            }

        protected:
            // set when capturing packets
            const_view_t   load_{};
            Buffer load_buf_;

            // set when crafting packets 
            std::shared_ptr<uint8_t[]> owned_load_;
            
            // underlayer access
            ProtocolBaseObject* underlayer_ = nullptr;
    };

} // namespace lynx

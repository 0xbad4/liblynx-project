#pragma once

#include "buffer.hpp"


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

                    __builtin_memcpy(owned_load_.get(), payload.data(), payload.size());
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
            //   3. return *this so chaining works left-to-rightw
            // if a change made in upper layer it wont afftect this load

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

        protected:
            // set when capturing packets
            const_view_t   load_{};
            // set when crafting packets 
            std::shared_ptr<uint8_t[]> owned_load_;
            // underlayer access
            ProtocolBaseObject* underlayer_ = nullptr;
    };

} // namespace lynx

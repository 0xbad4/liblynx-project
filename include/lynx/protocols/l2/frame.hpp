#pragma once

#include "lynx/core/base.hpp"
#include "lynx/core/proto_base.hpp"
#include "lynx/protocols/hdrs.hpp"

namespace lynx::proto
{

class Frame;

//  FrameType
enum class FrameType : uint8_t {
    Unknown = 0,
    Eth,        // standard Ethernet II
    Dot1Q,      // 802.1Q VLAN tagged (ethertype == 0x8100)
};
 

//  RawFrame
//  pure byte carrier + type classifier.
//  this is what Interface::recv() passes to the callback.

class RawFrame : public BaseObject {
    private:
        std::shared_ptr<uint8_t[]> slab_;
        uint32_t                   len_  = 0;
        FrameType                  type_ = FrameType::Unknown;

    public:
    
        RawFrame()  = default;
        ~RawFrame() = default;
    
        // called by recv loop — peeks ethertype only, no further parsing.
    
        void dissect(const uint8_t* data, uint32_t len) noexcept
        {
            // ALL IT SUPPORTS NOW IS ETHERNET, EXPAND IT AND: 
            // TODO: classify load type

            if (!data || len < constants::ETH_HDR_LEN) {
                set_error(Status::MalformedPacket, "raw frame too short");
                type_ = FrameType::Unknown;
                return;
            }
    
            // zero-copy: no-op deleter — recv loop owns the memory
            slab_ = std::shared_ptr<uint8_t[]>(
                const_cast<uint8_t*>(data),
                [](uint8_t*) {}
            );
            len_ = len;
    
            // peek ethertype at offset 12
            uint16_t et = static_cast<uint16_t>((data[12] << 8) | data[13]);
    
            switch (et) {
                case constants::ETH_TYPE_VLAN: type_ = FrameType::Dot1Q; break;
                default:                       type_ = FrameType::Eth;   break;
                // Dot11: determined by interface monitor mode flag — not ethertype (v1)
            }
        }
    
    
        [[nodiscard]] FrameType type() const noexcept { return type_; }

        // T must inherit Frame.
        // allocates T, calls T::dissect() on the raw slab — zero-copy.
        // returns nullptr if slab empty, alloc fails, or T::dissect() errors.
    
        template<typename T>
        [[nodiscard]] std::unique_ptr<T> as() const noexcept
        {
            static_assert(std::is_base_of_v<Frame, T>,
                        "T must inherit from Frame");
    
            if (!slab_ || len_ == 0) return nullptr;
    
            std::unique_ptr<T> t(new (std::nothrow) T{});
            if (!t) return nullptr;
    
            t->dissect(slab_.get(), len_);
            return t;
        }
    
        // direct access for logging, hex dump
    
        [[nodiscard]] const uint8_t*            data()  const noexcept { return slab_.get(); }
        [[nodiscard]] uint32_t                  len()   const noexcept { return len_; }
        [[nodiscard]] const_view_t  bytes() const noexcept {
            if (!slab_) return {};
            return { slab_.get(), len_ };
        }
};


//  Frame
//  base class for all L2 protocol implementations: Eth, Dot1Q, Dot11.
//  concrete subclasses define their own packed hdr_ struct and implement
//  all ProtocolBaseObject virtuals.
//
//  each subclass declares:
//    static constexpr FrameType frame_type = FrameType::Eth;
 
class Frame : public ProtocolBaseObject {
    public:
        virtual ~Frame() = default;
};


} // namespace lynx::proto

#pragma once


#include <span>
#include <memory>
#include <cerrno>
#include <cstring>
#include <cstdint>


namespace lynx
{
    #define capture_callback_t std::function<RecvAction(const proto::RawFrame&)>
    #define const_view_t std::span<const uint8_t>
    #define view_t std::span<uint8_t>
    #define LYNX_PACKED struct __attribute__((packed))

    // CRC-32c
    inline constexpr uint32_t CRC32C_POLY  = 0x1EDC6F41;
    inline constexpr uint32_t CRC32C_INIT  = 0xFFFFFFFF;

} // namespace lynx

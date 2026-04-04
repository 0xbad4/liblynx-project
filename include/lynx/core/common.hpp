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
} // namespace lynx

#pragma once

#include "common.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <cstring>

namespace lynx {

    struct hr_mac { char data[18]; };  // human readable mac
    struct mn_mac { uint8_t data[6]; };  // machine/numeric mac


    struct hr_ipv4 { char data[16]; };  // human readable mac
    struct mn_ipv4 { uint8_t data[4]; };  // machine/numeric mac


    struct hr_ipv6 { char data[40]; };
    struct mn_ipv6 { uint8_t data[16]; };

    namespace utils { 
        uint16_t inet_checksum(const uint8_t* data, size_t len) {
            uint32_t sum = 0;
            while (len > 1) {
                sum += static_cast<uint16_t>((data[0] << 8) | data[1]);
                data += 2;
                len  -= 2;
            }
            if (len)
                sum += static_cast<uint16_t>(data[0] << 8);

            while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

            return static_cast<uint16_t>(~sum);
        }

        [[nodiscard]] inline uint16_t inet_checksum(const_view_t data) noexcept {
            return inet_checksum(data.data(), static_cast<uint32_t>(data.size()));
        }
        
        // ── hex nibble lookup
        static constexpr uint8_t kHex[] = "0123456789abcdef";

        static constexpr uint8_t hex_val(uint8_t c) noexcept {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0xFF;
        }

        // ── MAC
        [[nodiscard]]
        inline hr_mac mac_encode(const uint8_t mac[6]) noexcept {
            hr_mac result{};
            for (int i = 0; i < 6; ++i) {
                const uint8_t b = mac[i];
                result.data[i * 3 + 0] = kHex[b >> 4];
                result.data[i * 3 + 1] = kHex[b & 0x0F];
                result.data[i * 3 + 2] = (i != 5) ? ':' : '\0';
            }
            return result;
        }

        [[nodiscard]]
        inline mn_mac mac_decode(const char* s) noexcept {
            mn_mac result{};
            if (!s) return result;
            for (int i = 0; i < 6; ++i) {
                const uint8_t hi = hex_val(s[0]);
                const uint8_t lo = hex_val(s[1]);
                if (hi == 0xFF || lo == 0xFF) return mn_mac{};
                result.data[i] = static_cast<uint8_t>((hi << 4) | lo);
                s += 2;
                if (i != 5) {
                    if (*s != ':' && *s != '-') return mn_mac{};
                    ++s;
                }
            }
            if (*s != '\0') return mn_mac{};
            return result;
        }

        // ── IPv4 
        [[nodiscard]]
        inline hr_ipv4 ipv4_encode(const uint8_t ip[4]) noexcept {
            hr_ipv4 result{};
            int pos = 0;
            for (int i = 0; i < 4; ++i) {
                const uint8_t b = ip[i];
                if (b >= 100) {
                    result.data[pos++] = '0' + b / 100;
                    result.data[pos++] = '0' + (b / 10) % 10;
                    result.data[pos++] = '0' + b % 10;
                } else if (b >= 10) {
                    result.data[pos++] = '0' + b / 10;
                    result.data[pos++] = '0' + b % 10;
                } else {
                    result.data[pos++] = '0' + b;
                }
                result.data[pos++] = (i != 3) ? '.' : '\0';
            }
            return result;
        }

        [[nodiscard]]
        inline mn_ipv4 ipv4_decode(const char* s) noexcept {
            mn_ipv4 result{};
            if (!s) return result;
            for (int i = 0; i < 4; ++i) {
                if (*s < '0' || *s > '9') return mn_ipv4{};
                uint32_t val    = 0;
                int      digits = 0;
                while (*s >= '0' && *s <= '9') {
                    val = val * 10 + static_cast<uint32_t>(*s++ - '0');
                    if (++digits > 3 || val > 255) return mn_ipv4{};
                }
                result.data[i] = static_cast<uint8_t>(val);
                if (i != 3) {
                    if (*s != '.') return mn_ipv4{};
                    ++s;
                }
            }
            if (*s != '\0') return mn_ipv4{};
            return result;
        }

        // -- IPv6
        [[nodiscard]]
        inline hr_ipv6 ipv6_encode(const uint8_t ip[16]) noexcept {
            hr_ipv6 result{};
            for (int i = 0; i < 8; ++i) {
                const uint16_t word = (static_cast<uint16_t>(ip[i * 2]) << 8) | ip[i * 2 + 1];
                result.data[i * 5 + 0] = kHex[(word >> 12) & 0x0F];
                result.data[i * 5 + 1] = kHex[(word >> 8) & 0x0F];
                result.data[i * 5 + 2] = kHex[(word >> 4) & 0x0F];
                result.data[i * 5 + 3] = kHex[word & 0x0F];
                result.data[i * 5 + 4] = (i != 7) ? ':' : '\0';
            }
            return result;
        }

        [[nodiscard]]
        inline mn_ipv6 ipv6_decode(const char* s) noexcept {
            mn_ipv6 result{};
            if (!s) return result;
            for (int i = 0; i < 8; ++i) {
                uint16_t val    = 0;
                int      digits = 0;
                while ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')) {
                    const uint8_t nib = hex_val(static_cast<uint8_t>(*s++));
                    if (nib == 0xFF) return mn_ipv6{};
                    val = (val << 4) | nib;
                    if (++digits > 4) return mn_ipv6{};
                }
                result.data[i * 2]     = static_cast<uint8_t>(val >> 8);
                result.data[i * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
                if (i != 7) {
                    if (*s != ':') return mn_ipv6{};
                    ++s;
                }
            }
            if (*s != '\0') return mn_ipv6{};
            return result;
        }

        [[nodiscard]]
        inline mn_ipv6 ipv6_from_mac(const uint8_t mac[6]) noexcept {
            mn_ipv6 result{};
            
            result.data[0] = mac[0] ^ 0x02;
            result.data[1] = mac[1];
            result.data[2] = mac[2];
            result.data[3] = 0xFF;
            result.data[4] = 0xFE;
            result.data[5] = mac[3];
            result.data[6] = mac[4];
            result.data[7] = mac[5];
            std::memset(result.data, 0, 8);
            return result;
        }

        // ── Randomization
        [[nodiscard]]
        inline std::span<uint8_t> buf_randomize(uint8_t* buf, size_t len) noexcept {
            for (size_t i = 0; i < len; ++i) {
                buf[i] = static_cast<uint8_t>(std::rand() % 256);
            }
            return std::span<uint8_t>(buf, len);
        }

    }
} // namespace lynx::utils

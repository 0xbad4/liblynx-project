#pragma once

#include "common.hpp"
#include <cstdint>
#include <cstddef>
#include <span>

namespace lynx::utils
{ 
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

    // Returns 0-15 for valid hex uint8_t, 0xFF for invalid
    static constexpr uint8_t hex_val(uint8_t c) noexcept {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        return 0xFF;
    }

    // ── MAC

    /// Encodes 6 raw MAC bytes → "xx:xx:xx:xx:xx:xx\0"
    inline void mac_encode(const uint8_t mac[6], char out[18]) noexcept {
        for (int i = 0; i < 6; ++i) {
            const uint8_t b = mac[i];
            out[i * 3 + 0] = kHex[b >> 4];
            out[i * 3 + 1] = kHex[b & 0x0F];
            out[i * 3 + 2] = (i != 5) ? ':' : '\0';
        }
    }

    /// Decodes "xx:xx:xx:xx:xx:xx" or "xx-xx-xx-xx-xx-xx" (case-insensitive).
    /// Returns true on success, false if malformed.
    [[nodiscard]]
    inline bool mac_decode(const char* s, uint8_t mac[6]) noexcept {
        if (!s) return false;
        for (int i = 0; i < 6; ++i) {
            const uint8_t hi = hex_val(s[0]);
            const uint8_t lo = hex_val(s[1]);
            if (hi == 0xFF || lo == 0xFF) return false;
            mac[i] = static_cast<uint8_t>((hi << 4) | lo);
            s += 2;
            if (i != 5) {
                if (*s != ':' && *s != '-') return false;
                ++s;
            }
        }
        return *s == '\0';
    }

    // ── IPv4 

    /// Encodes 4 raw IPv4 bytes → "ddd.ddd.ddd.ddd\0"
    inline void ipv4_encode(const uint8_t ip[4], char out[16]) noexcept {
        int pos = 0;
        for (int i = 0; i < 4; ++i) {
            const uint8_t b = ip[i];
            if (b >= 100) {
                out[pos++] = '0' + b / 100;
                out[pos++] = '0' + (b / 10) % 10;
                out[pos++] = '0' + b % 10;
            } else if (b >= 10) {
                out[pos++] = '0' + b / 10;
                out[pos++] = '0' + b % 10;
            } else {
                out[pos++] = '0' + b;
            }
            out[pos++] = (i != 3) ? '.' : '\0';
        }
    }

    /// Decodes "ddd.ddd.ddd.ddd" → 4 raw IPv4 bytes.
    /// Returns true on success, false if malformed.
    [[nodiscard]]
    inline bool ipv4_decode(const char* s, uint8_t ip[4]) noexcept {
        if (!s) return false;
        for (int i = 0; i < 4; ++i) {
            if (*s < '0' || *s > '9') return false;
            uint32_t val    = 0;
            int      digits = 0;
            while (*s >= '0' && *s <= '9') {
                val = val * 10 + static_cast<uint32_t>(*s++ - '0');
                if (++digits > 3 || val > 255) return false;
            }
            ip[i] = static_cast<uint8_t>(val);
            if (i != 3) {
                if (*s != '.') return false;
                ++s;
            }
        }
        return *s == '\0';
    }

    // -- IPv6
    /// Encodes 16 raw IPv6 bytes → "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx\0"
    inline void ipv6_encode(const uint8_t ip[16], char out[40]) noexcept {
        for (int i = 0; i < 8; ++i) {
            const uint16_t word = (static_cast<uint16_t>(ip[i * 2]) << 8) | ip[i * 2 + 1];
            out[i * 5 + 0] = kHex[(word >> 12) & 0x0F];
            out[i * 5 + 1] = kHex[(word >> 8) & 0x0F];
            out[i * 5 + 2] = kHex[(word >> 4) & 0x0F];
            out[i * 5 + 3] = kHex[word & 0x0F];
            out[i * 5 + 4] = (i != 7) ? ':' : '\0';
        }
    }

    /// Decodes "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx" → 16 raw IPv6 bytes.
    /// Returns true on success, false if malformed.
    [[nodiscard]]
    inline bool ipv6_decode(const char* s, uint8_t ip[16]) noexcept {
        if (!s) return false;
        for (int i = 0; i < 8; ++i) {
            uint16_t val    = 0;
            int      digits = 0;
            while ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')) {
                const uint8_t nib = hex_val(static_cast<uint8_t>(*s++));
                if (nib == 0xFF) return false;
                val = (val << 4) | nib;
                if (++digits > 4) return false;
            }
            ip[i * 2]     = static_cast<uint8_t>(val >> 8);
            ip[i * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
            if (i != 7) {
                if (*s != ':') return false;
                ++s;
            }
        }
        return *s == '\0';
    }

    // Build IPv6 from MAC (EUI-64 format)
    inline void ipv6_from_mac(const uint8_t mac[6], uint8_t ipv6[16]) noexcept {
        // EUI-64 format: https://en.wikipedia.org/wiki/IPv6_address#Modified_EUI-64
        ipv6[0]  = mac[0] ^ 0x02;  // Flip the Universal/Local bit
        ipv6[1]  = mac[1];
        ipv6[2]  = mac[2];
        ipv6[3]  = 0xFF;
        ipv6[4]  = 0xFE;
        ipv6[5]  = mac[3];
        ipv6[6]  = mac[4];
        ipv6[7]  = mac[5];
        // The first 8 bytes (network prefix) can be set to zero or a specific value as needed. Here we zero them out.
        std::memset(ipv6, 0, 8);
    }

    // ── Randomization
    /// Fills `buf` with `len` random bytes using `std::rand()`.
    inline void buf_randomize(uint8_t* buf, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            buf[i] = static_cast<uint8_t>(std::rand() % 256);
        }
    }

} // namespace lynx::utils

#pragma once
// Lenient base64 / base64url codec: decoding ignores whitespace and missing
// padding (matches Node's Buffer.from); the url alphabet uses -_ without padding.
//
// Structure: a shared core (b64::encode/b64::decode taking alpha / rev
// tables); the class template Base64T<Url> generates both alphabets at
// compile time, and its encode/decode are thin dispatchers.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace b64 {

// ---- shared core ----

// alpha points to 65 bytes: 64 alphabet chars; alpha[64] is the pad char,
// '\0' meaning "no padding"
inline std::string encode(std::string_view in, const char* alpha) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    uint32_t buf = 0;
    unsigned bits = 0;
    for (char c : in) {
        buf = (buf << 8U) | (uint32_t)(unsigned char)c;
        bits += 8;
        while (bits >= 6) { // one 8-bit accumulation can cross two 6-bit boundaries
            bits -= 6;
            out.push_back(alpha[(buf >> bits) & 0x3fU]);
        }
    }
    if (bits > 0)
        out.push_back(alpha[(buf << (6U - bits)) & 0x3fU]);
    if (alpha[64]) // pad only when a pad char is configured
        while (out.size() % 4 != 0)
            out.push_back(alpha[64]);
    return out;
}

// rev is a 256-entry reverse table (0-63 legal, 0xFF illegal); returns
// nullopt on illegal input. Trailing bits are not validated (matches the
// lenient behavior of Node's Buffer.from)
inline std::optional<std::string> decode(std::string_view in, const std::array<unsigned char, 256>& rev) {
    std::string out;
    out.reserve(in.size() / 4 * 3);
    uint32_t buf = 0;
    unsigned bits = 0;
    for (char c : in) {
        auto uc = (unsigned char)c;
        if (uc == ' ' || uc == '\t' || uc == '\r' || uc == '\n') continue; // skip whitespace
        if (c == '=') continue;                                             // skip padding
        unsigned char v = rev[uc];
        if (v > 63) return std::nullopt;
        buf = (buf << 6U) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((buf >> bits) & 0xffU));
        }
    }
    return out;
}

// ---- class template: compile-time alpha / rev generation ----

// Url=false: standard A-Za-z0-9+/ with '=' padding; true: base64url (-_, unpadded)
template <bool Url>
class Base64T {
    static constexpr auto makeAlpha() {
        std::array<char, 65> a{};
        for (int i = 0; i < 26; ++i) a[i] = char('A' + i);
        for (int i = 0; i < 26; ++i) a[26 + i] = char('a' + i);
        for (int i = 0; i < 10; ++i) a[52 + i] = char('0' + i);
        a[62] = Url ? '-' : '+';
        a[63] = Url ? '_' : '/';
        a[64] = Url ? '\0' : '=';
        return a;
    }
    static constexpr auto alpha = makeAlpha();

    static constexpr auto makeRev() {
        std::array<unsigned char, 256> t{};
        t.fill(0xff); // fill is constexpr since C++20
        for (int i = 0; i < 64; ++i)
            t[(unsigned char)alpha[i]] = (unsigned char)i;
        return t;
    }
    static constexpr auto rev = makeRev();

public:
    static std::string encode(std::string_view in) { return b64::encode(in, alpha.data()); }
    static std::optional<std::string> decode(std::string_view in) { return b64::decode(in, rev); }
};

using Base64Std = Base64T<false>; // standard base64 (+/, '=' padding)
using Base64Url = Base64T<true>;  // base64url (-_, no padding)

} // namespace b64

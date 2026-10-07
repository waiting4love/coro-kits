// b64 codec unit tests: RFC 4648 vectors plus the project-specific semantics
// (url alphabet without padding, lenient decoding)

#include <string>

#include <gtest/gtest.h>

#include "b64.hpp"

TEST(B64Std, RFC4648Vectors) {
    EXPECT_EQ(b64::Base64Std::encode(""), "");
    EXPECT_EQ(b64::Base64Std::encode("f"), "Zg==");
    EXPECT_EQ(b64::Base64Std::encode("fo"), "Zm8=");
    EXPECT_EQ(b64::Base64Std::encode("foo"), "Zm9v");
    EXPECT_EQ(b64::Base64Std::encode("foob"), "Zm9vYg==");
    EXPECT_EQ(b64::Base64Std::encode("fooba"), "Zm9vYmE=");
    EXPECT_EQ(b64::Base64Std::encode("foobar"), "Zm9vYmFy");
}

TEST(B64Url, NoPaddingAndUrlAlphabet) {
    EXPECT_EQ(b64::Base64Url::encode("f"), "Zg"); // no padding
    EXPECT_EQ(b64::Base64Url::encode("foobar"), "Zm9vYmFy");
    // 0xFB 0xEF 0xBE -> all four 6-bit groups are 62 -> '+' in std, '-' in url
    std::string in = {static_cast<char>(0xfb), static_cast<char>(0xef), static_cast<char>(0xbe)};
    EXPECT_EQ(b64::Base64Std::encode(in), "++++");
    EXPECT_EQ(b64::Base64Url::encode(in), "----");
}

TEST(B64Decode, RoundtripAndTolerance) {
    EXPECT_EQ(b64::Base64Std::decode("Zm9vYmFy").value(), "foobar");
    EXPECT_EQ(b64::Base64Url::decode("Zm9vYmFy").value(), "foobar");
    // lenient decoding: whitespace and missing padding are ignored (matches
    // Node Buffer.from, see b64.hpp)
    EXPECT_EQ(b64::Base64Std::decode("Zm9vYmFy\n").value(), "foobar");
    EXPECT_EQ(b64::Base64Std::decode("Zg=").value(), "f");
    // illegal characters -> nullopt
    EXPECT_EQ(b64::Base64Std::decode("!!!"), std::nullopt);
    EXPECT_EQ(b64::Base64Url::decode("!!!!"), std::nullopt);
    // roundtrips across lengths (3k / 3k+1 / 3k+2)
    for (size_t n = 0; n <= 10; ++n) {
        std::string in(n, 'x');
        EXPECT_EQ(b64::Base64Url::decode(b64::Base64Url::encode(in)).value(), in) << "len=" << n;
        EXPECT_EQ(b64::Base64Std::decode(b64::Base64Std::encode(in)).value(), in) << "len=" << n;
    }
}

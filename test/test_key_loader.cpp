// Key loader unit tests (KEYS_DIR is injected by CMake; 1024-bit test-only keys)

#include <string>

#include <gtest/gtest.h>

#include "key_loader.hpp"

namespace {
const std::string& keysDir() {
    static const std::string dir = KEYS_DIR;
    return dir;
}
} // namespace

TEST(KeyLoader, LoadsBothKeysWithCorrectSize) {
    openssl::Key priv = loadPrivateEvpKeyFromXml(keysDir() + "/private-key.xml");
    openssl::Key pub = loadPublicEvpKeyFromXml(keysDir() + "/public-key.xml");
    ASSERT_NE(priv.handle(), nullptr);
    ASSERT_NE(pub.handle(), nullptr);
    EXPECT_EQ(priv.size(), 128); // 1024-bit = 128 bytes
    EXPECT_EQ(pub.size(), 128);
}

TEST(KeyLoader, PrivateLoadRejectsPublicKeyFile) {
    // a public-key XML lacks the private parameters (<D> &c.) -> load fails
    EXPECT_THROW(loadPrivateEvpKeyFromXml(keysDir() + "/public-key.xml"), std::runtime_error);
}

TEST(KeyLoader, MissingFileThrows) {
    EXPECT_THROW(loadPrivateEvpKeyFromXml(keysDir() + "/no-such-file.xml"), std::runtime_error);
    EXPECT_THROW(loadPublicEvpKeyFromXml(keysDir() + "/no-such-file.xml"), std::runtime_error);
}

TEST(KeyLoader, PublicLoadAcceptsPrivateKeyFile) {
    // public loading only needs <Modulus>/<Exponent>; a private XML is a superset
    EXPECT_NE(loadPublicEvpKeyFromXml(keysDir() + "/private-key.xml").handle(), nullptr);
}

// JWT RS256 verification unit tests: tokens are signed at run time with the
// test private key (test/keys/, test-only); covers the jsonwebtoken-aligned
// error taxonomy (JwtVerifyError::name, see the jwt.hpp header)

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

#include <boost/json.hpp>
#include <openssl/evp.h>

#include "b64.hpp"
#include "jwt.hpp"
#include "key_loader.hpp"

namespace json = boost::json;

namespace {

constexpr const char* kIssuer = "CAAP-Server";
constexpr const char* kAudience = "CAAP-Client";

// Independent signing oracle (deliberately bare EVP, kept as the documented
// exception): verifying our verifier against a second implementation
std::string signRs256(EVP_PKEY* key, const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    std::string sig(EVP_PKEY_size(key), '\0');
    size_t len = sig.size();
    int ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
             EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(sig.data()), &len,
                            reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("EVP_DigestSign failed");
    sig.resize(len);
    return sig;
}

int64_t epochNow() {
    return (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class JwtTest : public ::testing::Test {
protected:
    void SetUp() override {
        priv = loadPrivateEvpKeyFromXml(KEYS_DIR "/private-key.xml");
        pub = loadPublicEvpKeyFromXml(KEYS_DIR "/public-key.xml");
    }
    openssl::Key priv;
    openssl::Key pub;
};

} // namespace

TEST_F(JwtTest, ValidTokenReturnsPayload) {
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", kAudience}, {"name", "TESTUSER"},
                     {"exp", epochNow() + 3600}});
    auto po = verifyJwt(token, pub, kIssuer, kAudience);
    EXPECT_EQ(po.at("name").as_string(), "TESTUSER");
}

TEST_F(JwtTest, MissingExpiryIsAccepted) {
    // jsonwebtoken semantics: absent exp/nbf are not checked (jwt.cpp step 5)
    auto token = makeJwt(priv, json::object{{"iss", kIssuer}, {"aud", kAudience}});
    auto po = verifyJwt(token, pub, kIssuer, kAudience);
    EXPECT_EQ(po.at("iss").as_string(), kIssuer);
}

TEST_F(JwtTest, MalformedTokens) {
    const std::string tokens[] = {"", "abc", "a.b", "h.p."}; // 0/1/2 segments and an empty signature
    for (const auto& tok : tokens) {
        try {
            (void)verifyJwt(tok, pub, kIssuer, kAudience);
            FAIL() << "expected throw for: " << tok;
        } catch (const JwtVerifyError& e) {
            EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError") << tok;
        }
    }
}

TEST_F(JwtTest, InvalidBase64Segment) {
    auto token = makeJwt(priv, json::object{{"iss", kIssuer}, {"aud", kAudience}});
    token = token.substr(0, token.rfind('.') + 1) + "!!!"; // signature segment -> illegal base64url
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError");
    }
}

TEST_F(JwtTest, AlgorithmConfusionRejected) {
    // anything but RS256 (none/HS256/...) is rejected, preventing algorithm
    // confusion (jwt.cpp step 2). The attack-shaped token is hand-built:
    // an HS256 header signed with the RSA private key
    json::object header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";
    auto h = b64::Base64Url::encode(json::serialize(header));
    auto p = b64::Base64Url::encode(json::serialize(json::object{
        {"iss", kIssuer}, {"aud", kAudience}, {"exp", epochNow() + 3600}}));
    auto token = h + "." + p + "." +
                 b64::Base64Url::encode(signRs256(priv.handle(), h + "." + p));
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError");
        EXPECT_NE(std::string(e.what()).find("algorithm"), std::string::npos);
    }
}

TEST_F(JwtTest, TamperedSignatureRejected) {
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", kAudience}, {"exp", epochNow() + 3600}});
    token.back() = token.back() == 'A' ? 'B' : 'A'; // flip the last signature char
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError");
        EXPECT_NE(std::string(e.what()).find("signature"), std::string::npos);
    }
}

TEST_F(JwtTest, ExpiredToken) {
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", kAudience}, {"exp", epochNow() - 10}});
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "TokenExpiredError");
    }
}

TEST_F(JwtTest, NotBeforeToken) {
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", kAudience},
                     {"nbf", epochNow() + 3600}, {"exp", epochNow() + 7200}});
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "NotBeforeError");
    }
}

TEST_F(JwtTest, IssuerMismatch) {
    auto token = makeJwt(priv, json::object{
                     {"iss", "Other"}, {"aud", kAudience}, {"exp", epochNow() + 3600}});
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError");
        EXPECT_NE(std::string(e.what()).find("issuer"), std::string::npos);
    }
}

TEST_F(JwtTest, AudienceMismatch) {
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", "Other"}, {"exp", epochNow() + 3600}});
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError");
        EXPECT_NE(std::string(e.what()).find("audience"), std::string::npos);
    }
}

TEST_F(JwtTest, AudienceArrayContainsExpected) {
    // aud accepts an array of strings; containing the expected one passes
    // (jsonwebtoken parity)
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", json::array{"other", kAudience}},
                     {"exp", epochNow() + 3600}});
    auto po = verifyJwt(token, pub, kIssuer, kAudience);
    EXPECT_EQ(po.at("iss").as_string(), kIssuer);
}

TEST_F(JwtTest, InvalidExpValue) {
    auto token = makeJwt(priv, json::object{
                     {"iss", kIssuer}, {"aud", kAudience}, {"exp", "not-a-number"}});
    try {
        (void)verifyJwt(token, pub, kIssuer, kAudience);
        FAIL() << "expected throw";
    } catch (const JwtVerifyError& e) {
        EXPECT_STREQ(e.name.c_str(), "JsonWebTokenError");
        EXPECT_NE(std::string(e.what()).find("exp"), std::string::npos);
    }
}

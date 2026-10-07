#pragma once
// JWT RS256 verification (mirrors the semantics of Node jsonwebtoken.verify).
//
// Checked:
//   - alg must be RS256 (rejects none/HS256 etc., prevents algorithm confusion)
//   - RSASSA-PKCS1-v1_5 + SHA-256 signature
//   - issuer / audience match (aud accepts a string or an array of strings)
//   - exp / nbf validity (absent claims are not checked, like jsonwebtoken;
//     no clock-skew tolerance)
//
// Error names match jsonwebtoken: TokenExpiredError / NotBeforeError /
// JsonWebTokenError, ready for API response details.

#include <stdexcept>
#include <string>

#include <boost/json.hpp>

#include "key_loader.hpp" // brings in openssl.hpp (openssl::Key)

struct JwtVerifyError : std::runtime_error {
    std::string name; // TokenExpiredError / NotBeforeError / JsonWebTokenError
    JwtVerifyError(std::string name_, const std::string& msg)
        : std::runtime_error(msg), name(std::move(name_)) {}
};

// Returns the payload object on success; throws JwtVerifyError on failure
boost::json::object verifyJwt(const std::string& token, const openssl::Key& publicKey,
                              const std::string& issuer, const std::string& audience);

// Issues an RS256 JWT (fixed header {"alg":"RS256","typ":"JWT"}) for tests
// and tooling. The payload is serialized as-is; claims like exp/iss/aud are
// the caller's job. Throws std::runtime_error on signing failure
std::string makeJwt(const openssl::Key& privateKey, const boost::json::object& payload);

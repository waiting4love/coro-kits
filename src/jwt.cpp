#include "jwt.hpp"

#include <ctime>
#include <string>
#include <vector>

#include "b64.hpp"

namespace {

std::vector<std::string> splitDot(const std::string& s) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (c == '.') {
            parts.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(std::move(cur));
    return parts;
}

// JSON number -> int64 (integral doubles accepted too, matching
// Number.isInteger); non-numbers return nullopt
std::optional<int64_t> jsonToInt64(const boost::json::value& v) {
    namespace json = boost::json;
    if (v.is_int64()) return v.get_int64();
    if (v.is_uint64()) {
        auto u = v.get_uint64();
        if (u <= (uint64_t)INT64_MAX) return (int64_t)u;
        return std::nullopt;
    }
    if (v.is_double()) {
        double d = v.get_double();
        if (d == std::trunc(d) && d >= -9.007199254740992e15 && d <= 9.007199254740992e15)
            return (int64_t)d;
    }
    return std::nullopt;
}

} // namespace

namespace json = boost::json; // file-scope alias shared by verifyJwt/makeJwt

boost::json::object verifyJwt(const std::string& token, const openssl::Key& publicKey,
                              const std::string& issuer, const std::string& audience) {

    // 1) structure: header.payload.signature, all three segments non-empty (an empty signature is invalid)
    auto parts = splitDot(token);
    if (parts.size() != 3)
        throw JwtVerifyError("JsonWebTokenError", "jwt malformed");
    const auto& headerB64 = parts[0];
    const auto& payloadB64 = parts[1];
    const auto& sigB64 = parts[2];
    if (headerB64.empty() || payloadB64.empty() || sigB64.empty())
        throw JwtVerifyError("JsonWebTokenError", "jwt malformed");

    auto headerRaw = b64::Base64Url::decode(headerB64);
    auto payloadRaw = b64::Base64Url::decode(payloadB64);
    auto sig = b64::Base64Url::decode(sigB64);
    if (!headerRaw || !payloadRaw || !sig)
        throw JwtVerifyError("JsonWebTokenError", "invalid token");

    // 2) header: alg must be RS256
    boost::system::error_code ec;
    auto header = json::parse(*headerRaw, ec);
    if (ec || !header.is_object())
        throw JwtVerifyError("JsonWebTokenError", "invalid header");
    auto *algIt = header.as_object().find("alg");
    if (algIt == header.as_object().end() || !algIt->value().is_string() ||
        algIt->value().get_string() != "RS256")
        throw JwtVerifyError("JsonWebTokenError", "invalid algorithm");

    // 3) signature: RSASSA-PKCS1-v1_5(SHA-256) over the ASCII of "header.payload"
    const std::string signedData = headerB64 + "." + payloadB64;
    if (!openssl::verifyRsaSha256(publicKey, signedData, *sig))
        throw JwtVerifyError("JsonWebTokenError", "invalid signature");

    // 4) payload parse
    auto payload = json::parse(*payloadRaw, ec);
    if (ec || !payload.is_object())
        throw JwtVerifyError("JsonWebTokenError", "invalid payload");
    json::object po = payload.as_object();

    // 5) time claims (jsonwebtoken parity: absent = unchecked; exp counts the current second as expired)
    auto now = (int64_t)std::time(nullptr);
    if (auto *it = po.find("exp"); it != po.end()) {
        auto exp = jsonToInt64(it->value());
        if (!exp) throw JwtVerifyError("JsonWebTokenError", "invalid exp value");
        if (now >= *exp) throw JwtVerifyError("TokenExpiredError", "token expired");
    }
    if (auto *it = po.find("nbf"); it != po.end()) {
        auto nbf = jsonToInt64(it->value());
        if (!nbf) throw JwtVerifyError("JsonWebTokenError", "invalid nbf value");
        if (nbf > now) throw JwtVerifyError("NotBeforeError", "token not active yet");
    }

    // 6) issuer
    if (auto *it = po.find("iss"); it != po.end()) {
        if (!it->value().is_string() || it->value().get_string() != issuer)
            throw JwtVerifyError("JsonWebTokenError", "jwt issuer invalid. expected: " + issuer);
    } else {
        throw JwtVerifyError("JsonWebTokenError", "jwt issuer invalid. expected: " + issuer);
    }

    // 7) audience: string equality, or contained in the array
    if (auto *it = po.find("aud"); it != po.end()) {
        const json::value& aud = it->value();
        bool match = false;
        if (aud.is_string()) match = aud.get_string() == audience;
        else if (aud.is_array()) {
            for (const auto& a : aud.as_array())
                if (a.is_string() && a.get_string() == audience) {
                    match = true;
                    break;
                }
        }
        if (!match)
            throw JwtVerifyError("JsonWebTokenError", "jwt audience invalid. expected: " + audience);
    } else {
        throw JwtVerifyError("JsonWebTokenError", "jwt audience invalid. expected: " + audience);
    }

    return po;
}

std::string makeJwt(const openssl::Key& privateKey, const json::object& payload) {
    json::object header;
    header["alg"] = "RS256";
    header["typ"] = "JWT";
    auto h = b64::Base64Url::encode(json::serialize(header));
    auto p = b64::Base64Url::encode(json::serialize(payload));

    // symmetric with verification: RSASSA-PKCS1-v1_5(SHA-256) over "header.payload"
    const std::string signedData = h + "." + p;
    std::string sig = openssl::signRsaSha256(privateKey, signedData);

    return h + "." + p + "." + b64::Base64Url::encode(sig);
}

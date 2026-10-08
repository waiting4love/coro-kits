#include "key_loader.hpp"

#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>

#include "b64.hpp"

namespace {

// Extracts the contents between <Tag>...</Tag> (whitespace-lenient, matching the original regex semantics)
std::string extractTag(const std::string& xml, const std::string& tag) {
    const std::string open = "<" + tag + ">";
    const std::string close = "</" + tag + ">";
    auto b = xml.find(open);
    if (b == std::string::npos) return {};
    b += open.size();
    auto e = xml.find(close, b);
    if (e == std::string::npos) return {};
    return xml.substr(b, e - b);
}

std::string readFileOrThrow(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open key file: " + path);
    return {(std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()};
}

// base64 text -> bytes (missing/empty/invalid -> nullopt)
std::optional<std::string> bytesFromB64Text(const std::string& b64Text) {
    auto bytes = b64::Base64Std::decode(b64Text);
    if (!bytes || bytes->empty()) return std::nullopt;
    return bytes;
}

// Extracts an optional private parameter (P/Q/DP/DQ/InverseQ): missing or invalid -> nullopt
std::optional<std::string> optionalFactor(const std::string& xml, const char* tag) {
    std::string text = extractTag(xml, tag);
    if (text.empty()) return std::nullopt;
    return bytesFromB64Text(text);
}

// RSA parameter assembly is delegated to openssl::Key::rsa (the RSA*-specific API stays inside its .cpp)
openssl::Key loadFromXml(const std::string& xmlPath, bool wantPrivate) {
    std::string xml = readFileOrThrow(xmlPath);

    auto modulus = bytesFromB64Text(extractTag(xml, "Modulus"));
    auto exponent = bytesFromB64Text(extractTag(xml, "Exponent"));
    if (!modulus || !exponent)
        throw std::runtime_error("File is not a valid RSAKeyValue XML: " + xmlPath);

    // CRT params (P/Q/DP/DQ/InverseQ): both .NET exports and the test key
    // generator include them; without them LibreSSL can still do private-key
    // math with (n,e,d) (slower but correct). Invalid or partially-missing
    // values are skipped; Key::rsa applies the pair/group consistency rules
    auto d = wantPrivate ? bytesFromB64Text(extractTag(xml, "D")) : std::nullopt;
    auto p = wantPrivate ? optionalFactor(xml, "P") : std::nullopt;
    auto q = wantPrivate ? optionalFactor(xml, "Q") : std::nullopt;
    auto dp = wantPrivate ? optionalFactor(xml, "DP") : std::nullopt;
    auto dq = wantPrivate ? optionalFactor(xml, "DQ") : std::nullopt;
    auto iq = wantPrivate ? optionalFactor(xml, "InverseQ") : std::nullopt;
    if (wantPrivate && !d)
        throw std::runtime_error(
            "RSAKeyValue XML does not contain private key parameters (missing <D>): " +
            xmlPath);

    openssl::Key::RsaNumbers nb;
    nb.modulus = std::move(*modulus);
    nb.exponent = std::move(*exponent);
    nb.d = std::move(d);
    nb.p = std::move(p);
    nb.q = std::move(q);
    nb.dp = std::move(dp);
    nb.dq = std::move(dq);
    nb.iq = std::move(iq);
    return openssl::Key::rsa(nb);
}

} // namespace

openssl::Key loadPrivateEvpKeyFromXml(const std::string& xmlPath) {
    return loadFromXml(xmlPath, true);
}

openssl::Key loadPublicEvpKeyFromXml(const std::string& xmlPath) {
    return loadFromXml(xmlPath, false);
}

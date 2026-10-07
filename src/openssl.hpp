#pragma once
// Thin RAII wrapper over the LibreSSL/OpenSSL C API.
//
// Designed around real caller needs: RSA keys assembled from .NET
// RSAKeyValue XML (key_loader), RS256/SHA256WithRSA sign/verify (jwt /
// binary protocols), chunked PKCS#1 v1.5 encryption, secure random bytes
// (session ids). Only the unified EVP_PKEY layer (openssl::Key) is exposed;
// the RSA* assembly API (RSA_new/RSA_set0_*/BN_bin2bn...) lives entirely
// inside openssl.cpp.
//
// Conventions:
//   - errors throw openssl::Error (inherits std::runtime_error); the message
//     carries the OpenSSL error stack text ("[openssl] what: <err>")
//   - a failed verification is not an error: verifyRsaSha256 returns false
//   - the digest is always SHA-256: the only algorithm any caller needs
//     (RS256 and SHA256WithRSA are the same construction); no unused knobs
//   - upstream TLS (asio::ssl::stream/context) is asio integration
//     territory, out of scope here

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

// Official opaque handle types, forward-declared: this header pulls in no C
// headers; <openssl/*.h> is only included in openssl.cpp (same approach as
// sqlite.hpp)
struct evp_pkey_st;
struct evp_pkey_ctx_st;
using EVP_PKEY = evp_pkey_st;
using EVP_PKEY_CTX = evp_pkey_ctx_st;

namespace openssl {

// ---- error ----

class Error : public std::runtime_error {
public:
    // what like "EVP_DigestSign failed"; msg is OpenSSL error stack text (may be empty)
    Error(const std::string& what, const std::string& msg);
};

// ---- secure random ----

// n cryptographically secure random bytes (RAND_bytes); throws Error on failure
[[nodiscard]] std::string randomBytes(size_t n);

// ---- EVP_PKEY (unified key layer) ----

class Key {
public:
    // RSA parameters (big-endian byte strings, owning copies - deliberately
    // not string_view: key assembly happens once at startup, and borrowing
    // members invite dangling views). Assembly uses the RSA*-specific API
    // but stays enclosed in openssl.cpp.
    struct RsaNumbers {
        std::string modulus;                    // required
        std::string exponent;                   // required
        std::optional<std::string> d;           // private exponent (absent = public)
        std::optional<std::string> p, q;        // factors (both must be present to take effect)
        std::optional<std::string> dp, dq, iq;  // CRT params (all must be present to take effect)
        // without p/q/dp/dq/iq, (n,e,d) private-key operations still work
        // (slower but correct)
    };

    Key() = default;
    ~Key();
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    Key(Key&& other) noexcept;
    Key& operator=(Key&& other) noexcept;

    // Assembles an EVP_PKEY from RSA numbers; throws Error on empty/invalid input
    [[nodiscard]] static Key rsa(const RsaNumbers& numbers);

    // OpenSSL-ecosystem interop (e.g. an independent verifier in tests);
    // empty key -> nullptr
    [[nodiscard]] EVP_PKEY* handle() const noexcept;
    [[nodiscard]] int size() const noexcept; // EVP_PKEY_size in bytes; 0 for an empty key
    explicit operator bool() const noexcept { return pkey_ != nullptr; }

private:
    EVP_PKEY* pkey_ = nullptr;
};

// ---- RSASSA-PKCS1-v1_5(SHA-256) sign/verify ----

// Hash + sign in one step; returns the signature bytes (length = key.size());
// throws Error on failure
[[nodiscard]] std::string signRsaSha256(const Key& key, std::string_view data);

// Hash + verify in one step: true for a valid signature; false for an
// invalid one (including malformed input), never throws
[[nodiscard]] bool verifyRsaSha256(const Key& key, std::string_view data, std::string_view sig);

// ---- RSA PKCS#1 v1.5 block encrypt/decrypt (EVP_PKEY_CTX) ----

// Context for block-wise encrypt/decrypt, reused per key (LibreSSL's
// rsa_pmeth PKCS1 path forwards straight to RSA_*_encrypt/decrypt with no
// cross-call state). The caller splits blocks by keySize (encrypt block <=
// keySize-11, decrypt block = keySize)
class Pkcs1Ctx {
public:
    ~Pkcs1Ctx();
    Pkcs1Ctx(const Pkcs1Ctx&) = delete;
    Pkcs1Ctx& operator=(const Pkcs1Ctx&) = delete;
    Pkcs1Ctx(Pkcs1Ctx&& other) noexcept;
    Pkcs1Ctx& operator=(Pkcs1Ctx&& other) noexcept;

    [[nodiscard]] static Pkcs1Ctx forEncrypt(const Key& key); // public-key encryption context
    [[nodiscard]] static Pkcs1Ctx forDecrypt(const Key& key); // private-key decryption context

    // Single-block operation: *outLen takes the capacity of out and receives
    // the actual length; throws Error on failure (decrypting corrupted data
    // throws too - mapping that to an error response is business logic)
    void encrypt(unsigned char* out, size_t* outLen, const unsigned char* in, size_t inLen);
    void decrypt(unsigned char* out, size_t* outLen, const unsigned char* in, size_t inLen);

private:
    explicit Pkcs1Ctx(EVP_PKEY_CTX* ctx) noexcept;

    EVP_PKEY_CTX* ctx_ = nullptr;
};

} // namespace openssl

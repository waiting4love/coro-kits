// Implementation of openssl.hpp. All LibreSSL/OpenSSL calls live in this
// file; the rest of the codebase only needs the forward declarations from
// openssl.hpp to hold handle pointers.
#include "openssl.hpp"

#include <cstring>
#include <memory>
#include <utility>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace openssl {
namespace {

[[noreturn]] void failMsg(const std::string& what, const std::string& msg = {}) {
    throw Error(what, msg);
}

// Pops the newest OpenSSL error-stack entry, then clears the stack (stack
// text is more diagnostic than return codes; without any, throws just what)
[[noreturn]] void failSsl(const char* what) {
    const unsigned long code = ERR_peek_last_error();
    char buf[256];
    if (code != 0) ERR_error_string_n(code, buf, sizeof(buf));
    ERR_clear_error();
    failMsg(what, code != 0 ? buf : "");
}

// ---- internal RAII (not exposed) ----

struct BnDeleter {
    void operator()(BIGNUM* p) const {
        if (p) BN_free(p);
    }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;

struct RsaDeleter {
    void operator()(RSA* p) const {
        if (p) RSA_free(p);
    }
};
using RsaPtr = std::unique_ptr<RSA, RsaDeleter>;

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX* p) const {
        if (p) EVP_MD_CTX_free(p);
    }
};
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

// OpenSSL takes over the raw pointer (RSA_set0_* / EVP_PKEY_assign_RSA
// succeeded); the pointer value returned by release() is deliberately unused
template <typename T, typename D>
void detach(std::unique_ptr<T, D>& p) {
    (void)p.release(); // NOLINT(bugprone-unused-return-value)
}

// big-endian byte string -> BIGNUM (empty string -> null pointer)
BIGNUM* bnFromBin(const std::string& bytes) {
    if (bytes.empty()) return nullptr;
    return BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.data()), (int)bytes.size(),
                     nullptr);
}

} // namespace

// ---- error ----

Error::Error(const std::string& what, const std::string& msg)
    : std::runtime_error("[openssl] " + what + (msg.empty() ? "" : ": " + msg)) {}

// ---- secure random ----

std::string randomBytes(size_t n) {
    std::string out(n, '\0');
    if (n != 0 &&
        RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), (int)n) != 1)
        failSsl("RAND_bytes failed");
    return out;
}

// ---- EVP_PKEY ----

Key::~Key() {
    if (pkey_ != nullptr) EVP_PKEY_free(pkey_);
}

Key::Key(Key&& other) noexcept : pkey_(std::exchange(other.pkey_, nullptr)) {}

Key& Key::operator=(Key&& other) noexcept {
    if (this != &other) {
        if (pkey_ != nullptr) EVP_PKEY_free(pkey_);
        pkey_ = std::exchange(other.pkey_, nullptr);
    }
    return *this;
}

Key Key::rsa(const RsaNumbers& numbers) {
    // The only place the RSA* assembly API exists: inside this function.
    // BN_free/RSA_free on every error path is handled by RAII; the success
    // path transfers ownership via release()
    BnPtr n(bnFromBin(numbers.modulus));
    BnPtr e(bnFromBin(numbers.exponent));
    if (!n || !e) failMsg("invalid RSA numbers", "modulus and exponent are required");

    BnPtr d;
    if (numbers.d) d.reset(bnFromBin(*numbers.d));
    if (numbers.d && !d) failMsg("invalid RSA numbers", "bad private exponent");

    RsaPtr rsa(RSA_new());
    if (!rsa) failSsl("RSA_new failed");
    if (RSA_set0_key(rsa.get(), n.get(), e.get(), d ? d.get() : nullptr) != 1)
        failSsl("RSA_set0_key failed");
    detach(n); // success: rsa owns n/e(/d)
    detach(e);
    if (d) detach(d);

    if (numbers.p && numbers.q) {
        BnPtr p(bnFromBin(*numbers.p));
        BnPtr q(bnFromBin(*numbers.q));
        if (p && q) {
            if (RSA_set0_factors(rsa.get(), p.get(), q.get()) != 1)
                failSsl("RSA_set0_factors failed");
            detach(p); // success: rsa owns p/q
            detach(q);

            if (numbers.dp && numbers.dq && numbers.iq) {
                BnPtr dp(bnFromBin(*numbers.dp));
                BnPtr dq(bnFromBin(*numbers.dq));
                BnPtr iq(bnFromBin(*numbers.iq));
                if (dp && dq && iq) {
                    if (RSA_set0_crt_params(rsa.get(), dp.get(), dq.get(), iq.get()) != 1)
                        failSsl("RSA_set0_crt_params failed");
                    detach(dp); // success: rsa owns dp/dq/iq
                    detach(dq);
                    detach(iq);
                }
                // partially missing: non-transferred values are BN_free'd by
                // their BnPtr destructors; affects speed only, not correctness
            }
        }
        // p or q invalid: same auto-release, CRT skipped
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == nullptr || EVP_PKEY_assign_RSA(pkey, rsa.get()) != 1) {
        if (pkey != nullptr) EVP_PKEY_free(pkey);
        failSsl("EVP_PKEY_assign_RSA failed");
    }
    detach(rsa); // assign succeeded: pkey owns rsa

    Key out;
    out.pkey_ = pkey;
    return out;
}

EVP_PKEY* Key::handle() const noexcept { return pkey_; }

int Key::size() const noexcept { return pkey_ != nullptr ? EVP_PKEY_size(pkey_) : 0; }

// ---- RSASSA-PKCS1-v1_5(SHA-256) ----

std::string signRsaSha256(const Key& key, std::string_view data) {
    if (!key) failMsg("sign: empty key");
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) failSsl("EVP_MD_CTX_new failed");
    std::string sig((size_t)key.size(), '\0');
    size_t len = sig.size();
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.handle()) <= 0 ||
        EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(sig.data()), &len,
                       reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0)
        failSsl("EVP_DigestSign failed");
    sig.resize(len);
    return sig;
}

bool verifyRsaSha256(const Key& key, std::string_view data, std::string_view sig) {
    if (!key) return false;
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) failSsl("EVP_MD_CTX_new failed");
    // A failed verification (init failure or invalid signature) is not an
    // error: clear the stack and return false - "invalid" is a business
    // result, not an exceptional one
    bool ok = EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.handle()) == 1 &&
              EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(sig.data()),
                               sig.size(), reinterpret_cast<const unsigned char*>(data.data()),
                               data.size()) == 1;
    ERR_clear_error();
    return ok;
}

// ---- RSA PKCS#1 v1.5 block encrypt/decrypt ----

Pkcs1Ctx::~Pkcs1Ctx() {
    if (ctx_ != nullptr) EVP_PKEY_CTX_free(ctx_);
}

Pkcs1Ctx::Pkcs1Ctx(Pkcs1Ctx&& other) noexcept : ctx_(std::exchange(other.ctx_, nullptr)) {}

Pkcs1Ctx& Pkcs1Ctx::operator=(Pkcs1Ctx&& other) noexcept {
    if (this != &other) {
        if (ctx_ != nullptr) EVP_PKEY_CTX_free(ctx_);
        ctx_ = std::exchange(other.ctx_, nullptr);
    }
    return *this;
}

Pkcs1Ctx::Pkcs1Ctx(EVP_PKEY_CTX* ctx) noexcept : ctx_(ctx) {}

Pkcs1Ctx Pkcs1Ctx::forEncrypt(const Key& key) {
    if (!key) failMsg("encrypt: empty key");
    Pkcs1Ctx out(EVP_PKEY_CTX_new(key.handle(), nullptr));
    if (!out.ctx_) failSsl("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_encrypt_init(out.ctx_) <= 0) failSsl("EVP_PKEY_encrypt_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(out.ctx_, RSA_PKCS1_PADDING) <= 0)
        failSsl("EVP_PKEY_CTX_set_rsa_padding failed");
    return out;
}

Pkcs1Ctx Pkcs1Ctx::forDecrypt(const Key& key) {
    if (!key) failMsg("decrypt: empty key");
    Pkcs1Ctx out(EVP_PKEY_CTX_new(key.handle(), nullptr));
    if (!out.ctx_) failSsl("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_decrypt_init(out.ctx_) <= 0) failSsl("EVP_PKEY_decrypt_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(out.ctx_, RSA_PKCS1_PADDING) <= 0)
        failSsl("EVP_PKEY_CTX_set_rsa_padding failed");
    return out;
}

void Pkcs1Ctx::encrypt(unsigned char* out, size_t* outLen, const unsigned char* in, size_t inLen) {
    if (EVP_PKEY_encrypt(ctx_, out, outLen, in, inLen) <= 0) failSsl("EVP_PKEY_encrypt failed");
}

void Pkcs1Ctx::decrypt(unsigned char* out, size_t* outLen, const unsigned char* in, size_t inLen) {
    if (EVP_PKEY_decrypt(ctx_, out, outLen, in, inLen) <= 0) failSsl("EVP_PKEY_decrypt failed");
}

} // namespace openssl

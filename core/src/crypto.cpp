#include "zt/crypto.hpp"

#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>

namespace zt {

namespace {

struct CtxFree {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
    void operator()(BIO* b) const { BIO_free(b); }
};

[[noreturn]] void crypto_failure(const char* what) {
    // Failing crypto primitives mean the process can't produce trustworthy output.
    std::fprintf(stderr, "zt: fatal: OpenSSL %s failed\n", what);
    std::abort();
}

Result<std::string> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return Result<std::string>::fail("cannot read " + path);
    return Result<std::string>::ok(std::string(std::istreambuf_iterator<char>(in), {}));
}

// Creates a new file with the given mode; fails if it already exists.
Result<bool> write_new_file(const std::string& path, const std::string& data, mode_t mode) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) return Result<bool>::fail("create " + path + ": " + std::strerror(errno));
    const ssize_t n = ::write(fd, data.data(), data.size());
    const bool ok = n == static_cast<ssize_t>(data.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) return Result<bool>::fail("write " + path + " failed");
    return Result<bool>::ok(true);
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<std::size_t>(len));
}

}  // namespace

Sha256 sha256(std::span<const std::uint8_t> data) {
    Sha256 out{};
    unsigned len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1) crypto_failure("SHA-256");
    return out;
}

std::string hex(std::span<const std::uint8_t> data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(data.size() * 2);
    for (const auto b : data) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0xF]);
    }
    return s;
}

std::string base64_encode(std::span<const std::uint8_t> data) {
    std::string out(4 * ((data.size() + 2) / 3) + 1, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data.data(), static_cast<int>(data.size()));
    out.resize(static_cast<std::size_t>(n));
    return out;
}

Result<std::vector<std::uint8_t>> base64_decode(std::string_view text) {
    using R = Result<std::vector<std::uint8_t>>;
    if (text.size() % 4 != 0) return R::fail("invalid base64 length");
    std::vector<std::uint8_t> out(text.size() / 4 * 3);
    const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(text.data()),
                                  static_cast<int>(text.size()));
    if (n < 0) return R::fail("invalid base64");
    // EVP_DecodeBlock doesn't strip padding from its output length.
    std::size_t len = static_cast<std::size_t>(n);
    if (!text.empty() && text.back() == '=') --len;
    if (text.size() >= 2 && text[text.size() - 2] == '=') --len;
    out.resize(len);
    return R::ok(std::move(out));
}

std::vector<std::uint8_t> random_bytes(std::size_t n) {
    std::vector<std::uint8_t> out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) crypto_failure("RAND_bytes");
    return out;
}

std::string uuid_v4() {
    auto b = random_bytes(16);
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);  // version 4
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);  // RFC 4122 variant
    const std::string h = hex(b);
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) + "-" + h.substr(20);
}

std::string utc_now_iso8601() {
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&now, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// --- Ed25519 ----------------------------------------------------------------

SigningKey::SigningKey(EVP_PKEY* key) : key_(key, EVP_PKEY_free) {}

SigningKey SigningKey::generate() {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (!key) crypto_failure("Ed25519 keygen");
    return SigningKey(key);
}

Result<SigningKey> SigningKey::load_private_pem(const std::string& path) {
    const auto pem = read_file(path);
    if (!pem) return Result<SigningKey>::fail(pem.error());
    std::unique_ptr<BIO, CtxFree> bio(BIO_new_mem_buf(pem->data(), static_cast<int>(pem->size())));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!key) return Result<SigningKey>::fail(path + ": not a PEM private key");
    if (EVP_PKEY_get_id(key) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(key);
        return Result<SigningKey>::fail(path + ": not an Ed25519 key");
    }
    return Result<SigningKey>::ok(SigningKey(key));
}

Result<bool> SigningKey::save_pem(const std::string& private_path, const std::string& public_path) const {
    std::unique_ptr<BIO, CtxFree> priv(BIO_new(BIO_s_mem()));
    std::unique_ptr<BIO, CtxFree> pub(BIO_new(BIO_s_mem()));
    if (PEM_write_bio_PrivateKey(priv.get(), key_.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
        PEM_write_bio_PUBKEY(pub.get(), key_.get()) != 1) {
        return Result<bool>::fail("PEM encoding failed");
    }
    if (auto r = write_new_file(private_path, bio_to_string(priv.get()), 0600); !r) return r;
    return write_new_file(public_path, bio_to_string(pub.get()), 0644);
}

std::vector<std::uint8_t> SigningKey::public_raw() const {
    std::vector<std::uint8_t> out(32);
    std::size_t len = out.size();
    if (EVP_PKEY_get_raw_public_key(key_.get(), out.data(), &len) != 1) crypto_failure("get public key");
    out.resize(len);
    return out;
}

std::vector<std::uint8_t> SigningKey::sign(std::span<const std::uint8_t> message) const {
    std::unique_ptr<EVP_MD_CTX, CtxFree> ctx(EVP_MD_CTX_new());
    std::vector<std::uint8_t> sig(64);
    std::size_t len = sig.size();
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key_.get()) != 1 ||
        EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1) {
        crypto_failure("Ed25519 sign");
    }
    sig.resize(len);
    return sig;
}

Result<std::vector<std::uint8_t>> load_public_pem(const std::string& path) {
    using R = Result<std::vector<std::uint8_t>>;
    const auto pem = read_file(path);
    if (!pem) return R::fail(pem.error());
    std::unique_ptr<BIO, CtxFree> bio(BIO_new_mem_buf(pem->data(), static_cast<int>(pem->size())));
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                                                          EVP_PKEY_free);
    if (!key || EVP_PKEY_get_id(key.get()) != EVP_PKEY_ED25519) return R::fail(path + ": not an Ed25519 public key");
    std::vector<std::uint8_t> out(32);
    std::size_t len = out.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), out.data(), &len) != 1) return R::fail(path + ": unreadable key");
    out.resize(len);
    return R::ok(std::move(out));
}

bool ed25519_verify(std::span<const std::uint8_t> public_raw, std::span<const std::uint8_t> message,
                    std::span<const std::uint8_t> signature) {
    if (public_raw.size() != 32 || signature.size() != 64) return false;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_raw.data(), public_raw.size()), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, CtxFree> ctx(EVP_MD_CTX_new());
    if (!key || !ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

// --- Keystream ----------------------------------------------------------------

Keystream Keystream::random() {
    Keystream k;
    const auto r = random_bytes(k.key_.size() + k.nonce_.size());
    std::memcpy(k.key_.data(), r.data(), k.key_.size());
    std::memcpy(k.nonce_.data(), r.data() + k.key_.size(), k.nonce_.size());
    return k;
}

void Keystream::fill(std::uint64_t offset, std::span<std::uint8_t> out) const {
    // IV = 64-bit nonce || 64-bit big-endian block counter starting at offset / 16.
    std::array<std::uint8_t, 16> iv{};
    std::memcpy(iv.data(), nonce_.data(), nonce_.size());
    const std::uint64_t block = offset / 16;
    for (int i = 0; i < 8; ++i) iv[15 - static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(block >> (8 * i));

    std::unique_ptr<EVP_CIPHER_CTX, CtxFree> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, key_.data(), iv.data()) != 1) {
        crypto_failure("AES-CTR init");
    }
    int len = 0;
    // Advance past the part of the first block that precedes `offset`.
    if (const int skip = static_cast<int>(offset % 16); skip > 0) {
        std::array<std::uint8_t, 16> scratch{};
        if (EVP_EncryptUpdate(ctx.get(), scratch.data(), &len, scratch.data(), skip) != 1) crypto_failure("AES-CTR");
    }
    // Encrypting zeros in place yields the raw keystream.
    std::memset(out.data(), 0, out.size());
    constexpr std::size_t kStep = 1 << 30;  // EVP lengths are int
    for (std::size_t done = 0; done < out.size(); done += kStep) {
        const int n = static_cast<int>(std::min(kStep, out.size() - done));
        if (EVP_EncryptUpdate(ctx.get(), out.data() + done, &len, out.data() + done, n) != 1) crypto_failure("AES-CTR");
    }
}

}  // namespace zt

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "pm/result.hpp"

typedef struct evp_pkey_st EVP_PKEY;

namespace pm {

using Sha256 = std::array<std::uint8_t, 32>;

Sha256 sha256(std::span<const std::uint8_t> data);
std::string hex(std::span<const std::uint8_t> data);
std::string base64_encode(std::span<const std::uint8_t> data);
Result<std::vector<std::uint8_t>> base64_decode(std::string_view text);
std::vector<std::uint8_t> random_bytes(std::size_t n);  // CSPRNG; aborts if the RNG fails
std::string uuid_v4();
std::string utc_now_iso8601();  // e.g. "2026-10-30T14:05:09Z"

inline std::span<const std::uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// Ed25519 signing key held by OpenSSL.
class SigningKey {
public:
    static SigningKey generate();
    static Result<SigningKey> load_private_pem(const std::string& path);
    // Writes PRIVATE (mode 0600) and PUBLIC PEM files; refuses to overwrite either.
    Result<bool> save_pem(const std::string& private_path, const std::string& public_path) const;

    std::vector<std::uint8_t> public_raw() const;  // 32 bytes
    std::vector<std::uint8_t> sign(std::span<const std::uint8_t> message) const;

private:
    explicit SigningKey(EVP_PKEY* key);
    std::shared_ptr<EVP_PKEY> key_;
};

Result<std::vector<std::uint8_t>> load_public_pem(const std::string& path);  // raw 32-byte key
bool ed25519_verify(std::span<const std::uint8_t> public_raw, std::span<const std::uint8_t> message,
                    std::span<const std::uint8_t> signature);

// AES-256-CTR keystream addressable by byte offset: fill(off, buf) yields the
// same bytes whether the stream is generated in one piece or in fragments. This
// lets verification recompute the expected random pattern at any sampled offset.
class Keystream {
public:
    static Keystream random();
    void fill(std::uint64_t offset, std::span<std::uint8_t> out) const;

private:
    std::array<std::uint8_t, 32> key_{};
    std::array<std::uint8_t, 8> nonce_{};
};

}  // namespace pm

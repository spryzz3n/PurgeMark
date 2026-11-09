// `pmark keygen` and `pmark verify-cert`.

#include <fstream>
#include <iostream>
#include <optional>

#include <nlohmann/json.hpp>

#include "common.hpp"
#include "pm/certificate.hpp"

namespace pmcli {

int cmd_keygen(const std::vector<std::string_view>& argv) {
    if (argv.size() != 1) {
        std::cerr << "usage: pmark keygen PREFIX   (writes PREFIX.key and PREFIX.pub)\n";
        return 2;
    }
    const std::string prefix(argv[0]);
    const auto key = pm::SigningKey::generate();
    if (auto r = key.save_pem(prefix + ".key", prefix + ".pub"); !r) {
        std::cerr << "pmark: " << r.error() << "\n";
        return 1;
    }
    std::cout << "private key: " << prefix << ".key (keep offline; mode 0600)\n"
              << "public key : " << prefix << ".pub (give to verifiers)\n"
              << "key id     : " << pm::key_id(key.public_raw()) << "\n";
    return 0;
}

int cmd_verify_cert(const std::vector<std::string_view>& argv) {
    const auto parsed = parse_args(argv, {"trusted-key"}, {});
    if (!parsed || parsed->positional.size() != 1) {
        if (!parsed) std::cerr << "pmark: " << parsed.error() << "\n";
        std::cerr << "usage: pmark verify-cert CERT.json [--trusted-key PUBLIC.pem]\n"
                     "exit status 0 only if the signature is valid, the signer is trusted\n"
                     "(when --trusted-key is given), and the certificate reports success.\n";
        return 2;
    }
    const Args& args = parsed.value();

    std::optional<std::vector<std::uint8_t>> trusted;
    if (args.options.count("trusted-key")) {
        auto pub = pm::load_public_pem(args.get("trusted-key"));
        if (!pub) {
            std::cerr << "pmark: " << pub.error() << "\n";
            return 1;
        }
        trusted = pub.value();
    }

    std::ifstream in(args.positional[0]);
    if (!in) {
        std::cerr << "pmark: cannot read " << args.positional[0] << "\n";
        return 1;
    }
    const auto cert = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
    if (cert.is_discarded()) {
        std::cerr << "pmark: not valid JSON\n";
        return 1;
    }

    const auto check = pm::verify_certificate(cert, trusted);
    if (!check.signature_valid) {
        std::cout << "signature : INVALID, " << check.error << "\n";
        return 1;
    }
    std::cout << "signature : valid\n";
    std::cout << "signer    : key " << check.key_id << " (" << check.attestation << ")\n";
    if (!trusted) std::cout << "trust     : not checked; pass --trusted-key to confirm who signed it\n";
    else if (check.trusted) std::cout << "trust     : signer matches the trusted key\n";
    else std::cout << "trust     : NOT TRUSTED, signer differs from the trusted key\n";

    // A validly signed certificate can still come from a key we don't know, so don't assume its shape.
    const auto section = [&](const char* name) {
        const auto it = cert.find(name);
        return it != cert.end() && it->is_object() ? *it : nlohmann::json::object();
    };
    const auto dev = section("device");
    const auto san = section("sanitization");
    const auto ver = section("verification");
    std::cout << "result    : " << cert.value("result", "?") << "\n"
              << "device    : " << dev.value("model", "") << ", serial " << dev.value("serial", "") << "\n"
              << "method    : " << san.value("method_name", "") << " (NIST " << san.value("nist_level", "")
              << ")\n"
              << "verified  : " << (ver.value("passed", false) ? "yes" : "no") << ", "
              << ver.value("samples", 0) << " samples\n"
              << "issued at : " << cert.value("issued_at", "") << "\n";

    const bool ok = (!trusted || check.trusted) && cert.value("result", "") == "sanitized";
    return ok ? 0 : 1;
}

}  // namespace pmcli

// `pmark android begin` and `pmark android verify`: the station side of the phone flow.

#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>

#include "common.hpp"
#include "pm/android_record.hpp"
#include "pm/crypto.hpp"

namespace pmcli {

namespace {

constexpr const char* kUsage =
    "usage: pmark android begin [--out FILE]\n"
    "       pmark android verify RECORD.json --challenge FILE --roots ROOTS.pem\n";

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

// Draws the QR code with qrencode. No shell involved; false if it isn't installed.
bool print_qr(const std::string& payload) {
    const pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        ::execlp("qrencode", "qrencode", "-t", "ANSIUTF8", payload.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int begin(const std::vector<std::string_view>& argv) {
    const auto parsed = parse_args(argv, {"out"}, {});
    if (!parsed || !parsed->positional.empty()) {
        std::cerr << kUsage;
        return 2;
    }
    const std::string payload = pm::challenge_payload(pm::random_bytes(pm::kChallengeSize));
    const std::string out = parsed->get("out", "challenge.txt");
    std::ofstream file(out, std::ios::trunc);
    if (!(file << payload << "\n")) {
        std::cerr << "pmark: cannot write " << out << "\n";
        return 1;
    }
    if (!print_qr(payload)) std::cout << "(install qrencode to get a QR code here)\n";
    std::cout << payload << "\nScan this in the app. Challenge saved to " << out << "\n";
    return 0;
}

const char* yes_no(bool v) { return v ? "yes" : "NO"; }

int verify(const std::vector<std::string_view>& argv) {
    const auto parsed = parse_args(argv, {"challenge", "roots"}, {});
    if (!parsed || parsed->positional.size() != 1) {
        std::cerr << kUsage;
        return 2;
    }
    const auto text = read_file(parsed->positional[0]);
    if (!text) {
        std::cerr << "pmark: cannot read " << parsed->positional[0] << "\n";
        return 1;
    }
    const auto record = nlohmann::json::parse(*text, nullptr, false);
    if (record.is_discarded()) {
        std::cerr << "pmark: not valid JSON\n";
        return 1;
    }

    std::optional<std::vector<std::uint8_t>> challenge;
    if (const std::string path = parsed->get("challenge"); !path.empty()) {
        auto payload = read_file(path);
        if (!payload) {
            std::cerr << "pmark: cannot read " << path << "\n";
            return 1;
        }
        payload->erase(payload->find_last_not_of(" \r\n") + 1);
        const auto bytes = pm::parse_challenge_payload(*payload);
        if (!bytes) {
            std::cerr << "pmark: " << path << ": " << bytes.error() << "\n";
            return 1;
        }
        challenge = bytes.value();
    }
    std::optional<std::string> roots;
    if (const std::string path = parsed->get("roots"); !path.empty()) {
        roots = read_file(path);
        if (!roots) {
            std::cerr << "pmark: cannot read " << path << "\n";
            return 1;
        }
    }

    const auto r = pm::check_android_record(record, challenge, roots);
    if (!r.error.empty()) {
        std::cerr << "pmark: " << r.error << "\n";
        return 1;
    }
    std::cout << "signature        : " << yes_no(r.signature_ok) << "\n"
              << "chain            : " << yes_no(r.chain_ok) << "\n"
              << "attested level   : " << r.security_level << (r.level_consistent ? "" : " (record claims otherwise)") << "\n"
              << "challenge bound  : " << yes_no(r.challenge_in_attestation) << "\n"
              << "station challenge: " << (r.challenge_expected ? yes_no(*r.challenge_expected) : "not checked") << "\n"
              << "trusted root     : " << (r.root_trusted ? yes_no(*r.root_trusted) : "not checked") << "\n"
              << "root key sha256  : " << r.root_sha256 << "\n"
              << "result           : " << (r.passed() ? "PASSED" : "NOT PROVEN") << "\n";
    return r.passed() ? 0 : 1;
}

}  // namespace

int cmd_android(const std::vector<std::string_view>& argv) {
    if (argv.empty()) {
        std::cerr << kUsage;
        return 2;
    }
    const std::vector<std::string_view> rest(argv.begin() + 1, argv.end());
    if (argv[0] == "begin") return begin(rest);
    if (argv[0] == "verify") return verify(rest);
    std::cerr << kUsage;
    return 2;
}

}  // namespace pmcli

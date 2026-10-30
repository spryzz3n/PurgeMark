#include <iostream>
#include <string_view>
#include <vector>

#include "common.hpp"

namespace {

constexpr std::string_view kUsage =
    "usage: zt <command> [args]\n"
    "\n"
    "inspect (read-only):\n"
    "  list                   show whole-disk block devices and erase blockers\n"
    "  probe [DEVICE..]       query drive identify data and rank erase methods (root)\n"
    "\n"
    "erase:\n"
    "  erase DEVICE           overwrite, verify, and issue a signed certificate (root)\n"
    "\n"
    "certificates:\n"
    "  keygen PREFIX          create an Ed25519 operator signing key\n"
    "  verify-cert CERT.json  check a certificate's signature and contents\n";

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << kUsage;
        return 2;
    }
    const std::string_view cmd = argv[1];
    const std::vector<std::string_view> rest(argv + 2, argv + argc);

    if (cmd == "list") return ztcli::cmd_list(rest);
    if (cmd == "probe") return ztcli::cmd_probe(rest);
    if (cmd == "erase") return ztcli::cmd_erase(rest);
    if (cmd == "keygen") return ztcli::cmd_keygen(rest);
    if (cmd == "verify-cert") return ztcli::cmd_verify_cert(rest);
    if (cmd == "-h" || cmd == "--help") {
        std::cout << kUsage;
        return 0;
    }
    std::cerr << "zt: unknown command '" << cmd << "'\n" << kUsage;
    return 2;
}

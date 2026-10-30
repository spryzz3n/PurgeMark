// `zt erase`: the only command that writes to a disk.

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

#include "common.hpp"
#include "zt/certificate.hpp"
#include "zt/erase.hpp"
#include "zt/probe.hpp"
#include "zt/safety.hpp"

namespace fs = std::filesystem;

namespace ztcli {

namespace {

constexpr const char* kEraseUsage =
    "usage: zt erase DEVICE [options]\n"
    "       zt erase --image FILE [options]\n"
    "\n"
    "  --pattern random|zero  overwrite pattern (default random)\n"
    "  --samples N            verification samples (default 1000)\n"
    "  --operator NAME        recorded in the certificate\n"
    "  --org NAME             recorded in the certificate\n"
    "  --key PRIVATE.pem      sign with this key; without it a one-off key is used\n"
    "                         and the certificate is marked self-attested\n"
    "  --out DIR              where to write the certificate (default .)\n"
    "  --confirm SERIAL       skip the interactive prompt; must equal the serial\n"
    "  --image                target is an image file or loop device (testing)\n";

std::atomic<bool> g_cancel{false};

extern "C" void on_sigint(int) { g_cancel.store(true); }

class ProgressPrinter {
public:
    bool operator()(std::uint64_t done, std::uint64_t total) {
        const auto now = Clock::now();
        if (now - last_ >= std::chrono::milliseconds(500) || done == total) {
            last_ = now;
            const double secs = std::chrono::duration<double>(now - start_).count();
            const double rate = secs > 0 ? static_cast<double>(done) / secs : 0;
            const long eta = rate > 0 ? static_cast<long>(static_cast<double>(total - done) / rate) : 0;
            std::fprintf(stderr, "\r  %5.1f%%  %s/s  ETA %ldm%02lds   ",
                         100.0 * static_cast<double>(done) / static_cast<double>(total),
                         human_size(static_cast<std::uint64_t>(rate)).c_str(), eta / 60, eta % 60);
            if (done == total) std::fputc('\n', stderr);
        }
        return !g_cancel.load();
    }

private:
    using Clock = std::chrono::steady_clock;
    Clock::time_point start_ = Clock::now();
    Clock::time_point last_{};
};

bool confirm(const std::string& token, const Args& args) {
    if (args.options.count("confirm")) return args.get("confirm") == token;
    if (!::isatty(STDIN_FILENO)) {
        std::cerr << "zt: not a terminal; pass --confirm " << token << " to proceed\n";
        return false;
    }
    std::cerr << "\nThis PERMANENTLY destroys all data on the target.\n"
              << "Type " << token << " to confirm: ";
    std::string typed;
    std::getline(std::cin, typed);
    return typed == token;
}

}  // namespace

int cmd_erase(const std::vector<std::string_view>& argv) {
    const auto parsed = parse_args(argv, {"pattern", "samples", "operator", "org", "key", "out", "confirm"}, {"image"});
    if (!parsed || parsed->positional.size() != 1) {
        if (!parsed) std::cerr << "zt: " << parsed.error() << "\n";
        std::cerr << kEraseUsage;
        return 2;
    }
    const Args& args = parsed.value();

    zt::EraseJob job;
    const std::string pattern = args.get("pattern", "random");
    if (pattern == "zero") job.pattern = zt::Pattern::Zero;
    else if (pattern != "random") {
        std::cerr << "zt: --pattern must be random or zero\n";
        return 2;
    }
    try {
        job.verify_samples = static_cast<std::uint32_t>(std::stoul(args.get("samples", "1000")));
    } catch (const std::exception&) {
        std::cerr << "zt: --samples must be a number\n";
        return 2;
    }

    // Resolve the target and the token the operator must type back.
    std::string token;
    const std::string target = args.positional[0];
    if (args.has("image")) {
        struct stat st{};
        if (::stat(target.c_str(), &st) != 0 || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) {
            std::cerr << "zt: --image expects an image file or a loop device\n";
            return 2;
        }
        job.target_path = target;
        job.device.name = fs::path(target).filename().string();
        job.device.path = target;
        if (S_ISBLK(st.st_mode)) {
            // Loop devices exercise the real block-device path (O_DIRECT, O_EXCL) in tests.
            const auto dev = zt::find_device(target);
            if (!dev || dev->name.rfind("loop", 0) != 0) {
                std::cerr << "zt: --image only accepts loop devices; erase real disks with zt erase DEVICE\n";
                return 2;
            }
            if (const auto blockers = zt::erase_blockers(*dev); !blockers.empty()) {
                for (const auto& b : blockers) std::cerr << "zt: refusing: " << b << "\n";
                return 1;
            }
            job.device = *dev;
            job.device.model = "loop device";
        } else {
            job.device.model = "disk image";
            job.device.size_bytes = static_cast<std::uint64_t>(st.st_size);
        }
        job.device.serial = "image:" + job.device.name;
        token = job.device.name;
    } else {
        if (::geteuid() != 0) {
            std::cerr << "zt: erasing a device needs root\n";
            return 1;
        }
        std::optional<zt::Device> dev;
        for (const auto& d : zt::list_devices()) {
            if (target == d.path || target == d.name) dev = d;
        }
        if (!dev) {
            std::cerr << "zt: no whole-disk device named '" << target << "' (see zt list)\n";
            return 1;
        }
        if (const auto blockers = zt::erase_blockers(*dev); !blockers.empty()) {
            for (const auto& b : blockers) std::cerr << "zt: refusing: " << b << "\n";
            return 1;
        }
        // Probe for identity: sysfs lacks SATA serials, IDENTIFY has them.
        job.device = zt::probe(*dev).device;
        job.target_path = dev->path;
        token = job.device.serial.empty() ? job.device.name : job.device.serial;
    }

    std::cerr << "target : " << job.target_path << "  " << or_dash(job.device.model) << "  "
              << human_size(job.device.size_bytes) << "\n"
              << "serial : " << or_dash(job.device.serial) << "\n"
              << "method : " << zt::to_string(job.method) << ", " << zt::to_string(job.pattern) << "\n";
    if (!confirm(token, args)) {
        std::cerr << "zt: confirmation did not match; nothing was written\n";
        return 1;
    }

    // Load the key before writing anything, so a bad --key can't strand a wiped disk without a record.
    std::optional<zt::SigningKey> key;
    zt::Attestation attestation = zt::Attestation::SelfAttested;
    if (args.options.count("key")) {
        auto k = zt::SigningKey::load_private_pem(args.get("key"));
        if (!k) {
            std::cerr << "zt: " << k.error() << "\n";
            return 1;
        }
        key = k.value();
        attestation = zt::Attestation::OperatorKey;
    } else {
        key = zt::SigningKey::generate();
    }
    const fs::path out_dir = args.get("out", ".");
    std::error_code ec;
    fs::create_directories(out_dir, ec);
    if (ec) {
        std::cerr << "zt: cannot create " << out_dir << ": " << ec.message() << "\n";
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    job.progress = ProgressPrinter{};
    auto input = zt::run_erase(job);
    std::signal(SIGINT, SIG_DFL);
    input.operator_name = args.get("operator");
    input.organization = args.get("org");

    const auto cert = zt::sign_certificate(zt::make_certificate_body(input), *key, attestation);
    if (!cert) {
        std::cerr << "zt: " << cert.error() << "\n";
        return 1;
    }
    const fs::path cert_path = out_dir / ("zerotrace-" + cert->at("certificate_id").get<std::string>() + ".json");
    std::ofstream(cert_path) << cert->dump(2) << "\n";

    const auto& v = input.verification;
    if (!input.sanitization.error.empty()) std::cerr << "erase  : FAILED, " << input.sanitization.error << "\n";
    else std::cerr << "erase  : wrote " << human_size(input.sanitization.bytes_written) << "\n";
    if (input.sanitization.completed) {
        std::cerr << "verify : " << (v.passed() ? "PASSED" : "FAILED") << ", " << v.samples << " samples, "
                  << human_size(v.bytes_checked) << " read back, " << v.mismatches << " mismatches"
                  << (v.error.empty() ? "" : ", " + v.error) << "\n";
    }
    std::cerr << "cert   : " << cert_path.string() << " ("
              << (attestation == zt::Attestation::OperatorKey ? "operator key " : "self-attested, key ")
              << zt::key_id(key->public_raw()) << ")\n";
    return cert->at("result") == "sanitized" ? 0 : 1;
}

}  // namespace ztcli

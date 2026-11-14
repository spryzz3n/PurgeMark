// `pmark erase`: the only command that writes to a disk.

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
#include "pm/certificate.hpp"
#include "pm/erase.hpp"
#include "pm/probe.hpp"
#include "pm/safety.hpp"

namespace fs = std::filesystem;

namespace pmcli {

namespace {

constexpr const char* kEraseUsage =
    "usage: pmark erase DEVICE [options]\n"
    "       pmark erase --image FILE [options]\n"
    "\n"
    "  --method ID            auto (default: best available, fully implemented),\n"
    "                         overwrite, nvme-format-ses1, nvme-format-ses2,\n"
    "                         nvme-sanitize-crypto|block|overwrite,\n"
    "                         ata-sanitize-crypto|block|overwrite (untested; need --experimental)\n"
    "  --experimental         allow methods not yet validated on real hardware\n"
    "  --allow-usb-sanitize   allow ATA SANITIZE on a drive behind a USB bridge; only\n"
    "                         with an explicit --method, never picked by auto\n"
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
        std::cerr << "pmark: not a terminal; pass --confirm " << token << " to proceed\n";
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
    const auto parsed = parse_args(argv, {"method", "pattern", "samples", "operator", "org", "key", "out", "confirm"},
                                   {"image", "experimental", "allow-usb-sanitize"});
    if (!parsed || parsed->positional.size() != 1) {
        if (!parsed) std::cerr << "pmark: " << parsed.error() << "\n";
        std::cerr << kEraseUsage;
        return 2;
    }
    const Args& args = parsed.value();

    pm::EraseJob job;
    job.allow_experimental = args.has("experimental");
    job.allow_usb_sanitize = args.has("allow-usb-sanitize");
    const std::string method_arg = args.get("method", "auto");
    std::optional<pm::Method> requested;
    if (method_arg != "auto") {
        requested = pm::method_from_id(method_arg);
        if (!requested) {
            std::cerr << "pmark: unknown --method " << method_arg << "\n" << kEraseUsage;
            return 2;
        }
    }
    const std::string pattern = args.get("pattern", "random");
    if (pattern == "zero") job.pattern = pm::Pattern::Zero;
    else if (pattern != "random") {
        std::cerr << "pmark: --pattern must be random or zero\n";
        return 2;
    }
    try {
        job.verify_samples = static_cast<std::uint32_t>(std::stoul(args.get("samples", "1000")));
    } catch (const std::exception&) {
        std::cerr << "pmark: --samples must be a number\n";
        return 2;
    }

    // Resolve the target and the token the operator must type back.
    std::string token;
    const std::string target = args.positional[0];
    if (args.has("image")) {
        struct stat st{};
        if (::stat(target.c_str(), &st) != 0 || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) {
            std::cerr << "pmark: --image expects an image file or a loop device\n";
            return 2;
        }
        job.target_path = target;
        job.device.name = fs::path(target).filename().string();
        job.device.path = target;
        if (S_ISBLK(st.st_mode)) {
            // Loop devices exercise the real block-device path (O_DIRECT, O_EXCL) in tests.
            const auto dev = pm::find_device(target);
            if (!dev || dev->name.rfind("loop", 0) != 0) {
                std::cerr << "pmark: --image only accepts loop devices; erase real disks with pmark erase DEVICE\n";
                return 2;
            }
            if (const auto blockers = pm::erase_blockers(*dev); !blockers.empty()) {
                for (const auto& b : blockers) std::cerr << "pmark: refusing: " << b << "\n";
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
        if (requested && *requested != pm::Method::Overwrite) {
            std::cerr << "pmark: --image targets support only --method overwrite\n";
            return 2;
        }
    } else {
        if (::geteuid() != 0) {
            std::cerr << "pmark: erasing a device needs root\n";
            return 1;
        }
        std::optional<pm::Device> dev;
        for (const auto& d : pm::list_devices()) {
            if (target == d.path || target == d.name) dev = d;
        }
        if (!dev) {
            std::cerr << "pmark: no whole-disk device named '" << target << "' (see pmark list)\n";
            return 1;
        }
        if (const auto blockers = pm::erase_blockers(*dev); !blockers.empty()) {
            for (const auto& b : blockers) std::cerr << "pmark: refusing: " << b << "\n";
            return 1;
        }
        // Probe for identity (sysfs lacks SATA serials, IDENTIFY has them) and capabilities.
        auto pr = pm::probe(*dev);
        job.device = pr.device;
        job.target_path = dev->path;
        token = job.device.serial.empty() ? job.device.name : job.device.serial;

        const auto runnable = [&](pm::Method m) {
            const auto s = pm::support(m);
            return s == pm::Support::Implemented || (s == pm::Support::Experimental && job.allow_experimental);
        };
        // The USB override only reopens the method that was asked for by name.
        if (job.allow_usb_sanitize && requested && pr.ata && pm::usb_sanitize_blocked(pr.device, *requested) &&
            pm::ata_sanitize_supported(*requested, *pr.ata)) {
            for (auto& c : pr.methods) {
                if (c.method == *requested) c.available = true;
            }
        }
        const pm::Candidate* chosen = nullptr;
        for (const auto& c : pr.methods) {
            if (requested ? c.method == *requested : (c.available && runnable(c.method))) {
                chosen = &c;
                break;
            }
        }
        if (!chosen || !chosen->available) {
            std::cerr << "pmark: " << (requested ? pm::to_string(*requested) : std::string("no method"))
                      << " is not available on this drive"
                      << (chosen && !chosen->note.empty() ? ": " + chosen->note : "") << " (see pmark probe)\n";
            return 1;
        }
        if (!runnable(chosen->method)) {
            std::cerr << "pmark: " << pm::to_string(chosen->method)
                      << (pm::support(chosen->method) == pm::Support::Experimental
                              ? " is experimental; add --experimental to use it\n"
                              : " is not implemented yet\n");
            return 1;
        }
        job.method = chosen->method;
    }

    std::cerr << "target : " << job.target_path << "  " << or_dash(job.device.model) << "  "
              << human_size(job.device.size_bytes) << "\n"
              << "serial : " << or_dash(job.device.serial) << "\n"
              << "method : " << pm::to_string(job.method) << " (NIST "
              << pm::to_string(pm::nominal_level(job.method, !job.device.rotational)) << ")"
              << (job.method == pm::Method::Overwrite ? ", " + pm::to_string(job.pattern) : "") << "\n";
    if (!confirm(token, args)) {
        std::cerr << "pmark: confirmation did not match; nothing was written\n";
        return 1;
    }

    // Load the key before writing anything, so a bad --key can't strand a wiped disk without a record.
    std::optional<pm::SigningKey> key;
    pm::Attestation attestation = pm::Attestation::SelfAttested;
    if (args.options.count("key")) {
        auto k = pm::SigningKey::load_private_pem(args.get("key"));
        if (!k) {
            std::cerr << "pmark: " << k.error() << "\n";
            return 1;
        }
        key = k.value();
        attestation = pm::Attestation::OperatorKey;
    } else {
        key = pm::SigningKey::generate();
    }
    const fs::path out_dir = args.get("out", ".");
    std::error_code ec;
    fs::create_directories(out_dir, ec);
    if (ec) {
        std::cerr << "pmark: cannot create " << out_dir << ": " << ec.message() << "\n";
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    job.progress = ProgressPrinter{};
    auto input = pm::run_erase(job);
    std::signal(SIGINT, SIG_DFL);
    input.operator_name = args.get("operator");
    input.organization = args.get("org");

    const auto cert = pm::sign_certificate(pm::make_certificate_body(input), *key, attestation);
    if (!cert) {
        std::cerr << "pmark: " << cert.error() << "\n";
        return 1;
    }
    const auto cert_path = pm::save_certificate(cert.value(), out_dir.string());
    if (!cert_path) {
        // Last resort: never lose the record of an erase that already happened.
        std::cerr << "pmark: " << cert_path.error() << "\n" << cert->dump(2) << "\n";
        return 1;
    }

    const auto& v = input.verification;
    if (!input.sanitization.error.empty()) std::cerr << "erase  : FAILED, " << input.sanitization.error << "\n";
    else if (input.sanitization.bytes_written) std::cerr << "erase  : wrote " << human_size(input.sanitization.bytes_written) << "\n";
    else std::cerr << "erase  : drive reported " << pm::to_string(job.method) << " complete\n";
    if (input.sanitization.completed) {
        std::cerr << "verify : " << (v.passed() ? "PASSED" : "FAILED") << " (" << v.mode << "), " << v.samples
                  << " samples, " << human_size(v.bytes_checked) << " read back, " << v.mismatches << " mismatches"
                  << (v.error.empty() ? "" : ", " + v.error) << "\n";
    }
    std::cerr << "cert   : " << cert_path.value() << " ("
              << (attestation == pm::Attestation::OperatorKey ? "operator key " : "self-attested, key ")
              << pm::key_id(key->public_raw()) << ")\n";
    return cert->at("result") == "sanitized" ? 0 : 1;
}

}  // namespace pmcli

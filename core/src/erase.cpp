#include "pm/erase.hpp"

#include <linux/fs.h>
#include <sys/ioctl.h>

#include <chrono>
#include <cstring>
#include <thread>

#include "pm/ata.hpp"
#include "pm/blockio.hpp"
#include "pm/crypto.hpp"
#include "pm/nvme.hpp"
#include "pm/safety.hpp"

namespace pm {

namespace {

SamplePlan make_plan(const Target& t, const EraseJob& job) {
    std::uint64_t seed = 0;
    const auto seed_bytes = random_bytes(sizeof seed);
    std::memcpy(&seed, seed_bytes.data(), sizeof seed);
    return plan_samples(t.size(), t.logical_block_size(), job.sample_bytes, job.verify_samples, seed);
}

// Sanitize can legitimately run for hours (overwrite on large HDDs); this only
// stops a drive that never reports completion from hanging the UI forever.
constexpr auto kSanitizeTimeout = std::chrono::hours(24);
constexpr int kMaxStatusErrors = 5;  // consecutive failed status queries before giving up

void report(const EraseJob& job, std::uint64_t done, std::uint64_t total) {
    if (job.progress) job.progress(done, total);
}

bool is_nvme_method(Method m) {
    switch (m) {
        case Method::NvmeSanitizeCrypto:
        case Method::NvmeSanitizeBlock:
        case Method::NvmeSanitizeOverwrite:
        case Method::NvmeFormatCrypto:
        case Method::NvmeFormatUserData:
            return true;
        default:
            return false;
    }
}

// Issues the NVMe command and waits for it to finish.
Result<bool> run_nvme(const Target& t, const EraseJob& job) {
    const auto nsid = nvme_namespace_id(t.path());
    if (!nsid) return Result<bool>::fail(nsid.error());

    if (job.method == Method::NvmeFormatUserData || job.method == Method::NvmeFormatCrypto) {
        const auto raw = nvme_identify_ns_raw(t.path(), nsid.value());
        if (!raw) return Result<bool>::fail(raw.error());
        const auto ns = parse_nvme_identify_ns(raw.value(), nsid.value());
        const unsigned ses = job.method == Method::NvmeFormatCrypto ? 2 : 1;
        report(job, 0, 1);
        auto r = nvme_format(t.fd(), nsid.value(), nvme_format_cdw10(ns, ses));
        if (r) report(job, 1, 1);
        return r;
    }

    const SanitizeAction action = job.method == Method::NvmeSanitizeCrypto  ? SanitizeAction::CryptoErase
                                  : job.method == Method::NvmeSanitizeBlock ? SanitizeAction::BlockErase
                                                                            : SanitizeAction::Overwrite;
    if (auto r = nvme_sanitize_start(t.fd(), action); !r) return r;
    // Sanitize runs in the background on the drive; poll its status log.
    int status_errors = 0;
    for (const auto deadline = std::chrono::steady_clock::now() + kSanitizeTimeout;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (std::chrono::steady_clock::now() > deadline) {
            return Result<bool>::fail("sanitize did not finish within 24 hours");
        }
        const auto st = nvme_sanitize_status(t.fd());
        if (!st) {
            if (++status_errors >= kMaxStatusErrors) return Result<bool>::fail(st.error());
            continue;
        }
        status_errors = 0;
        if (!st->done()) {
            report(job, st->progress, 65536);
            continue;
        }
        if (!st->succeeded()) {
            // AUSE was set, so the controller may leave the failed state on request
            // rather than restricting the drive until a sanitize succeeds.
            nvme_sanitize_start(t.fd(), SanitizeAction::ExitFailureMode);
            return Result<bool>::fail("drive reports the sanitize operation failed");
        }
        report(job, 1, 1);
        return Result<bool>::ok(true);
    }
}

bool is_ata_method(Method m) {
    return m == Method::AtaSanitizeCrypto || m == Method::AtaSanitizeBlock || m == Method::AtaSanitizeOverwrite;
}

// Issues ATA SANITIZE through SCSI/ATA Translation and waits for it to finish.
Result<bool> run_ata(const Target& t, const EraseJob& job) {
    const AtaSanitizeAction action = job.method == Method::AtaSanitizeCrypto  ? AtaSanitizeAction::CryptoScramble
                                     : job.method == Method::AtaSanitizeBlock ? AtaSanitizeAction::BlockErase
                                                                              : AtaSanitizeAction::Overwrite;
    if (auto r = ata_sanitize_start(t.fd(), action); !r) return r;
    int status_errors = 0;
    for (const auto deadline = std::chrono::steady_clock::now() + kSanitizeTimeout;;) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (std::chrono::steady_clock::now() > deadline) {
            return Result<bool>::fail("sanitize did not finish within 24 hours");
        }
        const auto st = ata_sanitize_status(t.fd());
        if (!st) {
            if (++status_errors >= kMaxStatusErrors) return Result<bool>::fail(st.error());
            continue;
        }
        status_errors = 0;
        if (st->in_progress) {
            report(job, st->progress, 65536);
            continue;
        }
        if (st->failed || !st->completed_ok) {
            // FAILURE MODE was set: CLEAR lets the drive leave the failed state.
            ata_sanitize_status(t.fd(), /*clear_failure=*/true);
            return Result<bool>::fail("drive reports the sanitize operation failed");
        }
        report(job, 1, 1);
        return Result<bool>::ok(true);
    }
}

void run_firmware(const EraseJob& job, CertificateInput& in) {
    auto& rec = in.sanitization;
    if (support(job.method) == Support::NotImplemented) {
        rec.error = to_string(job.method) + " is not implemented yet";
        return;
    }
    if (support(job.method) == Support::Experimental && !job.allow_experimental) {
        rec.error = to_string(job.method) + " is experimental (not yet validated on real hardware); "
                    "it needs an explicit opt-in";
        return;
    }
    const bool ata_bus = in.device.bus == Bus::Sata || in.device.bus == Bus::Usb || in.device.bus == Bus::Scsi;
    if ((is_nvme_method(job.method) && in.device.bus != Bus::Nvme) || (is_ata_method(job.method) && !ata_bus)) {
        rec.error = to_string(job.method) + " does not apply to a " + to_string(in.device.bus) + " device";
        return;
    }

    // The callers only check the chosen namespace, so look at the others right before starting.
    if (is_nvme_method(job.method)) {
        const auto raw = nvme_identify_ctrl_raw(job.target_path);
        const auto id = raw ? parse_nvme_identify_ctrl(raw.value()) : Result<NvmeIdentify>::fail(raw.error());
        if (!id) {
            rec.error = "cannot tell what this erase would reach: " + id.error();
            return;
        }
        if (is_controller_wide(job.method, id.value())) {
            if (const auto busy = sibling_blockers(in.device); !busy.empty()) {
                rec.error = to_string(job.method) + " would also erase " + busy.front();
                return;
            }
        }
    }

    const auto target = Target::open(job.target_path, Target::Mode::Write);
    if (!target) {
        rec.error = target.error();
        return;
    }
    const auto& t = *target.value();
    if (in.device.size_bytes == 0) in.device.size_bytes = t.size();

    const auto plan = make_plan(t, job);
    const auto canary = plant_canaries(t, plan);
    if (!canary) {
        rec.error = "could not plant verification canaries: " + canary.error();
        return;
    }

    if (auto r = is_ata_method(job.method) ? run_ata(t, job) : run_nvme(t, job); !r) {
        rec.error = r.error();
        return;
    }
    rec.completed = true;
    rec.finished_at = utc_now_iso8601();

    // The partition table is gone; let the kernel know (best effort).
    ::ioctl(t.fd(), BLKRRPART);
    in.verification = verify_canaries_gone(t, plan, canary.value());
}

void run_overwrite(const EraseJob& job, CertificateInput& in) {
    auto& rec = in.sanitization;
    const auto target = Target::open(job.target_path, Target::Mode::Write);
    if (!target) {
        rec.error = target.error();
        return;
    }
    const auto& t = *target.value();
    if (in.device.size_bytes == 0) in.device.size_bytes = t.size();

    rec.pattern = to_string(job.pattern);
    OverwriteOptions opts;
    opts.pattern = job.pattern;
    opts.progress = job.progress;
    const auto ow = overwrite(t, opts);
    if (!ow) {
        rec.error = ow.error();
        return;
    }
    rec.bytes_written = ow->bytes_written;
    rec.completed = true;
    rec.finished_at = utc_now_iso8601();
    in.verification = verify_pattern(t, make_plan(t, job), ow->expected);
}

}  // namespace

CertificateInput run_erase(const EraseJob& job) {
    CertificateInput in;
    in.device = job.device;
    auto& rec = in.sanitization;
    rec.method = job.method;
    rec.level = nominal_level(job.method, !in.device.rotational);
    rec.started_at = utc_now_iso8601();

    // Any unexpected failure in a method ends up as a failed record, never as an
    // exception escaping into the UI.
    try {
        if (job.method == Method::Overwrite) run_overwrite(job, in);
        else run_firmware(job, in);
    } catch (const std::exception& e) {
        rec.completed = false;
        rec.error = std::string("internal error: ") + e.what();
    } catch (...) {
        rec.completed = false;
        rec.error = "internal error";
    }

    if (rec.finished_at.empty()) rec.finished_at = utc_now_iso8601();
    return in;
}

}  // namespace pm

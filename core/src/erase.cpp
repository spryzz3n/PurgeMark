#include "zt/erase.hpp"

#include <linux/fs.h>
#include <sys/ioctl.h>

#include <chrono>
#include <cstring>
#include <thread>

#include "zt/blockio.hpp"
#include "zt/crypto.hpp"
#include "zt/nvme.hpp"

namespace zt {

namespace {

SamplePlan make_plan(const Target& t, const EraseJob& job) {
    std::uint64_t seed = 0;
    const auto seed_bytes = random_bytes(sizeof seed);
    std::memcpy(&seed, seed_bytes.data(), sizeof seed);
    return plan_samples(t.size(), t.logical_block_size(), job.sample_bytes, job.verify_samples, seed);
}

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
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        const auto st = nvme_sanitize_status(t.fd());
        if (!st) return Result<bool>::fail(st.error());
        if (!st->done()) {
            report(job, st->progress, 65536);
            continue;
        }
        if (!st->succeeded()) return Result<bool>::fail("drive reports the sanitize operation failed");
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
    if (!is_nvme_method(job.method) || in.device.bus != Bus::Nvme) {
        rec.error = to_string(job.method) + " does not apply to a " + to_string(in.device.bus) + " device";
        return;
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

    if (auto r = run_nvme(t, job); !r) {
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

    if (job.method == Method::Overwrite) run_overwrite(job, in);
    else run_firmware(job, in);

    if (rec.finished_at.empty()) rec.finished_at = utc_now_iso8601();
    return in;
}

}  // namespace zt

// Overwrite, verification, and the full erase-to-certificate path on image files.

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "check.hpp"
#include "pm/blockio.hpp"
#include "pm/certificate.hpp"
#include "pm/erase.hpp"
#include "pm/overwrite.hpp"
#include "pm/verify.hpp"

namespace fs = std::filesystem;

// An image whose size is a multiple of 512 but not of 4096 or the 8 MiB chunk,
// so the tail paths get exercised.
constexpr std::uint64_t kImageSize = (8u << 20) + 3 * 512;

static fs::path make_image(const fs::path& dir, const std::string& name) {
    const fs::path p = dir / name;
    std::ofstream out(p, std::ios::binary);
    const std::string secret = "TOP SECRET payroll 2025 ";
    for (std::uint64_t i = 0; i < kImageSize; ++i) out.put(secret[i % secret.size()]);
    return p;
}

static std::shared_ptr<pm::Target> open_target(const fs::path& p, pm::Target::Mode m) {
    auto t = pm::Target::open(p.string(), m);
    CHECK(static_cast<bool>(t));
    return t ? t.value() : nullptr;
}

static void test_sample_plan() {
    const auto plan = pm::plan_samples(kImageSize, 512, 64 << 10, 200, 42);
    CHECK(plan.sample_bytes == (64u << 10));
    CHECK(plan.offsets.front() == 0);
    CHECK(plan.offsets.back() + plan.sample_bytes <= kImageSize);
    CHECK(plan.offsets.back() + plan.sample_bytes > kImageSize - 512);  // reaches the tail
    CHECK(std::is_sorted(plan.offsets.begin(), plan.offsets.end()));
    CHECK(std::all_of(plan.offsets.begin(), plan.offsets.end(), [](std::uint64_t o) { return o % 512 == 0; }));
    // Apart from the end-anchored last sample, samples never overlap.
    for (std::size_t i = 1; i + 1 < plan.offsets.size(); ++i) {
        CHECK(plan.offsets[i] - plan.offsets[i - 1] >= plan.sample_bytes);
    }
    CHECK(pm::plan_samples(kImageSize, 512, 64 << 10, 200, 42).offsets == plan.offsets);  // reproducible

    const auto tiny = pm::plan_samples(1024, 512, 64 << 10, 10, 1);
    CHECK(tiny.sample_bytes == 1024 && tiny.offsets.size() == 1);
    CHECK(pm::plan_samples(100, 512, 4096, 10, 1).offsets.empty());
}

static void test_overwrite_and_verify(const fs::path& dir) {
    for (const auto pattern : {pm::Pattern::Random, pm::Pattern::Zero}) {
        const auto img = make_image(dir, "ow.img");
        auto t = open_target(img, pm::Target::Mode::Write);
        if (!t) return;
        const auto plan = pm::plan_samples(t->size(), 512, 64 << 10, 100, 7);
        const auto before = pm::fingerprint(*t, plan);
        CHECK(before && std::none_of(before->begin(), before->end(), [](const auto& f) { return f.uniform; }));

        pm::OverwriteOptions opts;
        opts.pattern = pattern;
        std::uint64_t last = 0;
        opts.progress = [&](std::uint64_t done, std::uint64_t) {
            CHECK(done > last);
            last = done;
            return true;
        };
        const auto ow = pm::overwrite(*t, opts);
        CHECK(ow && ow->bytes_written == kImageSize && last == kImageSize);
        if (!ow) return;

        const auto vp = pm::verify_pattern(*t, plan, ow->expected);
        CHECK(vp.passed() && vp.samples == plan.offsets.size() && vp.mismatches == 0);

        const auto vc = pm::verify_changed(*t, plan, before.value());
        CHECK(vc.passed() && vc.skipped == 0);

        // Plant old data back in a sampled region: both checks must catch it.
        const std::uint64_t victim = plan.offsets[plan.offsets.size() / 2];
        std::vector<std::uint8_t> secret(512, 'S');
        CHECK(static_cast<bool>(t->write_at(victim, secret)));
        const auto bad = pm::verify_pattern(*t, plan, ow->expected);
        CHECK(!bad.passed() && bad.mismatches == 1 && bad.first_mismatch == victim);

        // Content a zero overwrite leaves behind is uniform; "changed" mode can't judge it.
        if (pattern == pm::Pattern::Zero) {
            const auto after_zero = pm::fingerprint(*t, plan);
            const auto vz = pm::verify_changed(*t, plan, after_zero.value());
            CHECK(vz.skipped > 0);
        }
        fs::remove(img);
    }
}

static void test_unchanged_is_detected(const fs::path& dir) {
    const auto img = make_image(dir, "same.img");
    auto t = open_target(img, pm::Target::Mode::Read);
    if (!t) return;
    const auto plan = pm::plan_samples(t->size(), 512, 4096, 50, 9);
    const auto before = pm::fingerprint(*t, plan);
    const auto vc = pm::verify_changed(*t, plan, before.value());  // "erase" that did nothing
    CHECK(!vc.passed() && vc.mismatches == vc.samples);

    const auto blank = dir / "blank.img";
    std::ofstream(blank, std::ios::binary).write(std::string(1 << 20, '\0').data(), 1 << 20);
    auto bt = open_target(blank, pm::Target::Mode::Read);
    const auto bplan = pm::plan_samples(bt->size(), 512, 4096, 20, 9);
    const auto bv = pm::verify_changed(*bt, bplan, pm::fingerprint(*bt, bplan).value());
    CHECK(bv.inconclusive && !bv.passed());  // never-written drive: nothing to compare
}

// The firmware-method check: canaries planted before the erase must all be gone after.
static void test_canaries(const fs::path& dir) {
    const auto img = make_image(dir, "canary.img");
    auto t = open_target(img, pm::Target::Mode::Write);
    if (!t) return;
    const auto plan = pm::plan_samples(t->size(), 512, 64 << 10, 50, 3);
    const auto canary = pm::plant_canaries(*t, plan);
    CHECK(static_cast<bool>(canary));
    if (!canary) return;

    // Firmware that "succeeds" without erasing: every canary survives.
    auto r = pm::verify_canaries_gone(*t, plan, canary.value());
    CHECK(!r.passed() && r.mismatches == r.samples && r.mode == "canary");

    // A real erase (simulated by zeroing the image): conclusive pass, even though
    // zeros are uniform and would be inconclusive for verify_changed().
    pm::OverwriteOptions zero;
    zero.pattern = pm::Pattern::Zero;
    CHECK(static_cast<bool>(pm::overwrite(*t, zero)));
    r = pm::verify_canaries_gone(*t, plan, canary.value());
    CHECK(r.passed() && r.samples == plan.offsets.size());

    // One region the "firmware" missed: caught, at sector granularity.
    std::vector<std::uint8_t> survivor(512);
    const std::uint64_t victim = plan.offsets[plan.offsets.size() / 3] + 1024;
    canary.value()(victim, survivor);
    CHECK(static_cast<bool>(t->write_at(victim, survivor)));
    r = pm::verify_canaries_gone(*t, plan, canary.value());
    CHECK(!r.passed() && r.mismatches == 1 && r.first_mismatch == victim);
}

static void test_cancel(const fs::path& dir) {
    const auto img = make_image(dir, "cancel.img");
    auto t = open_target(img, pm::Target::Mode::Write);
    if (!t) return;
    pm::OverwriteOptions opts;
    opts.chunk_bytes = 1 << 20;
    opts.progress = [](std::uint64_t done, std::uint64_t) { return done < (3u << 20); };
    const auto ow = pm::overwrite(*t, opts);
    CHECK(!ow && ow.error().find("cancelled") != std::string::npos);
}

static void test_run_erase_to_certificate(const fs::path& dir) {
    const auto img = make_image(dir, "full.img");
    pm::EraseJob job;
    job.target_path = img.string();
    job.device.model = "disk image";
    job.device.serial = "image:full.img";
    job.verify_samples = 64;

    const auto in = pm::run_erase(job);
    CHECK(in.sanitization.completed && in.sanitization.error.empty());
    CHECK(in.verification.passed());
    CHECK(in.device.size_bytes == kImageSize);

    const auto key = pm::SigningKey::generate();
    const auto cert = pm::sign_certificate(pm::make_certificate_body(in), key, pm::Attestation::OperatorKey);
    CHECK(cert && cert->at("result") == "sanitized");
    CHECK(pm::verify_certificate(cert.value(), key.public_raw()).trusted);

    // Experimental method without opt-in, unimplemented method, and a firmware
    // method on a non-NVMe target: all recorded as failures, never as success.
    for (const auto m : {pm::Method::NvmeSanitizeCrypto, pm::Method::AtaSecurityErase, pm::Method::NvmeFormatCrypto}) {
        job.method = m;
        const auto nope = pm::run_erase(job);
        CHECK(!nope.sanitization.completed && !nope.sanitization.error.empty());
        CHECK(pm::make_certificate_body(nope)["result"] == "failed");
    }
    CHECK(pm::run_erase(job).sanitization.level == pm::Level::Purge);  // level comes from the core, not the caller

    // Untested methods with the opt-in still fail cleanly on a target they don't
    // apply to, before touching it, and the image is left intact for other methods.
    job.allow_experimental = true;
    for (const auto m : {pm::Method::AtaSanitizeCrypto, pm::Method::AtaSanitizeOverwrite, pm::Method::NvmeSanitizeBlock}) {
        job.method = m;
        const auto r = pm::run_erase(job);
        CHECK(!r.sanitization.completed && r.sanitization.error.find("does not apply") != std::string::npos);
    }
    job.method = pm::Method::Overwrite;
    CHECK(pm::run_erase(job).verification.passed());  // overwrite still works afterwards

    job.method = pm::Method::Overwrite;
    job.target_path = (dir / "missing.img").string();
    const auto missing = pm::run_erase(job);
    CHECK(!missing.sanitization.completed && pm::make_certificate_body(missing)["result"] == "failed");
}

int main() {
    const fs::path dir = fs::temp_directory_path() / "pm-test-erase";
    fs::remove_all(dir);
    fs::create_directories(dir);

    test_sample_plan();
    test_overwrite_and_verify(dir);
    test_unchanged_is_detected(dir);
    test_canaries(dir);
    test_cancel(dir);
    test_run_erase_to_certificate(dir);

    fs::remove_all(dir);
    return finish("erase");
}

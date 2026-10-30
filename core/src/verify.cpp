#include "zt/verify.hpp"

#include <algorithm>
#include <cstring>
#include <random>

namespace zt {

namespace {

std::uint32_t sample_len(const Target& t, const SamplePlan& plan, std::uint64_t offset) {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(plan.sample_bytes, t.size() - offset));
}

bool is_uniform(std::span<const std::uint8_t> s) {
    return std::all_of(s.begin(), s.end(), [&](std::uint8_t b) { return b == s.front(); });
}

}  // namespace

SamplePlan plan_samples(std::uint64_t target_size, std::uint32_t alignment, std::uint32_t sample_bytes,
                        std::uint32_t count, std::uint64_t seed) {
    SamplePlan plan;
    plan.seed = seed;
    if (alignment == 0) alignment = 512;
    // Clamp the sample to the target and keep it a whole number of blocks (O_DIRECT).
    const std::uint64_t max_len = target_size / alignment * alignment;
    plan.sample_bytes = static_cast<std::uint32_t>(std::min<std::uint64_t>(sample_bytes / alignment * alignment, max_len));
    if (plan.sample_bytes == 0) return plan;

    const std::uint64_t last = (target_size - plan.sample_bytes) / alignment * alignment;
    plan.offsets = {0, last};
    // Random samples sit on a grid of whole sample-sized slots, so they never
    // partially overlap (which would waste coverage and double-count findings).
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<std::uint64_t> dist(0, last / plan.sample_bytes);
    for (std::uint32_t i = 0; i < count; ++i) plan.offsets.push_back(dist(rng) * plan.sample_bytes);

    std::sort(plan.offsets.begin(), plan.offsets.end());
    plan.offsets.erase(std::unique(plan.offsets.begin(), plan.offsets.end()), plan.offsets.end());
    return plan;
}

VerifyReport verify_pattern(const Target& target, const SamplePlan& plan, const ExpectedContent& expected) {
    VerifyReport r;
    r.mode = "pattern";
    r.seed = plan.seed;
    r.sample_bytes = plan.sample_bytes;
    target.drop_cache();

    AlignedBuffer actual(plan.sample_bytes);
    std::vector<std::uint8_t> want(plan.sample_bytes);
    for (const auto off : plan.offsets) {
        const std::uint32_t len = sample_len(target, plan, off);
        auto got = actual.span().first(len);
        if (auto rd = target.read_at(off, got); !rd) {
            r.error = rd.error();
            return r;
        }
        expected(off, std::span(want).first(len));
        ++r.samples;
        r.bytes_checked += len;
        if (std::memcmp(got.data(), want.data(), len) != 0) {
            ++r.mismatches;
            if (!r.first_mismatch) r.first_mismatch = off;
        }
    }
    return r;
}

Result<ExpectedContent> plant_canaries(const Target& target, const SamplePlan& plan) {
    using R = Result<ExpectedContent>;
    ExpectedContent canary = [ks = Keystream::random()](std::uint64_t off, std::span<std::uint8_t> out) {
        ks.fill(off, out);
    };
    AlignedBuffer buf(plan.sample_bytes);
    for (const auto off : plan.offsets) {
        auto s = buf.span().first(sample_len(target, plan, off));
        canary(off, s);
        if (auto w = target.write_at(off, s); !w) return R::fail(w.error());
    }
    if (auto s = target.sync(); !s) return R::fail(s.error());
    return R::ok(std::move(canary));
}

VerifyReport verify_canaries_gone(const Target& target, const SamplePlan& plan, const ExpectedContent& canary) {
    VerifyReport r;
    r.mode = "canary";
    r.seed = plan.seed;
    r.sample_bytes = plan.sample_bytes;
    target.drop_cache();

    AlignedBuffer actual(plan.sample_bytes);
    std::vector<std::uint8_t> planted(plan.sample_bytes);
    for (const auto off : plan.offsets) {
        const std::uint32_t len = sample_len(target, plan, off);
        auto got = actual.span().first(len);
        if (auto rd = target.read_at(off, got); !rd) {
            r.error = rd.error();
            return r;
        }
        canary(off, std::span(planted).first(len));
        ++r.samples;
        r.bytes_checked += len;
        // Any surviving 512-byte sector of the canary means that region wasn't erased.
        for (std::uint32_t pos = 0; pos + 512 <= len; pos += 512) {
            if (std::memcmp(got.data() + pos, planted.data() + pos, 512) == 0) {
                ++r.mismatches;
                if (!r.first_mismatch) r.first_mismatch = off + pos;
                break;
            }
        }
    }
    return r;
}

Result<std::vector<Fingerprint>> fingerprint(const Target& target, const SamplePlan& plan) {
    using R = Result<std::vector<Fingerprint>>;
    target.drop_cache();
    AlignedBuffer buf(plan.sample_bytes);
    std::vector<Fingerprint> out;
    out.reserve(plan.offsets.size());
    for (const auto off : plan.offsets) {
        auto s = buf.span().first(sample_len(target, plan, off));
        if (auto rd = target.read_at(off, s); !rd) return R::fail(rd.error());
        out.push_back({sha256(s), is_uniform(s)});
    }
    return R::ok(std::move(out));
}

VerifyReport verify_changed(const Target& target, const SamplePlan& plan, const std::vector<Fingerprint>& before) {
    VerifyReport r;
    r.mode = "changed";
    r.seed = plan.seed;
    r.sample_bytes = plan.sample_bytes;
    if (before.size() != plan.offsets.size()) {
        r.error = "fingerprint count does not match sample plan";
        return r;
    }
    const auto after = fingerprint(target, plan);
    if (!after) {
        r.error = after.error();
        return r;
    }
    for (std::size_t i = 0; i < before.size(); ++i) {
        if (before[i].uniform) {
            ++r.skipped;
            continue;
        }
        ++r.samples;
        r.bytes_checked += sample_len(target, plan, plan.offsets[i]);
        if (after.value()[i].digest == before[i].digest) {
            ++r.mismatches;
            if (!r.first_mismatch) r.first_mismatch = plan.offsets[i];
        }
    }
    r.inconclusive = r.samples == 0;
    return r;
}

}  // namespace zt

#include "zt/erase.hpp"

#include <cstring>

#include "zt/blockio.hpp"
#include "zt/crypto.hpp"

namespace zt {

CertificateInput run_erase(const EraseJob& job) {
    CertificateInput in;
    in.device = job.device;
    auto& rec = in.sanitization;
    rec.method = job.method;
    rec.level = Level::Clear;
    rec.started_at = utc_now_iso8601();
    auto finish = [&](std::string error) {
        rec.error = std::move(error);
        rec.finished_at = utc_now_iso8601();
        return in;
    };

    if (job.method != Method::Overwrite) return finish(to_string(job.method) + " is not implemented yet");

    const auto target = Target::open(job.target_path, Target::Mode::Write);
    if (!target) return finish(target.error());
    const auto& t = *target.value();
    if (in.device.size_bytes == 0) in.device.size_bytes = t.size();

    rec.pattern = to_string(job.pattern);
    OverwriteOptions opts;
    opts.pattern = job.pattern;
    opts.progress = job.progress;
    const auto ow = overwrite(t, opts);
    if (!ow) return finish(ow.error());
    rec.bytes_written = ow->bytes_written;
    rec.completed = true;
    rec.finished_at = utc_now_iso8601();

    std::uint64_t seed = 0;
    const auto seed_bytes = random_bytes(sizeof seed);
    std::memcpy(&seed, seed_bytes.data(), sizeof seed);
    const auto plan = plan_samples(t.size(), t.logical_block_size(), job.sample_bytes, job.verify_samples, seed);
    in.verification = verify_pattern(t, plan, ow->expected);
    return in;
}

}  // namespace zt

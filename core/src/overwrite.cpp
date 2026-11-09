#include "pm/overwrite.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#include "pm/crypto.hpp"

namespace pm {

std::string to_string(Pattern p) { return p == Pattern::Zero ? "zeros" : "random (AES-256-CTR keystream)"; }

Result<OverwriteOutcome> overwrite(const Target& target, const OverwriteOptions& options) {
    using R = Result<OverwriteOutcome>;
    const auto start = std::chrono::steady_clock::now();

    // Random data defeats controllers that compress or deduplicate zeros.
    ExpectedContent expected;
    if (options.pattern == Pattern::Random) {
        expected = [ks = Keystream::random()](std::uint64_t off, std::span<std::uint8_t> out) { ks.fill(off, out); };
    } else {
        expected = [](std::uint64_t, std::span<std::uint8_t> out) { std::memset(out.data(), 0, out.size()); };
    }

    // Chunks stay a multiple of the logical block size so O_DIRECT accepts them.
    const std::size_t lbs = target.logical_block_size();
    const std::size_t chunk = std::max(lbs, options.chunk_bytes / lbs * lbs);
    AlignedBuffer buf(chunk);
    const std::uint64_t total = target.size();

    std::uint64_t done = 0;
    while (done < total) {
        const auto len = static_cast<std::size_t>(std::min<std::uint64_t>(chunk, total - done));
        auto piece = buf.span().first(len);
        expected(done, piece);
        if (auto w = target.write_at(done, piece); !w) return R::fail(w.error());
        done += len;
        if (options.progress && !options.progress(done, total)) {
            target.sync();
            return R::fail("cancelled after " + std::to_string(done) + " of " + std::to_string(total) + " bytes");
        }
    }
    if (auto s = target.sync(); !s) return R::fail(s.error());

    OverwriteOutcome out;
    out.bytes_written = done;
    out.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    out.expected = std::move(expected);
    return R::ok(std::move(out));
}

}  // namespace pm

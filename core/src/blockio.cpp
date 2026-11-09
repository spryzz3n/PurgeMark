#include "pm/blockio.hpp"

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <new>

namespace pm {

namespace {

std::string errno_msg(const std::string& what) { return what + ": " + std::strerror(errno); }

}  // namespace

Result<std::shared_ptr<Target>> Target::open(const std::string& path, Mode mode) {
    using R = Result<std::shared_ptr<Target>>;
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return R::fail(errno_msg("stat " + path));
    const bool block = S_ISBLK(st.st_mode);
    if (!block && !S_ISREG(st.st_mode)) return R::fail(path + " is neither a block device nor a regular file");

    int flags = O_CLOEXEC | (mode == Mode::Write ? O_RDWR : O_RDONLY);
    if (block && mode == Mode::Write) flags |= O_EXCL;

    // Block devices use O_DIRECT so verification reads hit the media, not the
    // page cache. Image files (tests) use cache dropping instead, since O_DIRECT
    // support and alignment rules vary by filesystem.
    int fd = ::open(path.c_str(), block ? flags | O_DIRECT : flags);
    bool direct = block && fd >= 0;
    if (fd < 0 && block && errno == EINVAL) fd = ::open(path.c_str(), flags);
    if (fd < 0) {
        if (errno == EBUSY) return R::fail(path + " is in use (mounted, swap, or held by dm/md); refusing");
        return R::fail(errno_msg("open " + path));
    }

    std::shared_ptr<Target> t(new Target());
    t->path_ = path;
    t->fd_ = fd;
    t->block_ = block;
    t->direct_ = direct;
    if (block) {
        std::uint64_t bytes = 0;
        if (::ioctl(fd, BLKGETSIZE64, &bytes) != 0) return R::fail(errno_msg("BLKGETSIZE64 " + path));
        t->size_ = bytes;
        int lbs = 0;
        if (::ioctl(fd, BLKSSZGET, &lbs) == 0 && lbs > 0) t->logical_block_ = static_cast<std::uint32_t>(lbs);
    } else {
        t->size_ = static_cast<std::uint64_t>(st.st_size);
    }
    return R::ok(std::move(t));
}

Target::~Target() {
    if (fd_ >= 0) ::close(fd_);
}

Result<bool> Target::read_at(std::uint64_t offset, std::span<std::uint8_t> buf) const {
    std::size_t done = 0;
    while (done < buf.size()) {
        const ssize_t n = ::pread(fd_, buf.data() + done, buf.size() - done, static_cast<off_t>(offset + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return Result<bool>::fail(errno_msg("read at offset " + std::to_string(offset + done)));
        }
        if (n == 0) return Result<bool>::fail("unexpected end of device at offset " + std::to_string(offset + done));
        done += static_cast<std::size_t>(n);
    }
    return Result<bool>::ok(true);
}

Result<bool> Target::write_at(std::uint64_t offset, std::span<const std::uint8_t> buf) const {
    std::size_t done = 0;
    while (done < buf.size()) {
        const ssize_t n = ::pwrite(fd_, buf.data() + done, buf.size() - done, static_cast<off_t>(offset + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return Result<bool>::fail(errno_msg("write at offset " + std::to_string(offset + done)));
        }
        done += static_cast<std::size_t>(n);
    }
    return Result<bool>::ok(true);
}

Result<bool> Target::sync() const {
    if (::fdatasync(fd_) != 0) return Result<bool>::fail(errno_msg("fdatasync " + path_));
    return Result<bool>::ok(true);
}

void Target::drop_cache() const {
    if (block_) ::ioctl(fd_, BLKFLSBUF, 0);
    ::posix_fadvise(fd_, 0, 0, POSIX_FADV_DONTNEED);
}

AlignedBuffer::AlignedBuffer(std::size_t size) : size_(size) {
    const std::size_t rounded = (size + kAlignment - 1) / kAlignment * kAlignment;
    auto* p = static_cast<std::uint8_t*>(std::aligned_alloc(kAlignment, rounded == 0 ? kAlignment : rounded));
    if (!p) throw std::bad_alloc();
    data_.reset(p);
}

void AlignedBuffer::Free::operator()(std::uint8_t* p) const { std::free(p); }

}  // namespace pm

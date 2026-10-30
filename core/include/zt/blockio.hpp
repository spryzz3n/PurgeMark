#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "zt/result.hpp"

namespace zt {

// An erase/verify target: a whole block device, or a regular file (image files
// in tests and dry runs). Block devices are opened with O_EXCL, which the
// kernel refuses while anything (a mount, dm, md, swap) still holds the disk.
class Target {
public:
    enum class Mode { Read, Write };

    static Result<std::shared_ptr<Target>> open(const std::string& path, Mode mode);
    ~Target();
    Target(const Target&) = delete;
    Target& operator=(const Target&) = delete;

    const std::string& path() const { return path_; }
    std::uint64_t size() const { return size_; }
    bool is_block_device() const { return block_; }
    bool direct_io() const { return direct_; }  // reads bypass the page cache
    // O_DIRECT offsets and lengths must be multiples of this. Device sizes always are.
    std::uint32_t logical_block_size() const { return logical_block_; }

    // Full-length positional I/O; retries short transfers and EINTR.
    Result<bool> read_at(std::uint64_t offset, std::span<std::uint8_t> buf) const;
    Result<bool> write_at(std::uint64_t offset, std::span<const std::uint8_t> buf) const;
    Result<bool> sync() const;
    // Drops cached pages so later reads come from the media.
    void drop_cache() const;
    // The underlying descriptor, for device commands (ioctls) issued while the
    // exclusive open keeps everything else off the disk.
    int fd() const { return fd_; }

private:
    Target() = default;
    std::string path_;
    int fd_ = -1;
    std::uint64_t size_ = 0;
    bool block_ = false;
    bool direct_ = false;
    std::uint32_t logical_block_ = 512;
};

// Page-aligned heap buffer, as required by O_DIRECT.
class AlignedBuffer {
public:
    static constexpr std::size_t kAlignment = 4096;
    explicit AlignedBuffer(std::size_t size);
    std::span<std::uint8_t> span() { return {data_.get(), size_}; }
    std::span<const std::uint8_t> span() const { return {data_.get(), size_}; }
    std::size_t size() const { return size_; }

private:
    struct Free {
        void operator()(std::uint8_t* p) const;
    };
    std::unique_ptr<std::uint8_t, Free> data_;
    std::size_t size_;
};

}  // namespace zt

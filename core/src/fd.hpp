#pragma once

#include <unistd.h>

namespace zt {

// Owning file descriptor; closes on scope exit.
class Fd {
public:
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd() {
        if (fd_ >= 0) ::close(fd_);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    explicit operator bool() const { return fd_ >= 0; }
    int get() const { return fd_; }

private:
    int fd_;
};

}  // namespace zt

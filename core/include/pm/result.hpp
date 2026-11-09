#pragma once

#include <optional>
#include <string>
#include <utility>

namespace pm {

// Minimal value-or-error type (std::expected needs C++23).
template <class T>
class Result {
public:
    static Result ok(T value) {
        Result r;
        r.value_ = std::move(value);
        return r;
    }
    static Result fail(std::string error) {
        Result r;
        r.error_ = std::move(error);
        return r;
    }

    explicit operator bool() const { return value_.has_value(); }
    const T& value() const { return *value_; }
    const T* operator->() const { return &*value_; }
    const std::string& error() const { return error_; }

private:
    Result() = default;
    std::optional<T> value_;
    std::string error_;
};

}  // namespace pm

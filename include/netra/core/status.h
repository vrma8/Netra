// SPDX-License-Identifier: MIT
// Netra - network reconnaissance & packet analysis toolkit
//
// core/status.h : lightweight error handling primitives.
#pragma once

#include <optional>
#include <string>
#include <utility>

namespace netra {

enum class StatusCode {
    Ok,
    InvalidArgument,
    NotFound,
    PermissionDenied,
    Unsupported,
    IoError,
    Timeout,
    Unavailable,
    AlreadyExists,
    Cancelled,
    Internal,
};

const char* statusCodeName(StatusCode code);

/// Non-throwing result of an operation.
class Status {
public:
    Status() = default;
    Status(StatusCode code, std::string message) : code_(code), message_(std::move(message)) {}

    static Status success() { return Status(); }
    static Status invalidArgument(std::string m) { return Status(StatusCode::InvalidArgument, std::move(m)); }
    static Status notFound(std::string m) { return Status(StatusCode::NotFound, std::move(m)); }
    static Status permissionDenied(std::string m) { return Status(StatusCode::PermissionDenied, std::move(m)); }
    static Status unsupported(std::string m) { return Status(StatusCode::Unsupported, std::move(m)); }
    static Status ioError(std::string m) { return Status(StatusCode::IoError, std::move(m)); }
    static Status timeout(std::string m) { return Status(StatusCode::Timeout, std::move(m)); }
    static Status unavailable(std::string m) { return Status(StatusCode::Unavailable, std::move(m)); }
    static Status cancelled(std::string m = "operation cancelled") { return Status(StatusCode::Cancelled, std::move(m)); }
    static Status internal(std::string m) { return Status(StatusCode::Internal, std::move(m)); }

    bool ok() const { return code_ == StatusCode::Ok; }
    explicit operator bool() const { return ok(); }

    StatusCode code() const { return code_; }
    const std::string& message() const { return message_; }

    std::string toString() const {
        return ok() ? std::string("ok") : std::string(statusCodeName(code_)) + ": " + message_;
    }

private:
    StatusCode code_{StatusCode::Ok};
    std::string message_;
};

/// Result<T> holds either a value or an error status.
template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), status_(Status::success()) {}  // NOLINT(google-explicit-constructor)
    Result(Status status) : status_(std::move(status)) {}                 // NOLINT(google-explicit-constructor)

    bool ok() const { return status_.ok(); }
    explicit operator bool() const { return ok(); }

    const T& value() const& { return *value_; }
    T& value() & { return *value_; }
    T&& value() && { return std::move(*value_); }

    const Status& status() const { return status_; }
    std::string message() const { return status_.toString(); }

    const T& operator*() const& { return *value_; }
    T& operator*() & { return *value_; }
    const T* operator->() const { return &*value_; }
    T* operator->() { return &*value_; }

    /// Value or fallback; useful for best-effort paths.
    T valueOr(T fallback) const { return value_ ? *value_ : std::move(fallback); }

private:
    std::optional<T> value_;
    Status status_;
};

}  // namespace netra

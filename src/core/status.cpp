// SPDX-License-Identifier: MIT
#include "netra/core/status.h"

namespace netra {

const char* statusCodeName(StatusCode code) {
    switch (code) {
        case StatusCode::Ok: return "ok";
        case StatusCode::InvalidArgument: return "invalid argument";
        case StatusCode::NotFound: return "not found";
        case StatusCode::PermissionDenied: return "permission denied";
        case StatusCode::Unsupported: return "unsupported";
        case StatusCode::IoError: return "I/O error";
        case StatusCode::Timeout: return "timeout";
        case StatusCode::Unavailable: return "unavailable";
        case StatusCode::AlreadyExists: return "already exists";
        case StatusCode::Cancelled: return "cancelled";
        case StatusCode::Internal: return "internal error";
    }
    return "unknown";
}

}  // namespace netra

// SPDX-License-Identifier: MIT
// core/poll_compat.h : poll(2) everywhere — WSAPoll on Windows.
//
// The scanner and the discovery engine drive many sockets through a single
// poll set. POSIX provides `poll(2)`; Windows provides `WSAPoll` with the same
// `struct pollfd` layout, so a thin inline wrapper keeps the call sites clean.
#pragma once

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#endif

namespace netra::compat {

/// Polls `count` sockets, waiting at most `timeoutMs` (-1 = block).
/// Returns the number of ready sockets, 0 on timeout and -1 on error.
inline int pollSockets(struct pollfd* fds, int count, int timeoutMs) {
#if defined(_WIN32)
    return ::WSAPoll(fds, static_cast<u_long>(count), timeoutMs);
#else
    return ::poll(fds, static_cast<nfds_t>(count), timeoutMs);
#endif
}

}  // namespace netra::compat

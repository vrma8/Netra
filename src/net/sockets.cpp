// SPDX-License-Identifier: MIT
#include "netra/net/sockets.h"

#include <cerrno>
#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif
#endif

#include <algorithm>
#include <chrono>
#include <thread>
#include <vector>

#include "netra/core/log.h"
#include "netra/core/util.h"

namespace netra::net {
namespace {

/// recvfrom()/sendto() take the buffer length as size_t on POSIX and int on Windows.
#if defined(_WIN32)
inline int socketLength(size_t bytes) { return static_cast<int>(bytes); }
#else
inline size_t socketLength(size_t bytes) { return bytes; }
#endif

#if defined(_WIN32)
struct WinsockInit {
    WinsockInit() {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
    }
};
WinsockInit g_winsockInit;
#endif

}  // namespace

void socketSubsystemInit() {
#if defined(_WIN32)
    (void)g_winsockInit;
#endif
}

int socketErrorCode() {
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string socketError() {
#if defined(_WIN32)
    wchar_t* buffer = nullptr;
    const int code = WSAGetLastError();
    const DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                        FORMAT_MESSAGE_IGNORE_INSERTS,
                                    nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::string message = len ? std::string(buffer, buffer + len) : ("error " + std::to_string(code));
    if (buffer) LocalFree(buffer);
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) message.pop_back();
    return message;
#else
    const int code = errno;
    return std::string(strerror(code)) + " (" + std::to_string(code) + ")";
#endif
}

bool isTransientError(int code) {
#if defined(_WIN32)
    return code == WSAEWOULDBLOCK || code == WSAEINTR || code == WSAENOBUFS;
#else
    return code == EAGAIN || code == EWOULDBLOCK || code == EINTR || code == ENOBUFS;
#endif
}

bool isConnectionRefused(int code) {
#if defined(_WIN32)
    return code == WSAECONNREFUSED;
#else
    return code == ECONNREFUSED;
#endif
}

bool isInProgress(int code) {
#if defined(_WIN32)
    return code == WSAEINPROGRESS || code == WSAEWOULDBLOCK;
#else
    return code == EINPROGRESS;
#endif
}

void closeSocket(socket_t fd) {
    if (fd == kInvalidSocket) return;
#if defined(_WIN32)
    ::closesocket(fd);
#else
    ::close(fd);
#endif
}

Status setNonBlocking(socket_t fd, bool enabled) {
#if defined(_WIN32)
    u_long mode = enabled ? 1 : 0;
    if (::ioctlsocket(fd, FIONBIO, &mode) != 0) return Status::ioError("ioctlsocket failed: " + socketError());
    return Status::success();
#else
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return Status::ioError("fcntl F_GETFL failed: " + socketError());
    const int next = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (::fcntl(fd, F_SETFL, next) < 0) return Status::ioError("fcntl F_SETFL failed: " + socketError());
    return Status::success();
#endif
}

Status setReuseAddress(socket_t fd, bool enabled) {
    const int value = enabled ? 1 : 0;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&value), sizeof(value)) < 0)
        return Status::ioError("SO_REUSEADDR failed: " + socketError());
    return Status::success();
}

Status setNoDelay(socket_t fd, bool enabled) {
    const int value = enabled ? 1 : 0;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&value), sizeof(value)) < 0)
        return Status::ioError("TCP_NODELAY failed: " + socketError());
    return Status::success();
}

Status setRecvTimeout(socket_t fd, std::chrono::milliseconds timeout) {
#if defined(_WIN32)
    DWORD millis = static_cast<DWORD>(timeout.count());
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&millis), sizeof(millis)) < 0)
        return Status::ioError("SO_RCVTIMEO failed: " + socketError());
#else
    struct timeval tv {};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return Status::ioError("SO_RCVTIMEO failed: " + socketError());
#endif
    return Status::success();
}

Status setSendTimeout(socket_t fd, std::chrono::milliseconds timeout) {
#if defined(_WIN32)
    DWORD millis = static_cast<DWORD>(timeout.count());
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&millis), sizeof(millis)) < 0)
        return Status::ioError("SO_SNDTIMEO failed: " + socketError());
#else
    struct timeval tv {};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        return Status::ioError("SO_SNDTIMEO failed: " + socketError());
#endif
    return Status::success();
}

Status setRecvBuffer(socket_t fd, int bytes) {
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bytes), sizeof(bytes)) < 0)
        return Status::ioError("SO_RCVBUF failed: " + socketError());
    return Status::success();
}

Status setSendBuffer(socket_t fd, int bytes) {
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bytes), sizeof(bytes)) < 0)
        return Status::ioError("SO_SNDBUF failed: " + socketError());
    return Status::success();
}

Status setBroadcast(socket_t fd, bool enabled) {
    const int value = enabled ? 1 : 0;
    if (::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&value), sizeof(value)) < 0)
        return Status::ioError("SO_BROADCAST failed: " + socketError());
    return Status::success();
}

Status bindToDevice(socket_t fd, const std::string& interfaceName) {
    if (interfaceName.empty()) return Status::success();
#if defined(__linux__)
    if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName.c_str(), static_cast<socklen_t>(interfaceName.size() + 1)) < 0)
        return Status::permissionDenied("SO_BINDTODEVICE '" + interfaceName + "' failed: " + socketError() +
                                        " (requires root or CAP_NET_RAW)");
    return Status::success();
#elif defined(__APPLE__) || defined(__FreeBSD__)
    const unsigned index = ::if_nametoindex(interfaceName.c_str());
    if (index == 0) return Status::notFound("unknown interface '" + interfaceName + "'");
    if (::setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) < 0)
        return Status::ioError("IP_BOUND_IF failed: " + socketError());
    return Status::success();
#else
    (void)fd;
    return Status::unsupported("binding to an interface is not supported on this platform");
#endif
}

socklen_t fillSockaddr(const IpAddr& address, uint16_t port, struct sockaddr_storage* storage) {
    std::memset(storage, 0, sizeof(*storage));
    if (address.isV6()) {
        auto* sa = reinterpret_cast<struct sockaddr_in6*>(storage);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        std::memcpy(sa->sin6_addr.s6_addr, address.rawBytes(), 16);
        return sizeof(sockaddr_in6);
    }
    auto* sa = reinterpret_cast<struct sockaddr_in*>(storage);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(address.toV4());
    return sizeof(sockaddr_in);
}

Status connectWithTimeout(socket_t fd, const IpAddr& address, uint16_t port, std::chrono::milliseconds timeout) {
    sockaddr_storage storage{};
    const socklen_t len = fillSockaddr(address, port, &storage);
    const int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&storage), len);
    if (rc == 0) return Status::success();
    const int code = socketErrorCode();
    if (!isInProgress(code)) {
        if (isConnectionRefused(code)) return Status::unavailable("connection refused");
        return Status::ioError("connect failed: " + socketError());
    }
#if defined(_WIN32)
    fd_set writeSet;
    fd_set errorSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    FD_SET(fd, &writeSet);
    FD_SET(fd, &errorSet);
    struct timeval tv {};
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    const int selected = ::select(0, nullptr, &writeSet, &errorSet, &tv);
    if (selected == 0) return Status::timeout("connect timed out");
    if (selected < 0) return Status::ioError("select failed: " + socketError());
    if (FD_ISSET(fd, &errorSet)) return Status::unavailable("connect failed");
    return Status::success();
#else
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    const int ready = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (ready == 0) return Status::timeout("connect timed out");
    if (ready < 0) {
        if (errno == EINTR) return Status::timeout("connect interrupted");
        return Status::ioError("poll failed: " + socketError());
    }
    int soError = 0;
    socklen_t soLen = sizeof(soError);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &soLen) < 0)
        return Status::ioError("getsockopt failed: " + socketError());
    if (soError != 0) {
        errno = soError;
        if (soError == ECONNREFUSED) return Status::unavailable("connection refused");
        return Status::ioError(std::string("connect failed: ") + strerror(soError));
    }
    return Status::success();
#endif
}

Result<Socket> createTcpSocket(const IpAddr& bindAddress, uint16_t bindPort, bool nonBlocking) {
    socketSubsystemInit();
    const int family = bindAddress.isV6() ? AF_INET6 : AF_INET;
    const socket_t fd = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kInvalidSocket) return Status::ioError("socket(SOCK_STREAM) failed: " + socketError());
    Socket socket(fd);
    if (nonBlocking) {
        auto status = setNonBlocking(fd);
        if (!status) return status;
    }
    setNoDelay(fd, true);
    setReuseAddress(fd, true);
    if (bindAddress.isValid() || bindPort != 0) {
        sockaddr_storage storage{};
        const IpAddr local = bindAddress.isValid() ? bindAddress
                                                   : (family == AF_INET6 ? IpAddr::fromV6Bytes(in6addr_any.s6_addr)
                                                                         : IpAddr::fromV4(0));
        const socklen_t len = fillSockaddr(local, bindPort, &storage);
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&storage), len) < 0)
            return Status::ioError("bind failed: " + socketError());
    }
    return socket;
}

Result<Socket> createUdpSocket(const IpAddr& bindAddress, uint16_t bindPort, bool nonBlocking) {
    socketSubsystemInit();
    const int family = bindAddress.isV6() ? AF_INET6 : AF_INET;
    const socket_t fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == kInvalidSocket) return Status::ioError("socket(SOCK_DGRAM) failed: " + socketError());
    Socket socket(fd);
    if (nonBlocking) {
        auto status = setNonBlocking(fd);
        if (!status) return status;
    }
    setBroadcast(fd, true);
    if (bindAddress.isValid() || bindPort != 0) {
        sockaddr_storage storage{};
        const socklen_t len = fillSockaddr(bindAddress, bindPort, &storage);
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&storage), len) < 0)
            return Status::ioError("bind failed: " + socketError());
    }
    return socket;
}

Result<Socket> createRawSocket(int protocol, bool ipHeaderIncluded, const IpAddr& bindAddress) {
#if defined(_WIN32)
    (void)protocol;
    (void)ipHeaderIncluded;
    (void)bindAddress;
    return Status::unsupported("raw sockets are not available in this build (Npcap required)");
#else
    socketSubsystemInit();
    const int family = bindAddress.isV6() ? AF_INET6 : AF_INET;
    const socket_t fd = ::socket(family, SOCK_RAW, protocol);
    if (fd == kInvalidSocket) {
        const std::string err = socketError();
        if (errno == EPERM || errno == EACCES)
            return Status::permissionDenied("raw socket creation denied: " + err +
                                            " (run as root or grant CAP_NET_RAW: sudo setcap cap_net_raw,cap_net_admin+ep <netra>)");
        return Status::ioError("socket(SOCK_RAW, " + std::to_string(protocol) + ") failed: " + err);
    }
    Socket socket(fd);
    if (ipHeaderIncluded) {
        const int on = 1;
        if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
            log::debug("IP_HDRINCL not supported: " + socketError());
    }
    if (bindAddress.isValid()) {
        sockaddr_storage storage{};
        const socklen_t len = fillSockaddr(bindAddress, 0, &storage);
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&storage), len) < 0)
            log::debug("raw socket bind failed: " + socketError());
    }
    return socket;
#endif
}

Result<Socket> createPacketSocket(int ethertype, const std::string& interfaceName, bool promiscuous) {
#if defined(__linux__)
    socketSubsystemInit();
    const socket_t fd = ::socket(AF_PACKET, SOCK_RAW, htons(static_cast<uint16_t>(ethertype)));
    if (fd == kInvalidSocket) {
        const std::string err = socketError();
        if (errno == EPERM || errno == EACCES)
            return Status::permissionDenied("AF_PACKET socket denied: " + err +
                                            " (live capture needs root or CAP_NET_RAW)");
        return Status::ioError("socket(AF_PACKET) failed: " + err);
    }
    Socket socket(fd);

    if (!interfaceName.empty()) {
        const unsigned index = ::if_nametoindex(interfaceName.c_str());
        if (index == 0) return Status::notFound("unknown interface '" + interfaceName + "'");
        sockaddr_ll addr{};
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(static_cast<uint16_t>(ethertype));
        addr.sll_ifindex = static_cast<int>(index);
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
            return Status::ioError("bind(AF_PACKET, " + interfaceName + ") failed: " + socketError());
        if (promiscuous) {
            struct packet_mreq mreq {};
            mreq.mr_ifindex = static_cast<int>(index);
            mreq.mr_type = PACKET_MR_PROMISC;
            if (::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                log::debug("promiscuous mode failed on " + interfaceName + ": " + socketError());
        }
    }
    return socket;
#else
    (void)ethertype;
    (void)interfaceName;
    (void)promiscuous;
    return Status::unsupported("AF_PACKET capture is only available on Linux; build with libpcap for other platforms");
#endif
}

Result<int> udpExchange(socket_t fd, const IpAddr& target, uint16_t port, ByteView request, uint8_t* response,
                        size_t responseCapacity, std::chrono::milliseconds timeout) {
    sockaddr_storage storage{};
    const socklen_t len = fillSockaddr(target, port, &storage);
    if (request.size > 0) {
        const ssize_t sent = ::sendto(fd, request.data, request.size, 0, reinterpret_cast<struct sockaddr*>(&storage), len);
        if (sent < 0) return Status::ioError("sendto failed: " + socketError());
    }
    const int64_t deadline = util::monotonicMillis() + std::max<int64_t>(1, timeout.count());
    while (true) {
        const int64_t remaining = deadline - util::monotonicMillis();
        if (remaining <= 0) return 0;
#if defined(_WIN32)
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(fd, &readSet);
        struct timeval tv {};
        tv.tv_sec = static_cast<long>(remaining / 1000);
        tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);
        const int ready = ::select(0, &readSet, nullptr, nullptr, &tv);
#else
        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int ready = ::poll(&pfd, 1, static_cast<int>(remaining));
#endif
        if (ready == 0) return 0;
        if (ready < 0) {
            if (isTransientError(socketErrorCode())) continue;
            return Status::ioError("poll failed: " + socketError());
        }
        sockaddr_storage from{};
        socklen_t fromLen = sizeof(from);
        const ssize_t received = ::recvfrom(fd, response, socketLength(responseCapacity), 0,
                                           reinterpret_cast<struct sockaddr*>(&from), &fromLen);
        if (received < 0) {
            const int code = socketErrorCode();
#if defined(_WIN32)
            if (code == WSAECONNRESET) return 0;  // ICMP port unreachable surfaced as reset
#else
            if (code == ECONNREFUSED) return 0;
#endif
            if (isTransientError(code)) continue;
            return Status::ioError("recvfrom failed: " + socketError());
        }
        return static_cast<int>(received);
    }
}

Result<std::string> readBanner(socket_t fd, std::chrono::milliseconds timeout, size_t maxBytes) {
    std::string banner;
    std::vector<char> buffer(4096);
    const int64_t deadline = util::monotonicMillis() + std::max<int64_t>(1, timeout.count());
    bool firstRead = true;
    while (banner.size() < maxBytes) {
        int64_t remaining = deadline - util::monotonicMillis();
        // After the first chunk only wait briefly: services that dribble data are rare,
        // and holding the scan open for the full timeout would waste seconds per port.
        if (!firstRead) remaining = std::min<int64_t>(remaining, 150);
        if (remaining <= 0) break;

#if defined(_WIN32)
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(fd, &readSet);
        struct timeval tv {};
        tv.tv_sec = static_cast<long>(remaining / 1000);
        tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);
        const int ready = ::select(0, &readSet, nullptr, nullptr, &tv);
#else
        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int ready = ::poll(&pfd, 1, static_cast<int>(remaining));
#endif
        if (ready <= 0) break;

        const ssize_t received = ::recv(fd, buffer.data(), std::min(buffer.size(), maxBytes - banner.size()), 0);
        if (received <= 0) break;
        banner.append(buffer.data(), static_cast<size_t>(received));
        firstRead = false;
    }
    return banner;
}

}  // namespace netra::net

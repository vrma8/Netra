// SPDX-License-Identifier: MIT
// net/sockets.h : thin, portable socket helpers shared by the scanner and capture code.
#pragma once

#include <chrono>
#include <string>

#include "netra/core/status.h"
#include "netra/net/ip.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <netinet/in.h>
#include <sys/socket.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

namespace netra::net {

/// Ensures WSAStartup on Windows; no-op elsewhere. Called automatically.
void socketSubsystemInit();

std::string socketError();
int socketErrorCode();
/// True when a connect()/send() should be retried.
bool isTransientError(int code);
bool isConnectionRefused(int code);
bool isInProgress(int code);

Status setNonBlocking(socket_t fd, bool enabled = true);
Status setReuseAddress(socket_t fd, bool enabled = true);
Status setNoDelay(socket_t fd, bool enabled = true);
Status setRecvTimeout(socket_t fd, std::chrono::milliseconds timeout);
Status setSendTimeout(socket_t fd, std::chrono::milliseconds timeout);
Status setRecvBuffer(socket_t fd, int bytes);
Status setSendBuffer(socket_t fd, int bytes);
Status setBroadcast(socket_t fd, bool enabled = true);
Status bindToDevice(socket_t fd, const std::string& interfaceName);
Status connectWithTimeout(socket_t fd, const IpAddr& address, uint16_t port, std::chrono::milliseconds timeout);
void closeSocket(socket_t fd);

/// RAII socket handle.
class Socket {
public:
    Socket() = default;
    explicit Socket(socket_t fd) : fd_(fd) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : fd_(other.fd_) { other.fd_ = kInvalidSocket; }
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = kInvalidSocket;
        }
        return *this;
    }
    ~Socket() { reset(); }

    socket_t get() const { return fd_; }
    bool valid() const { return fd_ != kInvalidSocket; }
    explicit operator bool() const { return valid(); }
    socket_t release() {
        socket_t fd = fd_;
        fd_ = kInvalidSocket;
        return fd;
    }
    void reset() {
        if (valid()) closeSocket(fd_);
        fd_ = kInvalidSocket;
    }

private:
    socket_t fd_{kInvalidSocket};
};

/// Creates a non-blocking TCP socket, optionally bound to a local address/port.
Result<Socket> createTcpSocket(const IpAddr& bindAddress = IpAddr(), uint16_t bindPort = 0, bool nonBlocking = true);
Result<Socket> createUdpSocket(const IpAddr& bindAddress = IpAddr(), uint16_t bindPort = 0, bool nonBlocking = false);
/// Raw IPv4 socket. `ipHeaderIncluded` enables IP_HDRINCL for hand-built headers.
Result<Socket> createRawSocket(int protocol, bool ipHeaderIncluded = false, const IpAddr& bindAddress = IpAddr());
/// AF_PACKET (Linux) / AF_INET raw ICMP (macOS/BSD) socket for L2 work.
Result<Socket> createPacketSocket(int ethertype, const std::string& interfaceName, bool promiscuous);

/// Fills a sockaddr_in/in6 for an address+port. Returns the sockaddr length.
socklen_t fillSockaddr(const IpAddr& address, uint16_t port, struct sockaddr_storage* storage);

/// Sends a UDP probe and waits (up to `timeout`) for a reply. Used by the UDP scanner
/// and by service detection. Returns the number of bytes read, 0 on timeout.
Result<int> udpExchange(socket_t fd, const IpAddr& target, uint16_t port, ByteView request, uint8_t* response,
                        size_t responseCapacity, std::chrono::milliseconds timeout);

/// Blocking read of a TCP banner with a deadline. Returns whatever arrived.
Result<std::string> readBanner(socket_t fd, std::chrono::milliseconds timeout, size_t maxBytes = 4096);

}  // namespace netra::net

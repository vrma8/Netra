// SPDX-License-Identifier: MIT
// scan/asio_prober.h : optional Boost.Asio backed probing path.
//
// Netra ships a dependency-free poll() engine (scan/engine.h). When the build
// detects Boost.Asio, this module provides an alternative asynchronous prober
// that uses an io_context thread pool; the CLI/dashboard pick whichever is
// available at runtime via asioAvailable().
#pragma once

#include <atomic>
#include <string>
#include <vector>

#include "netra/core/status.h"
#include "netra/net/ip.h"
#include "netra/scan/engine.h"
#include "netra/scan/types.h"

namespace netra::scan {

/// Whether the optional Boost.Asio path was compiled in, plus a description.
bool asioAvailable();
std::string asioStatus();

/// Asynchronously probes every request using Boost.Asio (returns Unsupported
/// when the library is absent).
Status asioScanPorts(const ScanOptions& options, const std::vector<ProbeRequest>& requests, const ProbeSink& sink,
                     std::atomic<bool>* cancel = nullptr);

/// Resolves a hostname through the Asio resolver when available.
Result<std::vector<net::IpAddr>> asioResolve(const std::string& hostname, bool preferV4 = true);

}  // namespace netra::scan

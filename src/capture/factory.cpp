// SPDX-License-Identifier: MIT
// capture/factory.cpp : backend selection and capability reporting.
#include "netra/capture/source.h"

#include "netra/capture/pcap_file.h"
#include "netra/core/log.h"
#include "netra/net/interfaces.h"

namespace netra::capture {

CaptureSourcePtr createPcapFileSource() { return CaptureSourcePtr(new PcapFileSource()); }

CaptureSourcePtr createCaptureSource(const CaptureOptions& options) {
    if (!options.syntheticScenario.empty()) return createSyntheticSource();

    if (!options.readFile.empty()) {
#if NETRA_HAVE_LIBPCAP
        // libpcap reads exotic pcapng flavours more reliably than the built-in parser.
        if (auto source = createLibpcapSource()) {
            log::debug("using libpcap backend for capture file");
            return source;
        }
#endif
        return createPcapFileSource();
    }

#if NETRA_HAVE_LIBPCAP
    if (auto source = createLibpcapSource()) return source;
#endif
#if NETRA_HAVE_PCAPPLUSPLUS
    if (auto source = createPcapPlusPlusSource()) return source;
#endif
#if defined(__linux__)
    return createAfPacketSource();
#else
    log::warn("no live capture backend available on this platform; build with libpcap/Npcap support");
    return nullptr;
#endif
}

std::vector<BackendInfo> availableBackends() {
    std::vector<BackendInfo> backends;
    const bool rawOk = net::canOpenRawSockets();

    backends.push_back(BackendInfo{"builtin-pcap-file", "built-in pcap/pcapng file reader", true, true,
                                   "always available (no external dependency)"});
#if NETRA_HAVE_LIBPCAP
    backends.push_back(BackendInfo{"libpcap", "libpcap/Npcap live capture and file reading", true, true,
                                   "kernel BPF filters available"});
#else
    backends.push_back(BackendInfo{"libpcap", "libpcap/Npcap live capture and file reading", false, false,
                                   "not found at build time"});
#endif
#if NETRA_HAVE_PCAPPLUSPLUS
    backends.push_back(BackendInfo{"pcapplusplus", "PcapPlusPlus live capture backend", true, true,
                                   "uses libpcap/Npcap underneath"});
#else
    backends.push_back(BackendInfo{"pcapplusplus", "PcapPlusPlus live capture backend", false, false,
                                   "not found at build time"});
#endif
#if defined(__linux__)
    backends.push_back(BackendInfo{"afpacket", "Linux AF_PACKET raw socket capture", true, rawOk,
                                   rawOk ? "ready" : "needs root or CAP_NET_RAW"});
#else
    backends.push_back(BackendInfo{"afpacket", "Linux AF_PACKET raw socket capture", false, false,
                                   "Linux only"});
#endif
    backends.push_back(BackendInfo{"synthetic", "built-in traffic generator (demo/tests)", true, true,
                                   "no privileges required"});
    return backends;
}

std::string backendSummary() {
    std::string out;
    for (const auto& backend : availableBackends()) {
        out += backend.compiled ? (backend.usable ? "  [available] " : "  [limited]   ") : "  [not built] ";
        out += util::pad(backend.id, 18) + backend.description;
        if (!backend.note.empty()) out += " - " + backend.note;
        out += "\n";
    }
    return out;
}

}  // namespace netra::capture

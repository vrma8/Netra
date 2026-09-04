// SPDX-License-Identifier: MIT
// tools/pcapgen.cpp : writes synthetic traffic to a PCAP file.
//
// Handy for trying `netra analyze`, the display filters and the dashboard without
// capturing on a live interface:
//
//   netra-pcapgen -o sample.pcap --scenario mixed --count 500
//   netra analyze sample.pcap --stats --flows

#include <cstring>
#include <iostream>
#include <string>

#include "netra/capture/packet.h"
#include "netra/capture/source.h"
#include "netra/core/util.h"

namespace {

void usage() {
    std::cout << "Usage: netra-pcapgen [-o FILE] [--scenario mixed|lan|web|dns] [--count N] [--rate HZ]\n"
                 "\n"
                 "  -o, --output FILE   PCAP file to write (default: netra-sample.pcap)\n"
                 "      --scenario S    traffic profile (default: mixed)\n"
                 "      --count N       packets to generate (default: 500)\n"
                 "      --rate HZ       packets per second, 0 = as fast as possible (default: 0)\n"
                 "      --snaplen N     link snapshot length (default: 262144)\n"
                 "  -h, --help          this help\n";
}

std::string valueFor(int argc, char** argv, int& i, const std::string& fallback) {
    if (i + 1 < argc) return argv[++i];
    return fallback;
}

}  // namespace

int main(int argc, char** argv) {
    std::string output = "netra-sample.pcap";
    std::string scenario = "mixed";
    int count = 500;
    int rate = 0;
    int snaplen = 262144;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { usage(); return 0; }
        else if (arg == "-o" || arg == "--output") output = valueFor(argc, argv, i, output);
        else if (arg == "--scenario") scenario = valueFor(argc, argv, i, scenario);
        else if (arg == "--count") count = std::atoi(valueFor(argc, argv, i, std::to_string(count)).c_str());
        else if (arg == "--rate") rate = std::atoi(valueFor(argc, argv, i, std::to_string(rate)).c_str());
        else if (arg == "--snaplen") snaplen = std::atoi(valueFor(argc, argv, i, std::to_string(snaplen)).c_str());
        else {
            std::cerr << "netra-pcapgen: unknown argument " << arg << "\n\n";
            usage();
            return 2;
        }
    }
    if (count <= 0) {
        std::cerr << "netra-pcapgen: --count must be positive\n";
        return 2;
    }

    netra::capture::CaptureOptions options;
    options.syntheticScenario = netra::util::toLower(scenario);
    options.syntheticRateHz = rate;
    options.snaplen = snaplen;

    auto source = netra::capture::createCaptureSource(options);
    if (!source) {
        std::cerr << "netra-pcapgen: no capture source for scenario '" << scenario << "'\n";
        return 1;
    }
    const auto opened = source->open(options);
    if (!opened.ok()) {
        std::cerr << "netra-pcapgen: " << opened.message() << "\n";
        return 1;
    }

    netra::capture::PcapWriter writer;
    const auto created = writer.open(output, source->linkType());
    if (!created.ok()) {
        std::cerr << "netra-pcapgen: " << created.message() << "\n";
        return 1;
    }

    int written = 0;
    netra::capture::RawPacket packet;
    while (written < count) {
        const auto result = source->nextPacket(packet, 2000);
        if (result != netra::capture::ReadResult::Packet) break;
        if (!writer.write(packet).ok()) break;
        ++written;
    }
    writer.close();
    source->close();

    std::cout << "wrote " << written << " packet(s) (" << netra::util::humanBytes(static_cast<double>(writer.bytesWritten()))
              << ") to " << output << "\n";
    return written > 0 ? 0 : 1;
}

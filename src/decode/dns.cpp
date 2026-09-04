// SPDX-License-Identifier: MIT
// decode/dns.cpp : DNS message dissection with full name decompression.
#include "netra/decode/packet.h"

#include <cstring>
#include <sstream>

#include "netra/core/util.h"

namespace netra::decode {
namespace {

struct DnsReader {
    ByteView message;
    size_t pos{0};
    bool error{false};

    uint8_t u8() {
        if (pos + 1 > message.size) {
            error = true;
            return 0;
        }
        return message.data[pos++];
    }
    uint16_t u16() {
        // Sequence the two reads explicitly: the order of evaluation inside an
        // expression would otherwise be unspecified.
        const uint8_t high = u8();
        const uint8_t low = u8();
        return static_cast<uint16_t>((static_cast<uint16_t>(high) << 8) | low);
    }
    uint32_t u32() {
        const uint16_t high = u16();
        const uint16_t low = u16();
        return (static_cast<uint32_t>(high) << 16) | low;
    }
    void skip(size_t count) {
        if (pos + count > message.size) {
            pos = message.size;
            error = true;
            return;
        }
        pos += count;
    }
    ByteView take(size_t count) {
        if (pos + count > message.size) {
            error = true;
            return ByteView(message.data + pos, message.size > pos ? message.size - pos : 0);
        }
        const ByteView view(message.data + pos, count);
        pos += count;
        return view;
    }
};

std::string readName(DnsReader& reader) {
    std::string name;
    size_t cursor = reader.pos;
    int jumps = 0;
    bool jumped = false;
    size_t endPos = cursor;

    while (true) {
        if (cursor >= reader.message.size) {
            reader.error = true;
            break;
        }
        const uint8_t length = reader.message.data[cursor];
        if (length == 0) {
            ++cursor;
            if (!jumped) endPos = cursor;
            break;
        }
        if ((length & 0xc0) == 0xc0) {
            if (cursor + 1 >= reader.message.size) {
                reader.error = true;
                break;
            }
            const uint16_t pointer = static_cast<uint16_t>(((length & 0x3f) << 8) | reader.message.data[cursor + 1]);
            if (!jumped) endPos = cursor + 2;
            if (++jumps > 16 || pointer >= reader.message.size || pointer >= cursor) {
                // Loops or forward pointers are malformed.
                reader.error = true;
                break;
            }
            cursor = pointer;
            jumped = true;
            continue;
        }
        if (length > 63 || cursor + 1 + length > reader.message.size) {
            reader.error = true;
            break;
        }
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(reader.message.data + cursor + 1), length);
        cursor += 1 + length;
    }

    reader.pos = endPos ? endPos : cursor;
    return name.empty() ? std::string("<root>") : name;
}

std::string formatRdata(uint16_t type, ByteView rdata, DnsReader& reader, size_t rdataStart) {
    (void)rdataStart;
    switch (type) {
        case 1:  // A
            return rdata.size == 4 ? net::IpAddr::fromV4Bytes(rdata.data).toString() : util::toHex(rdata);
        case 28:  // AAAA
            return rdata.size == 16 ? net::IpAddr::fromV6Bytes(rdata.data).toString() : util::toHex(rdata);
        case 2:   // NS
        case 5:   // CNAME
        case 12:  // PTR
        case 39:  // DNAME
        {
            DnsReader local = reader;
            local.pos = static_cast<size_t>(rdata.data - reader.message.data);
            return readName(local);
        }
        case 15: {  // MX
            if (rdata.size < 3) return util::toHex(rdata);
            const uint16_t preference = static_cast<uint16_t>((rdata.data[0] << 8) | rdata.data[1]);
            DnsReader local = reader;
            local.pos = static_cast<size_t>(rdata.data - reader.message.data) + 2;
            return std::to_string(preference) + " " + readName(local);
        }
        case 6: {  // SOA
            DnsReader local = reader;
            local.pos = static_cast<size_t>(rdata.data - reader.message.data);
            const std::string mname = readName(local);
            const std::string rname = readName(local);
            std::ostringstream os;
            os << mname << ' ' << rname;
            if (!local.error) {
                os << ' ' << local.u32() << ' ' << local.u32() << ' ' << local.u32() << ' ' << local.u32() << ' '
                   << local.u32();
            }
            return os.str();
        }
        case 16: {  // TXT
            std::string text;
            size_t offset = 0;
            while (offset < rdata.size) {
                const uint8_t length = rdata.data[offset++];
                if (offset + length > rdata.size) break;
                text.append(reinterpret_cast<const char*>(rdata.data + offset), length);
                offset += length;
                if (offset < rdata.size) text += " ";
            }
            return text;
        }
        case 33: {  // SRV
            if (rdata.size < 7) return util::toHex(rdata);
            const uint16_t priority = static_cast<uint16_t>((rdata.data[0] << 8) | rdata.data[1]);
            const uint16_t weight = static_cast<uint16_t>((rdata.data[2] << 8) | rdata.data[3]);
            const uint16_t port = static_cast<uint16_t>((rdata.data[4] << 8) | rdata.data[5]);
            DnsReader local = reader;
            local.pos = static_cast<size_t>(rdata.data - reader.message.data) + 6;
            std::ostringstream os;
            os << priority << ' ' << weight << ' ' << port << ' ' << readName(local);
            return os.str();
        }
        case 41:  // OPT
            return "EDNS0 (" + std::to_string(rdata.size) + " bytes)";
        case 257: {  // CAA
            if (rdata.size < 2) return util::toHex(rdata);
            const uint8_t tagLength = rdata.data[1];
            const std::string tag(reinterpret_cast<const char*>(rdata.data + 2), std::min<size_t>(tagLength, rdata.size - 2));
            const size_t valueStart = 2 + tagLength;
            const std::string value = valueStart < rdata.size
                                          ? std::string(reinterpret_cast<const char*>(rdata.data + valueStart),
                                                        rdata.size - valueStart)
                                          : std::string();
            return tag + " \"" + value + "\"";
        }
        default:
            return util::toHex(rdata.sub(0, std::min<size_t>(rdata.size, 32)));
    }
}

}  // namespace

std::string DnsRecord::typeName() const {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 39: return "DNAME";
        case 41: return "OPT";
        case 43: return "DS";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 50: return "NSEC3";
        case 52: return "TLSA";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 99: return "SPF";
        case 255: return "ANY";
        case 256: return "URI";
        case 257: return "CAA";
        default: return "TYPE" + std::to_string(type);
    }
}

bool parseDns(ByteView payload, DnsLayer& out, bool overTcp) {
    if (overTcp && payload.size >= 14) {
        // DNS-over-TCP prefixes the message with a 2 byte length.
        const uint16_t declared = static_cast<uint16_t>((payload.data[0] << 8) | payload.data[1]);
        if (static_cast<size_t>(declared) + 2 <= payload.size) payload = payload.sub(2);
    }
    if (payload.size < 12) return false;
    DnsReader reader;
    reader.message = payload;

    out.id = reader.u16();
    const uint16_t flags = reader.u16();
    const uint16_t qdCount = reader.u16();
    const uint16_t anCount = reader.u16();
    const uint16_t nsCount = reader.u16();
    const uint16_t arCount = reader.u16();

    out.query = (flags & 0x8000) == 0;
    out.opcode = static_cast<uint8_t>((flags >> 11) & 0x0f);
    out.authoritative = (flags & 0x0400) != 0;
    out.truncated = (flags & 0x0200) != 0;
    out.recursionDesired = (flags & 0x0100) != 0;
    out.recursionAvailable = (flags & 0x0080) != 0;
    out.rcode = static_cast<uint8_t>(flags & 0x000f);

    if (qdCount > 64 || anCount > 512 || nsCount > 512 || arCount > 512) return false;

    for (uint16_t i = 0; i < qdCount && !reader.error; ++i) {
        const std::string name = readName(reader);
        const uint16_t type = reader.u16();
        reader.u16();  // class
        out.questions.emplace_back(name, type);
    }
    if (reader.error) {
        out.valid = false;
        return !out.questions.empty();
    }

    auto parseRecords = [&](uint16_t count, std::vector<DnsRecord>& sink) {
        for (uint16_t i = 0; i < count && !reader.error; ++i) {
            DnsRecord record;
            record.name = readName(reader);
            record.type = reader.u16();
            record.klass = reader.u16();
            record.ttl = reader.u32();
            const uint16_t rdLength = reader.u16();
            if (reader.error) break;
            const size_t rdataStart = reader.pos;
            const ByteView rdata = reader.take(rdLength);
            record.data = formatRdata(record.type, rdata, reader, rdataStart);
            sink.push_back(std::move(record));
        }
    };
    parseRecords(anCount, out.answers);
    parseRecords(nsCount, out.authority);
    parseRecords(arCount, out.additional);

    if (reader.error) out.valid = false;

    // Human readable summary, e.g. "Standard query A www.example.com".
    std::ostringstream os;
    if (out.query) {
        os << (out.opcode == 0 ? "Standard query" : "Query opcode " + std::to_string(out.opcode));
        for (const auto& question : out.questions) {
            DnsRecord probe;
            probe.type = question.second;
            os << ' ' << probe.typeName() << ' ' << question.first;
        }
    } else {
        os << "Standard query response";
        if (out.rcode != 0) os << " " << out.rcodeName();
        std::vector<std::string> answers;
        for (const auto& record : out.answers) {
            DnsRecord probe;
            probe.type = record.type;
            answers.push_back(probe.typeName() + " " + record.data);
        }
        for (size_t i = 0; i < answers.size() && i < 3; ++i) os << ' ' << answers[i];
        if (answers.size() > 3) os << " (+" << (answers.size() - 3) << " more)";
        if (out.answers.empty() && !out.questions.empty()) {
            DnsRecord probe;
            probe.type = out.questions.front().second;
            os << ' ' << probe.typeName() << ' ' << out.questions.front().first;
        }
    }
    out.summary = os.str();
    return true;
}

std::string DnsLayer::rcodeName() const {
    switch (rcode) {
        case 0: return "No error";
        case 1: return "Format error";
        case 2: return "Server failure";
        case 3: return "Non-existent domain (NXDOMAIN)";
        case 4: return "Not implemented";
        case 5: return "Query refused";
        case 6: return "Name exists when it should not";
        case 7: return "RR set exists when it should not";
        case 8: return "RR set that should exist does not";
        case 9: return "Server not authoritative for zone";
        case 10: return "Name not contained in zone";
        default: return "rcode " + std::to_string(rcode);
    }
}

}  // namespace netra::decode

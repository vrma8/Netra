// SPDX-License-Identifier: MIT
// decode/http.cpp : HTTP/1.x request and response dissection (per packet).
//
// Note: Netra dissects each TCP segment independently; streams split across
// segments are reported as a single message from the segment that carries the
// header block (see docs/architecture.md for the reassembly roadmap).
#include "netra/decode/packet.h"

#include <algorithm>
#include <sstream>

#include "netra/core/util.h"

namespace netra::decode {
namespace {

const char* kMethods[] = {"GET",     "POST",    "HEAD",     "PUT",     "DELETE",  "OPTIONS", "TRACE",
                          "CONNECT", "PATCH",   "PROPFIND", "PROPPATCH", "MKCOL", "COPY",    "MOVE",
                          "LOCK",    "UNLOCK",  "SUBSCRIBE", "NOTIFY",  "PURGE",   "SEARCH",  "CHECKOUT",
                          "MERGE",   "REPORT",  "MKACTIVITY"};

bool isMethod(std::string_view token) {
    for (const char* method : kMethods) {
        if (token == method) return true;
    }
    return false;
}

std::string lower(std::string_view text) { return util::toLower(text); }

}  // namespace

bool looksLikeHttp(ByteView payload) {
    if (payload.size < 8) return false;
    const ByteView head = payload.sub(0, std::min<size_t>(payload.size, 16));
    std::string prefix(reinterpret_cast<const char*>(head.data), head.size);
    if (util::startsWith(prefix, "HTTP/1.") || util::startsWith(prefix, "HTTP/2")) return true;
    const size_t space = prefix.find(' ');
    if (space == std::string::npos || space < 3 || space > 9) return false;
    return isMethod(prefix.substr(0, space));
}

bool parseHttp(ByteView payload, HttpLayer& out, bool fromServerHint) {
    if (payload.size < 8) return false;
    const std::string text(reinterpret_cast<const char*>(payload.data), payload.size);

    // Locate the end of the header block. It may not be present in this segment.
    size_t headerEnd = text.find("\r\n\r\n");
    size_t headerLength = 0;
    if (headerEnd != std::string::npos) {
        headerLength = headerEnd + 4;
    } else {
        headerEnd = text.find("\n\n");
        if (headerEnd != std::string::npos) headerLength = headerEnd + 2;
        else headerLength = text.size();  // header split across segments
    }

    const std::string headerBlock = text.substr(0, headerLength);
    const auto lines = util::splitLines(headerBlock);
    if (lines.empty()) return false;

    const std::string& firstLine = lines[0];
    const bool response = util::startsWith(firstLine, "HTTP/");
    const bool request = !response && isMethod(firstLine.substr(0, firstLine.find(' ')));
    if (!response && !request) return false;

    out.request = request;
    if (request) {
        const auto tokens = util::split(firstLine, " ");
        if (tokens.size() < 2) return false;
        out.method = tokens[0];
        out.uri = tokens[1];
        out.version = tokens.size() > 2 ? tokens[2] : "HTTP/1.0";
    } else {
        const auto tokens = util::split(firstLine, " ");
        if (tokens.size() < 2) return false;
        out.version = tokens[0];
        const auto code = util::parseInt(tokens[1]);
        if (!code) return false;
        out.statusCode = static_cast<int>(*code);
        out.statusText = tokens.size() > 2 ? util::join(std::vector<std::string>(tokens.begin() + 2, tokens.end()), " ")
                                           : std::string();
    }

    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        if (line.empty()) continue;
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        HttpHeader header;
        header.name = util::trim(line.substr(0, colon));
        header.value = util::trim(line.substr(colon + 1));
        const std::string key = lower(header.name);
        if (key == "host") out.host = header.value;
        else if (key == "user-agent") out.userAgent = header.value;
        else if (key == "content-type") out.contentType = header.value;
        else if (key == "server") out.server = header.value;
        else if (key == "cookie" || key == "set-cookie") out.cookie = header.value;
        else if (key == "referer") out.referer = header.value;
        else if (key == "content-length") out.contentLength = util::parseInt(header.value).value_or(-1);
        out.headers.push_back(std::move(header));
    }

    if (headerEnd != std::string::npos) out.body = payload.sub(headerLength);

    std::ostringstream summary;
    if (request) {
        summary << out.method << ' ' << out.uri;
        if (!out.host.empty()) summary << " (Host: " << out.host << ')';
    } else {
        summary << out.version << ' ' << out.statusCode << ' ' << out.statusText;
        if (!out.contentType.empty()) summary << " [" << out.contentType << ']';
        if (out.body.size) summary << " (" << out.body.size << " bytes)";
    }
    out.summary = summary.str();
    (void)fromServerHint;
    return true;
}

const std::string* HttpLayer::header(const std::string& name) const {
    const std::string key = lower(name);
    for (const auto& candidate : headers) {
        if (lower(candidate.name) == key) return &candidate.value;
    }
    return nullptr;
}

}  // namespace netra::decode

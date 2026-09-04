// SPDX-License-Identifier: MIT
// dashboard/assets.cpp : embedded/disk lookup for the web dashboard files.
#include "netra/dashboard/assets.h"

#include <algorithm>

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"

#if NETRA_EMBEDDED_WEB && defined(NETRA_WEB_ASSETS_HEADER)
#include NETRA_WEB_ASSETS_HEADER
#define NETRA_DASHBOARD_EMBEDDED 1
#endif

namespace netra::dashboard {
namespace {

std::string normalisePath(const std::string& path) {
    std::string clean = path;
    if (clean.empty() || clean == "/") return "index.html";
    while (!clean.empty() && clean.front() == '/') clean.erase(clean.begin());
    // Strip any query string or fragment.
    const size_t cut = clean.find_first_of("?#");
    if (cut != std::string::npos) clean = clean.substr(0, cut);
    if (clean.empty()) return "index.html";
    if (clean.find("..") != std::string::npos) return {};  // refuse traversal
    return clean;
}

bool readFromDirectory(const std::string& directory, const std::string& name, ServedAsset* out) {
    if (directory.empty() || name.empty()) return false;
    const std::string path = util::pathJoin(directory, name);
    if (!util::fileExists(path) || util::isDirectory(path)) return false;
    auto content = util::readFile(path);
    if (!content) {
        log::debug("cannot read web asset " + path + ": " + content.message());
        return false;
    }
    out->found = true;
    out->fromDisk = true;
    out->contentType = contentTypeForPath(name);
    out->body.assign(reinterpret_cast<const char*>(content->data()), content->size());
    return true;
}

}  // namespace

std::string contentTypeForPath(const std::string& path) {
    const size_t dot = path.rfind('.');
    const std::string extension = dot == std::string::npos ? "" : util::toLower(path.substr(dot));
    if (extension == ".html" || extension == ".htm") return "text/html; charset=utf-8";
    if (extension == ".css") return "text/css; charset=utf-8";
    if (extension == ".js" || extension == ".mjs") return "application/javascript; charset=utf-8";
    if (extension == ".json") return "application/json";
    if (extension == ".svg") return "image/svg+xml";
    if (extension == ".png") return "image/png";
    if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
    if (extension == ".ico") return "image/x-icon";
    if (extension == ".woff") return "font/woff";
    if (extension == ".woff2") return "font/woff2";
    if (extension == ".txt") return "text/plain; charset=utf-8";
    if (extension == ".map") return "application/json";
    return "application/octet-stream";
}

bool assetsEmbedded() {
#ifdef NETRA_DASHBOARD_EMBEDDED
    return netra::web::kAssetCount > 0;
#else
    return false;
#endif
}

std::string assetDirectory() {
#ifdef NETRA_WEB_ASSETS_DIR
    return NETRA_WEB_ASSETS_DIR;
#else
    return {};
#endif
}

std::vector<std::string> embeddedAssetPaths() {
    std::vector<std::string> paths;
#ifdef NETRA_DASHBOARD_EMBEDDED
    for (size_t i = 0; i < netra::web::kAssetCount; ++i) paths.emplace_back(netra::web::kAssets[i].path);
#endif
    return paths;
}

std::string assetSummary() {
    if (assetsEmbedded()) {
        return std::to_string(embeddedAssetPaths().size()) + " web asset(s) embedded in the binary";
    }
    const std::string directory = assetDirectory();
    if (!directory.empty()) return "web assets served from " + directory;
    return "web assets not available (build with -DNETRA_EMBED_WEB=ON)";
}

ServedAsset loadAsset(const std::string& path, const std::string& webRoot) {
    ServedAsset asset;
    const std::string name = normalisePath(path);
    if (name.empty()) return asset;

    // An explicit web root wins so the UI can be edited without rebuilding.
    if (!webRoot.empty() && readFromDirectory(webRoot, name, &asset)) return asset;

#ifdef NETRA_DASHBOARD_EMBEDDED
    for (size_t i = 0; i < netra::web::kAssetCount; ++i) {
        const auto& entry = netra::web::kAssets[i];
        if (name != entry.path) continue;
        asset.found = true;
        asset.fromDisk = false;
        asset.contentType = entry.mimeType && *entry.mimeType ? entry.mimeType : contentTypeForPath(name);
        asset.body.assign(reinterpret_cast<const char*>(entry.data), entry.size);
        return asset;
    }
#endif

    if (readFromDirectory(assetDirectory(), name, &asset)) return asset;
    return asset;
}

}  // namespace netra::dashboard

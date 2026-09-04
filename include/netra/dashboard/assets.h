// SPDX-License-Identifier: MIT
// dashboard/assets.h : web UI asset lookup (embedded byte arrays or files on disk).
#pragma once

#include <string>
#include <vector>

namespace netra::dashboard {

struct ServedAsset {
    bool found{false};
    std::string contentType;
    std::string body;
    bool fromDisk{false};
};

/// True when the web UI was compiled into the binary.
bool assetsEmbedded();
/// Where assets are read from when they are not embedded (may be empty).
std::string assetDirectory();
/// Human readable one-liner for `netra version` / the dashboard footer.
std::string assetSummary();

/// Resolves a request path ("/", "/app.js", ...) to an asset.
/// `webRoot` (when non-empty) takes precedence over the embedded copy, which
/// makes it possible to iterate on the UI without rebuilding.
ServedAsset loadAsset(const std::string& path, const std::string& webRoot = {});

/// Content type derived from a file extension.
std::string contentTypeForPath(const std::string& path);

/// Paths of the embedded assets (empty when not embedded).
std::vector<std::string> embeddedAssetPaths();

}  // namespace netra::dashboard

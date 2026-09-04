# Building Netra

Netra builds with nothing but a C++17 compiler and CMake. Every third-party library it
can use is **optional**: when a library is missing, Netra falls back to its own
implementation of the same feature, so the command set never shrinks — only the fast path
changes.

---

## 1. Prerequisites

| Requirement | Minimum | Notes |
| --- | --- | --- |
| CMake | 3.16 | Works with CMake 4.x (`cmake_minimum_required` is 3.16) |
| Compiler | C++17 | GCC 9+, Clang 10+, Apple Clang 12+, MSVC 2019 (v142)+ |
| Threads | pthreads / Win32 | Linked automatically |
| OS | Linux, macOS, Windows | Linux adds the `AF_PACKET` capture backend |

No network access, no package manager and no external libraries are needed for a full
build.

## 2. Quick build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

./build/bin/netra version      # shows detected dependencies and capture backends
./build/bin/netra selftest     # 16 built-in verification checks
ctest --test-dir build         # 79 unit tests (11 CTest entries)
```

Artifacts:

| Path | What |
| --- | --- |
| `build/bin/netra` | the main executable (web dashboard assets embedded) |
| `build/bin/netra-pcapgen` | sample capture generator (built when `NETRA_BUILD_TOOLS=ON`) |
| `build/bin/netra_tests` | unit test binary (built when `NETRA_BUILD_TESTS=ON`) |
| `build/lib/libnetra_*.a` | per-module static libraries |
| `build/compile_commands.json` | for clangd / IDE integration |

The configure step prints a summary of every detected dependency, the enabled backends and
the selected build options — worth reading once per machine.

## 3. Install

```bash
sudo cmake --install build                     # default prefix /usr/local
cmake --install build --prefix ~/.local        # user-local install
```

Installs `bin/netra`, the headers under `include/netra/`, and `README.md`, `LICENSE` and
`description.md` into the documentation directory.

## 4. CMake options

| Option | Default | Effect |
| --- | --- | --- |
| `NETRA_BUILD_TESTS` | `ON` | Build `netra_tests` and register CTest entries |
| `NETRA_BUILD_TOOLS` | `ON` | Build `netra-pcapgen` |
| `NETRA_EMBED_WEB` | `ON` | Compile `web/` assets into the binary (`netra dashboard` needs no files at runtime) |
| `NETRA_WERROR` | `OFF` | Treat compiler warnings as errors |
| `NETRA_SANITIZE` | `OFF` | Build with AddressSanitizer + UndefinedBehaviorSanitizer |
| `NETRA_USE_LIBPCAP` | `AUTO` | `AUTO`/`ON`/`OFF` — libpcap or Npcap capture backend |
| `NETRA_USE_PCAPPLUSPLUS` | `AUTO` | PcapPlusPlus capture/parsing backend |
| `NETRA_USE_BOOST` | `AUTO` | Boost.Asio asynchronous connect scanner |
| `NETRA_USE_OPENSSL` | `AUTO` | OpenSSL TLS probing and X.509 parsing |
| `NETRA_USE_SQLITE` | `AUTO` | SQLite result store |

`AUTO` means "use it if `find_package`/`find_library` succeeds, otherwise fall back
silently". `ON` makes a missing library a configure error, `OFF` skips the search
entirely — useful for reproducible builds.

```bash
# Fully self-contained build, no external libraries at all
cmake -S . -B build \
  -DNETRA_USE_LIBPCAP=OFF -DNETRA_USE_PCAPPLUSPLUS=OFF \
  -DNETRA_USE_BOOST=OFF -DNETRA_USE_OPENSSL=OFF -DNETRA_USE_SQLITE=OFF

# Strict build for development
cmake -S . -B build -DNETRA_WERROR=ON -DNETRA_SANITIZE=ON
```

## 5. Optional dependencies in detail

| Library | What it enables | Built-in fallback |
| --- | --- | --- |
| **libpcap / Npcap** | Live capture through the standard API, kernel BPF capture filters, pcap-ng writing | Linux `AF_PACKET` capture backend, own pcap/pcap-ng reader and writer, own display-filter engine |
| **PcapPlusPlus** | Alternative capture backend and packet parsing | own decoder stack |
| **Boost.Asio** | Asynchronous connect scanning with a strand-based scheduler | `poll()`-driven concurrent connect scanner with a token-bucket rate limiter |
| **OpenSSL** | Real TLS handshakes for service detection, full X.509 parsing | own TLS record parser (handshake type, version, SNI, cipher suites) and minimal DER/X.509 reader |
| **SQLite3** | SQL result store (`scans`, `hosts`, `captures`, `flows`, `packets`) | JSON Lines store with the same query API (`netra store`) |

Backend selection at runtime (`capture::createCaptureSource`):

1. `readFile` set → pcap/pcap-ng file reader
2. `syntheticScenario` set → built-in traffic generator
3. otherwise live capture → libpcap → PcapPlusPlus → `AF_PACKET` (Linux)

`netra interfaces` and `netra version` list every backend compiled into the binary and
whether it is *usable* in the current environment (for example `afpacket` reports
*limited* when raw sockets are not permitted).

### Finding libraries in unusual locations

```bash
cmake -S . -B build \
  -DCMAKE_PREFIX_PATH="/opt/npcap;/opt/boost" \
  -DOPENSSL_ROOT_DIR=/opt/openssl \
  -DSQLITE3_INCLUDE_DIR=/opt/sqlite/include
```

On Windows with Npcap, install the SDK and point `CMAKE_PREFIX_PATH` at it; the Npcap
`wpcap.lib`/`Packet.lib` pair is picked up by the standard `FindPCAP` logic in
`cmake/NetraDependencies.cmake`.

## 6. Platform notes

**Linux** — `AF_PACKET` capture needs `CAP_NET_RAW`/`CAP_NET_ADMIN` (or root). Raw-socket
scans (`-sS`, `-sA`, `-sU`, ARP/ICMP discovery) need the same. Everything else, including
the default connect scan, runs unprivileged. To grant the capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./build/bin/netra
```

**macOS** — no `AF_PACKET`; live capture requires libpcap (preinstalled) and root or
`/dev/bpf*` access. BSD loopback (`DLT_NULL`) captures are decoded correctly.

**Windows** — partial and not covered by CI. The networking layer has Winsock paths
(`net::socket_t`, `WSAPoll`, `GetAdaptersAddresses`) and the scanner's probe loop is
portable, so pcap file analysis and `connect()` scans are the intended Windows feature
set; Npcap in WinPcap API-compatible mode supplies live capture. The dashboard server
still includes POSIX socket headers, so `netra dashboard` does not build there yet.
Target Visual Studio 2019+ or MinGW-w64 GCC and expect to finish that port yourself.

## 7. Sanitizers and warnings

```bash
cmake -S . -B build -DNETRA_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j && ./build/bin/netra_tests
```

The project compiles cleanly with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wsign-conversion` (see `cmake/NetraCompilerFlags.cmake`); conversion warnings are enabled
but not fatal by default so that third-party headers do not break the build. Turn on
`NETRA_WERROR=ON` in CI or when touching the codebase.

## 8. Cross-compiling / minimal environments

Netra has no runtime dependencies beyond libc++/libstdc++ and pthreads, so a static build
is straightforward:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++"
```

For containers, a two-stage build (compile in `gcc:13`, copy `build/bin/netra` into a
`debian:slim` runtime) produces an image of a few megabytes.

## 9. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `cannot open capture source: operation not permitted` | Live capture needs privileges — use `sudo`, `setcap`, or `netra demo` |
| `afpacket … limited` in `netra interfaces` | Raw sockets are blocked in this environment (containers/seccomp); unprivileged scanning and file analysis still work |
| `SQLite was not found at build time` in `netra store` | Expected fallback: the JSON Lines store is used instead. Install `libsqlite3-dev` and reconfigure for SQL |
| CMake error `Compatibility with CMake < 3.5 has been removed` | You are on CMake 4.x with an old dependency's `find_package` module; Netra itself requires ≥ 3.16 |
| Dashboard shows a stale UI after editing `web/` | Assets are embedded at build time — rebuild, or run with `--web-root web/` |
| `netra scan` reports every port `filtered` | A firewall drops the probes; try `-sT` with a longer `--timeout`, or `-Pn` to skip discovery |

# SPDX-License-Identifier: MIT
#
# Netra - network reconnaissance & packet analysis toolkit
#
# The build works with nothing but a C++17 compiler: every third-party library
# (libpcap, Boost.Asio, OpenSSL, SQLite3, PcapPlusPlus) is optional and enables
# an additional backend when it is present. Run `cmake --build . --target help`
# or see docs/building.md for details.

cmake_minimum_required(VERSION 3.16)

project(netra
        VERSION 0.1.0
        DESCRIPTION "Network reconnaissance and packet analysis toolkit"
        LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# --------------------------------------------------------------------- options
option(NETRA_BUILD_TESTS "Build the unit test suite" ON)
option(NETRA_BUILD_TOOLS "Build helper tools (sample pcap generator)" ON)
option(NETRA_EMBED_WEB "Embed the web dashboard assets into the binary" ON)
option(NETRA_WERROR "Treat compiler warnings as errors" OFF)
option(NETRA_SANITIZE "Build with address/undefined behaviour sanitizers" OFF)

set(NETRA_USE_LIBPCAP "AUTO" CACHE STRING "Use libpcap/Npcap for capture (AUTO/ON/OFF)")
set(NETRA_USE_BOOST "AUTO" CACHE STRING "Use Boost.Asio for asynchronous scanning (AUTO/ON/OFF)")
set(NETRA_USE_OPENSSL "AUTO" CACHE STRING "Use OpenSSL for TLS service probing (AUTO/ON/OFF)")
set(NETRA_USE_SQLITE "AUTO" CACHE STRING "Use SQLite for the result database (AUTO/ON/OFF)")
set(NETRA_USE_PCAPPLUSPLUS "AUTO" CACHE STRING "Use PcapPlusPlus for capture/parsing (AUTO/ON/OFF)")
set_property(CACHE NETRA_USE_LIBPCAP PROPERTY STRINGS AUTO ON OFF)
set_property(CACHE NETRA_USE_BOOST PROPERTY STRINGS AUTO ON OFF)
set_property(CACHE NETRA_USE_OPENSSL PROPERTY STRINGS AUTO ON OFF)
set_property(CACHE NETRA_USE_SQLITE PROPERTY STRINGS AUTO ON OFF)
set_property(CACHE NETRA_USE_PCAPPLUSPLUS PROPERTY STRINGS AUTO ON OFF)

include(NetraCompilerFlags)
include(NetraDependencies)

netra_detect_compiler_flags()
netra_find_dependencies()

# ------------------------------------------------------------- build metadata
if(NETRA_EMBED_WEB)
    set(NETRA_EMBEDDED_WEB 1)
else()
    set(NETRA_EMBEDDED_WEB 0)
endif()

string(TIMESTAMP NETRA_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ" UTC)
execute_process(COMMAND git rev-parse --short HEAD
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE NETRA_GIT_COMMIT
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
if(NOT NETRA_GIT_COMMIT)
    set(NETRA_GIT_COMMIT "unknown")
endif()

configure_file(${CMAKE_SOURCE_DIR}/cmake/config.h.in
               ${CMAKE_BINARY_DIR}/generated/netra/config.h @ONLY)

include(NetraEmbedWeb)

# ------------------------------------------------------------------ libraries
include(NetraModules)

# Embeds web/* into a generated header used by the dashboard module.
netra_embed_web(netra_dashboard)

# ----------------------------------------------------------------- executable
file(GLOB NETRA_APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/app/*.cpp)
netra_add_executable(netra ${NETRA_APP_SOURCES})
target_link_libraries(netra PRIVATE netra_dashboard netra_report netra_storage netra_scan netra_analysis
                                    netra_filter netra_decode netra_capture netra_net netra_core)
target_include_directories(netra PRIVATE ${CMAKE_SOURCE_DIR}/src)

set_target_properties(netra PROPERTIES OUTPUT_NAME netra)

# ------------------------------------------------------------------ artifacts
if(NETRA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(NETRA_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

include(GNUInstallDirs)
install(TARGETS netra RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/netra DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES README.md LICENSE description.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

netra_print_summary()

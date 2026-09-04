# SPDX-License-Identifier: MIT
#
# Netra is built as a set of static module libraries that mirror the layout in
# docs/architecture.md:
#
#   netra_core      logging, errors, JSON, CLI parsing, utilities
#   netra_net       interfaces, addresses, routing, sockets, checksums
#   netra_capture   capture sources (AF_PACKET, libpcap, PcapPlusPlus, pcap files)
#   netra_decode    protocol decoders (Ethernet..DNS/HTTP/TLS)
#   netra_filter    Wireshark-style display filter engine
#   netra_scan      host discovery, port scanning, service detection
#   netra_analysis  flow/session tracking and traffic statistics
#   netra_report    text/JSON/CSV rendering of every result type
#   netra_storage   persistence (JSON store, optional SQLite)
#   netra_dashboard embedded HTTP server + web UI

function(netra_add_module name)
    cmake_parse_arguments(ARG "" "DIR" "DEPENDS;OPTIONAL" ${ARGN})
    # Sources live in src/<name without the netra_ prefix> unless DIR says otherwise.
    set(_dir "${ARG_DIR}")
    if(NOT _dir)
        string(REGEX REPLACE "^netra_" "" _dir "${name}")
    endif()
    file(GLOB _sources CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/${_dir}/*.cpp)
    if(NOT _sources)
        message(FATAL_ERROR "netra module '${name}' has no sources in src/${_dir}")
    endif()
    add_library(${name} STATIC ${_sources})
    add_library(netra::${name} ALIAS ${name})
    target_include_directories(${name}
        PUBLIC  ${CMAKE_SOURCE_DIR}/include
        PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/generated)
    target_link_libraries(${name} PUBLIC netra_flags)
    if(ARG_DEPENDS)
        target_link_libraries(${name} PUBLIC ${ARG_DEPENDS})
    endif()
    if(ARG_OPTIONAL)
        foreach(dep IN LISTS ARG_OPTIONAL)
            if(TARGET ${dep})
                target_link_libraries(${name} PRIVATE ${dep})
            endif()
        endforeach()
    endif()
endfunction()

function(netra_add_executable name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name}
        PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/generated)
    target_link_libraries(${name} PRIVATE netra_flags)
endfunction()

# Optional backend interface libraries (only created when the dependency exists).
if(NETRA_HAVE_LIBPCAP)
    add_library(pcap_backend INTERFACE)
    target_include_directories(pcap_backend INTERFACE ${NETRA_LIBPCAP_INCLUDE_DIR})
    target_link_libraries(pcap_backend INTERFACE ${NETRA_LIBPCAP_LIBRARY})
    target_compile_definitions(pcap_backend INTERFACE NETRA_LIBPCAP_ENABLED=1)
endif()

if(NETRA_HAVE_PCAPPLUSPLUS)
    add_library(pcapplusplus_backend INTERFACE)
    target_link_libraries(pcapplusplus_backend INTERFACE PcapPlusPlus::PcapPlusPlus)
    target_compile_definitions(pcapplusplus_backend INTERFACE NETRA_PCAPPLUSPLUS_ENABLED=1)
endif()

if(NETRA_HAVE_BOOST_ASIO)
    add_library(asio_backend INTERFACE)
    target_include_directories(asio_backend INTERFACE ${NETRA_BOOST_INCLUDE_DIR})
    if(NETRA_BOOST_LIBRARY)
        target_link_libraries(asio_backend INTERFACE ${NETRA_BOOST_LIBRARY})
    endif()
    target_compile_definitions(asio_backend INTERFACE NETRA_BOOST_ASIO_ENABLED=1
                                                      BOOST_ASIO_DISABLE_CONCEPTS=1)
endif()

if(NETRA_HAVE_OPENSSL)
    add_library(tls_backend INTERFACE)
    target_link_libraries(tls_backend INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(tls_backend INTERFACE NETRA_OPENSSL_ENABLED=1)
endif()

if(NETRA_HAVE_SQLITE)
    add_library(sqlite_backend INTERFACE)
    target_link_libraries(sqlite_backend INTERFACE SQLite::SQLite3)
    target_compile_definitions(sqlite_backend INTERFACE NETRA_SQLITE_ENABLED=1)
endif()

# --------------------------------------------------------------------- modules
netra_add_module(netra_core
    DEPENDS Threads::Threads)

netra_add_module(netra_net
    DEPENDS netra_core)

netra_add_module(netra_capture
    DEPENDS netra_core netra_net
    OPTIONAL pcap_backend pcapplusplus_backend)

netra_add_module(netra_decode
    DEPENDS netra_core netra_net netra_capture
    OPTIONAL pcapplusplus_backend)

netra_add_module(netra_filter
    DEPENDS netra_core netra_decode)

netra_add_module(netra_scan
    DEPENDS netra_core netra_net
    OPTIONAL asio_backend tls_backend)

netra_add_module(netra_analysis
    DEPENDS netra_core netra_net netra_decode netra_filter)

netra_add_module(netra_report
    DEPENDS netra_core netra_net netra_decode netra_filter netra_scan netra_analysis)

netra_add_module(netra_storage
    DEPENDS netra_core netra_net netra_scan netra_analysis
    OPTIONAL sqlite_backend)

netra_add_module(netra_dashboard
    DEPENDS netra_core netra_net netra_capture netra_decode netra_filter netra_scan
            netra_analysis netra_report netra_storage)


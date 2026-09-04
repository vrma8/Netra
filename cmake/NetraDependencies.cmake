# SPDX-License-Identifier: MIT
#
# Optional dependency detection.
#
# Every dependency below is *optional*: Netra ships built-in fallbacks so the
# tool builds and runs with nothing but a C++ compiler. When a library is found
# it unlocks an additional backend:
#
#   libpcap / Npcap  -> native capture backend + kernel BPF filters
#   PcapPlusPlus     -> accelerated live/file capture backend
#   Boost.Asio       -> asynchronous TCP connect prober
#   OpenSSL          -> TLS service probing (certificate inspection)
#   SQLite3          -> persistent scan/result database
#
# Set NETRA_USE_<DEP>=ON to require it (configuration fails when missing) or OFF
# to skip detection entirely.

find_package(Threads REQUIRED)

function(_netra_report name found detail)
    if(found)
        message(STATUS "  ${name}: ${detail}")
    else()
        message(STATUS "  ${name}: not found (built-in fallback will be used)")
    endif()
endfunction()

function(netra_find_dependencies)
    if(POLICY CMP0167)
        cmake_policy(SET CMP0167 OLD)  # keep using the bundled FindBoost module
    endif()
    message(STATUS "Netra: detecting optional dependencies")

    # ---------------------------------------------------------------- libpcap
    if(NOT NETRA_USE_LIBPCAP STREQUAL "OFF")
        if(WIN32)
            set(_pcap_roots "$ENV{NPCAP_SDK_DIR}" "C:/npcap" "C:/WpdPack")
            foreach(root IN LISTS _pcap_roots)
                if(root AND EXISTS "${root}")
                    list(APPEND CMAKE_PREFIX_PATH "${root}")
                endif()
            endforeach()
        endif()
        find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h)
        find_library(PCAP_LIBRARY NAMES pcap wpcap pcap_static)
        if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
            set(NETRA_HAVE_LIBPCAP 1 CACHE INTERNAL "libpcap available")
            set(NETRA_LIBPCAP_INCLUDE_DIR "${PCAP_INCLUDE_DIR}" CACHE INTERNAL "")
            set(NETRA_LIBPCAP_LIBRARY "${PCAP_LIBRARY}" CACHE INTERNAL "")
            _netra_report("libpcap" TRUE "${PCAP_LIBRARY}")
        else()
            set(NETRA_HAVE_LIBPCAP 0 CACHE INTERNAL "libpcap available")
            _netra_report("libpcap" FALSE "")
            if(NETRA_USE_LIBPCAP STREQUAL "ON")
                message(FATAL_ERROR "NETRA_USE_LIBPCAP=ON but libpcap/Npcap was not found")
            endif()
        endif()
    else()
        set(NETRA_HAVE_LIBPCAP 0 CACHE INTERNAL "libpcap available")
    endif()

    # ------------------------------------------------------------- Boost.Asio
    if(NOT NETRA_USE_BOOST STREQUAL "OFF")
        find_package(Boost QUIET COMPONENTS system)
        if(Boost_FOUND AND EXISTS "${Boost_INCLUDE_DIR}/boost/asio.hpp")
            set(NETRA_HAVE_BOOST_ASIO 1 CACHE INTERNAL "Boost.Asio available")
            set(NETRA_BOOST_INCLUDE_DIR "${Boost_INCLUDE_DIR}" CACHE INTERNAL "")
            if(TARGET Boost::system)
                set(NETRA_BOOST_LIBRARY "Boost::system" CACHE INTERNAL "")
            else()
                set(NETRA_BOOST_LIBRARY "" CACHE INTERNAL "")
            endif()
            _netra_report("Boost.Asio" TRUE "${Boost_INCLUDE_DIR}")
        else()
            set(NETRA_HAVE_BOOST_ASIO 0 CACHE INTERNAL "Boost.Asio available")
            _netra_report("Boost.Asio" FALSE "")
            if(NETRA_USE_BOOST STREQUAL "ON")
                message(FATAL_ERROR "NETRA_USE_BOOST=ON but Boost.Asio was not found")
            endif()
        endif()
    else()
        set(NETRA_HAVE_BOOST_ASIO 0 CACHE INTERNAL "Boost.Asio available")
    endif()

    # ---------------------------------------------------------------- OpenSSL
    if(NOT NETRA_USE_OPENSSL STREQUAL "OFF")
        find_package(OpenSSL QUIET)
        if(OPENSSL_FOUND)
            set(NETRA_HAVE_OPENSSL 1 CACHE INTERNAL "OpenSSL available")
            _netra_report("OpenSSL" TRUE "${OPENSSL_VERSION}")
        else()
            set(NETRA_HAVE_OPENSSL 0 CACHE INTERNAL "OpenSSL available")
            _netra_report("OpenSSL" FALSE "")
            if(NETRA_USE_OPENSSL STREQUAL "ON")
                message(FATAL_ERROR "NETRA_USE_OPENSSL=ON but OpenSSL was not found")
            endif()
        endif()
    else()
        set(NETRA_HAVE_OPENSSL 0 CACHE INTERNAL "OpenSSL available")
    endif()

    # ----------------------------------------------------------------- SQLite
    if(NOT NETRA_USE_SQLITE STREQUAL "OFF")
        find_package(SQLite3 QUIET)
        if(SQLite3_FOUND)
            set(NETRA_HAVE_SQLITE 1 CACHE INTERNAL "SQLite3 available")
            _netra_report("SQLite3" TRUE "${SQLite3_VERSION}")
        else()
            set(NETRA_HAVE_SQLITE 0 CACHE INTERNAL "SQLite3 available")
            _netra_report("SQLite3" FALSE "")
            if(NETRA_USE_SQLITE STREQUAL "ON")
                message(FATAL_ERROR "NETRA_USE_SQLITE=ON but SQLite3 was not found")
            endif()
        endif()
    else()
        set(NETRA_HAVE_SQLITE 0 CACHE INTERNAL "SQLite3 available")
    endif()

    # ----------------------------------------------------------- PcapPlusPlus
    if(NOT NETRA_USE_PCAPPLUSPLUS STREQUAL "OFF")
        find_package(PcapPlusPlus QUIET)
        if(PCAPPLUSPLUS_FOUND)
            set(NETRA_HAVE_PCAPPLUSPLUS 1 CACHE INTERNAL "PcapPlusPlus available")
            _netra_report("PcapPlusPlus" TRUE "${PCAPPLUSPLUS_VERSION}")
        else()
            set(NETRA_HAVE_PCAPPLUSPLUS 0 CACHE INTERNAL "PcapPlusPlus available")
            _netra_report("PcapPlusPlus" FALSE "")
            if(NETRA_USE_PCAPPLUSPLUS STREQUAL "ON")
                message(FATAL_ERROR "NETRA_USE_PCAPPLUSPLUS=ON but PcapPlusPlus was not found")
            endif()
        endif()
    else()
        set(NETRA_HAVE_PCAPPLUSPLUS 0 CACHE INTERNAL "PcapPlusPlus available")
    endif()
endfunction()

function(netra_print_summary)
    message(STATUS "")
    message(STATUS "Netra ${PROJECT_VERSION} configuration summary")
    message(STATUS "  build type         : ${CMAKE_BUILD_TYPE}")
    message(STATUS "  compiler           : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    message(STATUS "  libpcap backend    : ${NETRA_HAVE_LIBPCAP}")
    message(STATUS "  PcapPlusPlus       : ${NETRA_HAVE_PCAPPLUSPLUS}")
    message(STATUS "  Boost.Asio scanner : ${NETRA_HAVE_BOOST_ASIO}")
    message(STATUS "  OpenSSL TLS probe  : ${NETRA_HAVE_OPENSSL}")
    message(STATUS "  SQLite storage     : ${NETRA_HAVE_SQLITE}")
    message(STATUS "  embedded dashboard : ${NETRA_EMBED_WEB}")
    message(STATUS "  tests              : ${NETRA_BUILD_TESTS}")
    message(STATUS "")
endfunction()

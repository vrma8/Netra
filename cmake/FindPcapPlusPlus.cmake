# SPDX-License-Identifier: MIT
#
# FindPcapPlusPlus
# ----------------
# Locates a PcapPlusPlus installation (headers + Packet++/Common++/Pcap++ libs)
# and exposes an imported target `PcapPlusPlus::PcapPlusPlus`.
#
# Result variables:
#   PCAPPLUSPLUS_FOUND
#   PCAPPLUSPLUS_INCLUDE_DIRS
#   PCAPPLUSPLUS_LIBRARIES
#   PCAPPLUSPLUS_VERSION
#
# Hints: PCAPPLUSPLUS_ROOT, -DPCAPPLUSPLUS_ROOT=..., common install prefixes.

if(PCAPPLUSPLUS_FOUND)
    return()
endif()

set(_pcpp_hints
    ${PCAPPLUSPLUS_ROOT}
    $ENV{PCAPPLUSPLUS_ROOT}
    /usr/local
    /usr
    /opt/pcapplusplus
    C:/PcapPlusPlus
)

find_path(PCAPPLUSPLUS_INCLUDE_DIR
          NAMES Packet++.h Pcap++.h Packet.h
          HINTS ${_pcpp_hints}
          PATH_SUFFIXES include pcapplusplus include/pcapplusplus)

set(_pcpp_lib_names Packet++ Common++ Pcap++ packet++ common++ pcap++)
set(PCAPPLUSPLUS_LIBRARIES "")
set(_pcpp_missing "")

foreach(_name IN LISTS _pcpp_lib_names)
    find_library(PCAPPLUSPLUS_${_name}_LIBRARY
                 NAMES ${_name}
                 HINTS ${_pcpp_hints}
                 PATH_SUFFIXES lib lib64 lib/x86_64-linux-gnu)
    if(PCAPPLUSPLUS_${_name}_LIBRARY)
        list(APPEND PCAPPLUSPLUS_LIBRARIES ${PCAPPLUSPLUS_${_name}_LIBRARY})
    else()
        list(APPEND _pcpp_missing ${_name})
    endif()
endforeach()

if(PCAPPLUSPLUS_INCLUDE_DIR)
    # Version is only available from the packaged header (21.11+).
    file(STRINGS "${PCAPPLUSPLUS_INCLUDE_DIR}/PcapPlusPlusVer.h" _pcpp_version_line
         REGEX "#define[ \t]+PCAPPLUSPLUS_VERSION[ \t]+" LIMIT_COUNT 1)
    if(_pcpp_version_line)
        string(REGEX REPLACE ".*#define[ \t]+PCAPPLUSPLUS_VERSION[ \t]+\"?([0-9.]+)\"?.*" "\\1"
               PCAPPLUSPLUS_VERSION "${_pcpp_version_line}")
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PcapPlusPlus
                                  REQUIRED_VARS PCAPPLUSPLUS_INCLUDE_DIR PCAPPLUSPLUS_LIBRARIES
                                  VERSION_VAR PCAPPLUSPLUS_VERSION)

if(PCAPPLUSPLUS_FOUND AND NOT TARGET PcapPlusPlus::PcapPlusPlus)
    add_library(PcapPlusPlus::PcapPlusPlus INTERFACE IMPORTED)
    set_target_properties(PcapPlusPlus::PcapPlusPlus PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${PCAPPLUSPLUS_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${PCAPPLUSPLUS_LIBRARIES}")
endif()

mark_as_advanced(PCAPPLUSPLUS_INCLUDE_DIR PCAPPLUSPLUS_LIBRARIES)

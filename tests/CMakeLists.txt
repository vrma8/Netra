# SPDX-License-Identifier: MIT
# Netra test suite: a single binary with a tiny built-in runner, registered with
# CTest once as a whole and once per suite so failures are easy to narrow down.

file(GLOB NETRA_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/*.cpp)

netra_add_executable(netra_tests ${NETRA_TEST_SOURCES})
target_include_directories(netra_tests PRIVATE ${CMAKE_SOURCE_DIR}/tests)
# GCC's optimiser reports bogus -Warray-bounds/-Wnull-dereference findings for the
# checksum tests, which deliberately feed corrupted frames through inline byte views.
# Keep every other warning fatal so the suite cannot rot silently.
if(NETRA_WERROR AND NOT MSVC)
    target_compile_options(netra_tests PRIVATE -Wno-error=array-bounds -Wno-error=null-dereference)
endif()

target_link_libraries(netra_tests PRIVATE
    netra_dashboard netra_storage netra_report netra_analysis netra_filter
    netra_scan netra_decode netra_capture netra_net netra_core)

set(NETRA_TEST_SUITES
    core net decode filter capture analysis scan report storage dashboard)

add_test(NAME netra_tests COMMAND netra_tests)
set_tests_properties(netra_tests PROPERTIES TIMEOUT 600)

foreach(suite IN LISTS NETRA_TEST_SUITES)
    add_test(NAME suite_${suite} COMMAND netra_tests --suite ${suite})
    set_tests_properties(suite_${suite} PROPERTIES TIMEOUT 300)
endforeach()

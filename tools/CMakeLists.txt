# SPDX-License-Identifier: MIT
# Helper tools that ship with Netra.

netra_add_executable(netra-pcapgen pcapgen.cpp)
target_link_libraries(netra-pcapgen PRIVATE netra_capture netra_decode netra_analysis netra_net netra_core)

install(TARGETS netra-pcapgen RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

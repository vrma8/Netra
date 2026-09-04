# SPDX-License-Identifier: MIT
# Compiler warning/feature flags shared by every Netra target.

add_library(netra_flags INTERFACE)

function(netra_detect_compiler_flags)
    target_compile_features(netra_flags INTERFACE cxx_std_17)

    if(MSVC)
        target_compile_options(netra_flags INTERFACE /W4 /permissive- /Zc:__cplusplus /utf-8
                                                     /wd4100 /wd4127 /wd4244 /wd4267 /wd4459)
        target_compile_definitions(netra_flags INTERFACE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN
                                                         NOMINMAX _WINSOCK_DEPRECATED_NO_WARNINGS)
        if(NETRA_WERROR)
            target_compile_options(netra_flags INTERFACE /WX)
        endif()
    else()
        target_compile_options(netra_flags INTERFACE
            -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused
            -Woverloaded-virtual -Wpedantic -Wconversion -Wsign-conversion -Wnull-dereference
            -Wdouble-promotion -Wimplicit-fallthrough -Wno-unused-parameter)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(netra_flags INTERFACE -fno-omit-frame-pointer)
        endif()
        if(NETRA_WERROR)
            target_compile_options(netra_flags INTERFACE -Werror)
        endif()
    endif()

    if(NETRA_SANITIZE)
        target_compile_options(netra_flags INTERFACE -fsanitize=address,undefined -fno-sanitize-recover=all)
        target_link_options(netra_flags INTERFACE -fsanitize=address,undefined)
    endif()

    if(UNIX AND NOT APPLE)
        target_link_libraries(netra_flags INTERFACE pthread dl)
    endif()
    if(WIN32)
        target_link_libraries(netra_flags INTERFACE ws2_32 iphlpapi wsock32)
    endif()
endfunction()

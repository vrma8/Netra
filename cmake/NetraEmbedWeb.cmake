# SPDX-License-Identifier: MIT
#
# Embeds the web dashboard assets (web/*) into a generated C++ header so the
# `netra dashboard` command ships as a single self-contained binary.
#
# Generated header: ${CMAKE_BINARY_DIR}/generated/netra/web_assets.h

function(netra_embed_web target)
    set(_web_dir ${CMAKE_SOURCE_DIR}/web)
    set(_out ${CMAKE_BINARY_DIR}/generated/netra/web_assets.h)
    if(NETRA_EMBED_WEB)
        add_custom_command(
            OUTPUT ${_out}
            COMMAND ${CMAKE_COMMAND}
                    -DIN_DIR=${_web_dir}
                    -DOUT_FILE=${_out}
                    -P ${CMAKE_SOURCE_DIR}/cmake/embed_web.cmake
            DEPENDS ${CMAKE_SOURCE_DIR}/cmake/embed_web.cmake
                    ${_web_dir}/index.html ${_web_dir}/app.js ${_web_dir}/style.css
                    ${_web_dir}/favicon.svg
            COMMENT "Embedding web dashboard assets"
            VERBATIM)
        add_custom_target(${target}_web_assets DEPENDS ${_out})
        add_dependencies(${target} ${target}_web_assets)
        target_compile_definitions(${target} PRIVATE NETRA_WEB_ASSETS_HEADER=\"netra/web_assets.h\")
    else()
        target_compile_definitions(${target} PRIVATE NETRA_WEB_ASSETS_DIR=\"${_web_dir}\")
    endif()
endfunction()

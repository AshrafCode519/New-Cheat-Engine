cmake_minimum_required(VERSION 3.20)
project(nce_gui LANGUAGES CXX)

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/imgui)

# Dear ImGui with Win32+DX11 on Windows and SDL2+OpenGL3 on Linux (third-party code: built without our warnings)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/misc/cpp/imgui_stdlib.cpp
)

if (WIN32)
    list(APPEND IMGUI_SOURCES
        ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
        ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    )
else()
    list(APPEND IMGUI_SOURCES
        ${IMGUI_DIR}/backends/imgui_impl_sdl2.cpp
        ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    )
endif()

add_library(imgui STATIC ${IMGUI_SOURCES})
target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMGUI_DIR}/misc/cpp
)
if (MSVC)
    target_compile_options(imgui PRIVATE /w)
else()
    target_compile_options(imgui PRIVATE -w)
endif()

set(NCE_GUI_SOURCES
    src/main.cpp
    src/app_common.cpp
    src/tabs/scanner_table_tab.cpp
    src/tabs/memory_tabs.cpp
    src/tabs/re_debugger_tabs.cpp
    src/tabs/tools_tabs.cpp
)

if (WIN32)
    target_link_libraries(imgui PUBLIC d3d11 d3dcompiler dxgi dwmapi gdi32)
    add_executable(nce_gui WIN32 ${NCE_GUI_SOURCES})
    target_include_directories(nce_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../third_party)
    target_link_libraries(nce_gui PRIVATE engine imgui shell32)
else()
    if (TARGET SDL2::SDL2)
        target_link_libraries(imgui PUBLIC SDL2::SDL2)
    elseif (SDL2_PKG_FOUND)
        target_include_directories(imgui SYSTEM PUBLIC ${SDL2_PKG_INCLUDE_DIRS})
        target_link_libraries(imgui PUBLIC ${SDL2_PKG_LIBRARIES})
    else()
        target_include_directories(imgui SYSTEM PUBLIC ${SDL2_INCLUDE_DIRS})
        target_link_libraries(imgui PUBLIC ${SDL2_LIBRARIES})
    endif()
    target_link_libraries(imgui PUBLIC OpenGL::GL ${CMAKE_DL_LIBS})
    add_executable(nce_gui ${NCE_GUI_SOURCES})
    target_include_directories(nce_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../third_party)
    target_link_libraries(nce_gui PRIVATE engine imgui)
endif()

cmake_minimum_required(VERSION 3.20)
project(nce_gui LANGUAGES CXX)

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/imgui)

# Dear ImGui with the Win32 + DirectX 11 backends (third-party code: built without our warnings)
add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    ${IMGUI_DIR}/misc/cpp/imgui_stdlib.cpp
)
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
target_link_libraries(imgui PUBLIC d3d11 d3dcompiler dxgi dwmapi gdi32)

add_executable(nce_gui WIN32 src/main.cpp)
target_link_libraries(nce_gui PRIVATE engine imgui shell32)

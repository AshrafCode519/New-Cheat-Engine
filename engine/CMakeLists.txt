cmake_minimum_required(VERSION 3.20)
project(engine LANGUAGES CXX)

add_library(engine STATIC
    src/hal/process_win32.cpp
    src/hal/hotkeys.cpp
    src/hal/hotkeys_win32.cpp
    src/scanner/memory_scanner.cpp
    src/scanner/scan_results.cpp
    src/scanner/pointer_scanner.cpp
    src/scanner/grouped_scanner.cpp
    src/scanner/value_tracker.cpp
    src/scanner/noise_map.cpp
    src/utils/hex_utils.cpp
    src/utils/text_encoding.cpp
    src/table/cheat_table.cpp
    src/session/scan_session.cpp
    src/session/session.cpp
    src/view/memory_view.cpp
)

target_include_directories(engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Header-only JSON library used by the cheat table code (not exposed in engine headers)
target_include_directories(engine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party
)

if (WIN32)
    target_link_libraries(engine PUBLIC psapi)
endif()


cmake_minimum_required(VERSION 3.20)
project(engine LANGUAGES CXX)

add_library(engine STATIC
    src/hal/process_win32.cpp
    src/scanner/memory_scanner.cpp
    src/scanner/scan_results.cpp
    src/scanner/pointer_scanner.cpp
    src/scanner/grouped_scanner.cpp
    src/utils/hex_utils.cpp
)

target_include_directories(engine PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (WIN32)
    target_link_libraries(engine PUBLIC psapi)
endif()


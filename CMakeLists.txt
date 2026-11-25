cmake_minimum_required(VERSION 3.20)
project(NewCheatEngine VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Enable compiler warnings & optimizations
if (MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

# Shared VEH agent DLL must NOT inherit global -static flag on MinGW
if (WIN32)
    add_subdirectory(veh_agent)
endif()

if (MINGW)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

# Subdirectories
add_subdirectory(third_party/lua)
add_subdirectory(engine)
add_subdirectory(target_dummy)
add_subdirectory(cli)
if (WIN32)
    add_subdirectory(gui)
endif()

option(NCE_BUILD_TESTS "Build the engine unit tests" ON)
if (NCE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

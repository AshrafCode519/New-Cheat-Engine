cmake_minimum_required(VERSION 3.20)
project(memscan_cli LANGUAGES CXX)

add_executable(memscan_cli
    src/main.cpp
)

target_link_libraries(memscan_cli PRIVATE engine)


cmake_minimum_required(VERSION 3.20)
project(target_dummy LANGUAGES CXX)

add_executable(target_dummy src/main.cpp)

if (WIN32)
    target_link_libraries(target_dummy PRIVATE)
endif()


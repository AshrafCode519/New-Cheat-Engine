cmake_minimum_required(VERSION 3.20)
project(nce_veh LANGUAGES CXX)

add_library(nce_veh SHARED veh_agent.cpp)

set_target_properties(nce_veh PROPERTIES
    PREFIX ""
    OUTPUT_NAME "nce_veh"
)

if (NOT MSVC)
    target_link_options(nce_veh PRIVATE -static-libgcc -static-libstdc++)
endif()

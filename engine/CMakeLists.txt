cmake_minimum_required(VERSION 3.20)
project(engine LANGUAGES CXX)

add_library(engine STATIC
    src/hal/process_win32.cpp
    src/hal/process_linux.cpp
    src/hal/injector_win32.cpp
    src/hal/hotkeys.cpp
    src/hal/hotkeys_win32.cpp
    src/hal/hotkeys_linux.cpp
    src/scanner/memory_scanner.cpp
    src/scanner/scan_results.cpp
    src/scanner/pointer_scanner.cpp
    src/scanner/grouped_scanner.cpp
    src/scanner/value_tracker.cpp
    src/scanner/noise_map.cpp
    src/scanner/strings_scanner.cpp
    src/scanner/simd_scanner.cpp
    src/utils/hex_utils.cpp
    src/utils/text_encoding.cpp
    src/utils/sig_generator.cpp
    src/view/vector_detector.cpp
    src/table/cheat_table.cpp
    src/table/ce_table_format.cpp
    src/table/standalone_generator.cpp
    src/session/scan_session.cpp
    src/session/session.cpp
    src/view/memory_view.cpp
    src/assembler/x86_assembler.cpp
    src/assembler/auto_assembler.cpp
    src/view/structure_dissector.cpp
    src/debugger/disassembler.cpp
    src/debugger/access_watcher_win32.cpp
    src/debugger/hook_engine.cpp
    src/speedhack/speedhack_win32.cpp
    src/view/memory_diff.cpp
    src/view/engine_inspector.cpp
    src/debugger/pe_analyzer.cpp
    src/debugger/elf_analyzer.cpp
    src/debugger/ultimap.cpp
    src/debugger/condition_eval.cpp
    src/debugger/debug_coordinator.cpp
    src/debugger/step_debugger.cpp
    src/script/lua_engine.cpp
)

target_include_directories(engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/lua/src
)

# Header-only JSON library used by the cheat table code (not exposed in engine headers)
target_include_directories(engine PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party
)

target_link_libraries(engine PUBLIC lua)

if (WIN32)
    target_link_libraries(engine PUBLIC psapi dbghelp)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(engine PUBLIC ${CMAKE_DL_LIBS} Threads::Threads)
endif()


add_executable(engine_tests
    test_main.cpp
    test_parsing.cpp
    test_memory_scanner.cpp
    test_compact_results.cpp
    test_pointer_scanner.cpp
    test_cheat_table.cpp
    test_value_tracker.cpp
    test_noise_map.cpp
    test_grouped_scanner.cpp
    test_text_encoding.cpp
    test_results_io.cpp
    test_win32_process.cpp
    test_session.cpp
    test_memory_view.cpp
    test_hotkeys.cpp
    test_table_library.cpp
    test_auto_assembler.cpp
    test_structure_dissector.cpp
    test_table_scripts.cpp
    test_ce_table_format.cpp
    test_strings_and_generator.cpp
    test_disassembler.cpp
    test_simd_scanner.cpp
    test_sig_and_vector.cpp
    test_emulator_be.cpp
    test_hook_speedhack.cpp
    test_pe_and_diff.cpp
    test_step_debugger.cpp
    test_lua_engine.cpp
    test_linux_hal.cpp
    test_debug_phase1.cpp
    test_phase2_scripting.cpp
    test_phase3_re.cpp
    test_phase4_platforms_engines.cpp
    test_phase5_completeness.cpp
    test_phase6_ux_tools.cpp
    test_phase7_re_and_maps.cpp
)

target_include_directories(engine_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party
)

target_link_libraries(engine_tests PRIVATE engine)

add_test(NAME engine_tests COMMAND engine_tests)

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
)

target_include_directories(engine_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party
)

target_link_libraries(engine_tests PRIVATE engine)

add_test(NAME engine_tests COMMAND engine_tests)

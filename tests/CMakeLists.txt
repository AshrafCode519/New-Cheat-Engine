add_executable(engine_tests
    test_main.cpp
    test_parsing.cpp
    test_memory_scanner.cpp
    test_compact_results.cpp
    test_text_encoding.cpp
    test_results_io.cpp
    test_win32_process.cpp
)

target_include_directories(engine_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party
)

target_link_libraries(engine_tests PRIVATE engine)

add_test(NAME engine_tests COMMAND engine_tests)

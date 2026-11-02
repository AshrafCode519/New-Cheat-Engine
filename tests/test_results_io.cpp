#include <doctest/doctest.h>
#include "scanner/scan_results.hpp"
#include <filesystem>
#include <fstream>

using namespace nce;
using scanner::DataType;
using scanner::ScanValue;

namespace {

std::string temp_file(const char* name) {
    return (std::filesystem::temp_directory_path() / name).string();
}

} // anonymous namespace

TEST_CASE("save_results / load_results round-trip every kind of value") {
    struct Case {
        DataType type;
        ScanValue value;
    };
    const Case cases[] = {
        {DataType::Int32, ScanValue::of(DataType::Int32, int32_t{-1337})},
        {DataType::UInt64, ScanValue::of(DataType::UInt64, uint64_t{0xA5A5A5A5A5A5ull})},
        {DataType::Double, ScanValue::of(DataType::Double, 12.3456)},
        {DataType::String, ScanValue::of(DataType::String, std::string("CyberWarrior"))},
        {DataType::String16, ScanValue::of(DataType::String16, std::vector<uint8_t>{'H', 0, 'i', 0})},
        {DataType::AOB, ScanValue::of(DataType::AOB, std::vector<uint8_t>{0x48, 0x8B, 0x05})},
    };

    const auto path = temp_file("nce_results_roundtrip.txt");
    for (const auto& c : cases) {
        CAPTURE(static_cast<int>(c.type));
        scanner::ScanResults results;
        results.add_match(0x7FF63E80A078, c.value, c.value);
        results.add_match(0x10, c.value, c.value);

        REQUIRE(scanner::save_results(path, 4242, c.type, results));
        auto loaded = scanner::load_results(path);
        REQUIRE(loaded.has_value());
        CHECK(loaded->pid == 4242);
        CHECK(loaded->type == c.type);
        REQUIRE(loaded->results.count() == 2);
        CHECK(loaded->results[0].address == 0x7FF63E80A078);
        CHECK(loaded->results[1].address == 0x10);
        CHECK(loaded->results[0].current_value.to_string() == c.value.to_string());
    }
    std::filesystem::remove(path);
}

TEST_CASE("load_results rejects missing and malformed files") {
    CHECK_FALSE(scanner::load_results(temp_file("nce_results_does_not_exist.txt")).has_value());

    const auto path = temp_file("nce_results_malformed.txt");
    const char* bad_files[] = {
        "not a results file\n",
        "NCE-RESULTS 1\ntype nope\npid 1\ncount 0\n",                 // unknown type
        "NCE-RESULTS 1\ntype i32\npid 1\ncount 2\n10 39050000\n",     // count mismatch
        "NCE-RESULTS 1\ntype i32\npid 1\ncount 1\n10 3905\n",         // 2 bytes for an i32
        "NCE-RESULTS 1\ntype i32\npid 1\ncount 1\nzz 39050000\n",     // bad address
    };
    for (const char* content : bad_files) {
        CAPTURE(content);
        { std::ofstream(path) << content; }
        CHECK_FALSE(scanner::load_results(path).has_value());
    }
    std::filesystem::remove(path);
}

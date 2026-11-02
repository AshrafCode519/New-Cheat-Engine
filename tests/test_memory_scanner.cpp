#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/memory_scanner.hpp"
#include "utils/hex_utils.hpp"
#include <memory>
#include <variant>

using namespace nce;
using scanner::DataType;
using scanner::ScanCondition;
using test::FakeProcess;
using test::contains_address;

namespace {

template <typename T>
scanner::ScanValue make_value(DataType type, T value) {
    scanner::ScanValue sv;
    sv.type = type;
    sv.value = value;
    return sv;
}

template <typename T>
void check_first_and_next(DataType type, T initial, T changed) {
    CAPTURE(static_cast<int>(type));
    auto process = std::make_shared<FakeProcess>(0x4000);
    scanner::MemoryScanner ms(process);

    const uintptr_t address = FakeProcess::kBase + 0x100;
    process->put<T>(0x100, initial);

    auto first = ms.first_scan(type, ScanCondition::ExactValue, make_value(type, initial), {}, sizeof(T));
    REQUIRE(first.count() == 1);
    CHECK(contains_address(first, address));

    // next_scan used to drop every result whose type was not i32/i64/f32/f64
    auto unchanged = ms.next_scan(first, ScanCondition::Unchanged);
    CHECK(contains_address(unchanged, address));

    process->put<T>(0x100, changed);
    auto moved = ms.next_scan(unchanged, ScanCondition::Changed);
    CHECK(contains_address(moved, address));

    auto exact = ms.next_scan(moved, ScanCondition::ExactValue, make_value(type, changed));
    CHECK(contains_address(exact, address));
}

// Every next-scan condition, for a value that went from 40 to 60 (small enough for i8/u8)
template <typename T>
void check_next_conditions(scanner::MemoryScanner& ms, const scanner::ScanResults& first, DataType type) {
    auto v = [type](T x) { return make_value(type, x); };

    // The value conditions used to compare against 0 instead of the given value
    CHECK(ms.next_scan(first, ScanCondition::ExactValue, v(T(60))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::ExactValue, v(T(40))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::GreaterThan, v(T(50))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::GreaterThan, v(T(80))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::LessThan, v(T(80))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::LessThan, v(T(50))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::Between, v(T(55)), v(T(65))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Between, v(T(1)), v(T(2))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::IncreasedBy, v(T(20))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::IncreasedBy, v(T(5))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::DecreasedBy, v(T(20))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::Changed).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Unchanged).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::Increased).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Decreased).count() == 0);
}

template <typename T>
void check_value_conditions(DataType type) {
    CAPTURE(static_cast<int>(type));
    auto process = std::make_shared<FakeProcess>(0x4000);
    scanner::MemoryScanner ms(process);
    auto v = [type](T x) { return make_value(type, x); };
    const uintptr_t address = FakeProcess::kBase + 0x200;

    process->put<T>(0x200, T(40));

    // First-scan conditions (the rest of the fake memory is 0)
    CHECK(ms.first_scan(type, ScanCondition::GreaterThan, v(T(30)), {}, sizeof(T)).count() == 1);
    CHECK(contains_address(ms.first_scan(type, ScanCondition::LessThan, v(T(50)), {}, sizeof(T)), address));
    CHECK(ms.first_scan(type, ScanCondition::Between, v(T(35)), v(T(45)), sizeof(T)).count() == 1);

    auto first = ms.first_scan(type, ScanCondition::ExactValue, v(T(40)), {}, sizeof(T));
    REQUIRE(first.count() == 1);
    process->put<T>(0x200, T(60));
    check_next_conditions<T>(ms, first, type);
}

template <typename T>
void check_unknown_initial_value(DataType type) {
    CAPTURE(static_cast<int>(type));
    auto process = std::make_shared<FakeProcess>(0x4000);
    scanner::MemoryScanner ms(process);
    auto v = [type](T x) { return make_value(type, x); };
    const uintptr_t address = FakeProcess::kBase + 0x300;

    process->put<T>(0x300, T(40));
    auto snapshot = ms.first_scan_unknown(type, sizeof(T));
    REQUIRE(snapshot.total_bytes() == 0x4000);
    process->put<T>(0x300, T(60));

    auto changed = ms.next_scan(snapshot, ScanCondition::Changed);
    REQUIRE(changed.count() == 1);
    CHECK(changed[0].address == address);
    CHECK(std::get<T>(changed[0].current_value.value) == T(60));
    CHECK(std::get<T>(changed[0].previous_value.value) == T(40));

    CHECK(ms.next_scan(snapshot, ScanCondition::Increased).count() == 1);
    CHECK(ms.next_scan(snapshot, ScanCondition::Decreased).count() == 0);
    CHECK(ms.next_scan(snapshot, ScanCondition::IncreasedBy, v(T(20))).count() == 1);
    CHECK(ms.next_scan(snapshot, ScanCondition::ExactValue, v(T(60))).count() == 1);
    CHECK_FALSE(contains_address(ms.next_scan(snapshot, ScanCondition::Unchanged), address));
    CHECK(ms.next_scan(snapshot, ScanCondition::Unchanged).count() == 0x4000 / sizeof(T) - 1);

    // The snapshot results feed a normal next scan, relative to the value they captured (60)
    auto from_snapshot = ms.next_scan(snapshot, ScanCondition::IncreasedBy, v(T(20)));
    process->put<T>(0x300, T(80));
    CHECK(ms.next_scan(from_snapshot, ScanCondition::IncreasedBy, v(T(20))).count() == 1);
    CHECK(ms.next_scan(from_snapshot, ScanCondition::Changed).count() == 1);
    CHECK(ms.next_scan(from_snapshot, ScanCondition::ExactValue, v(T(80))).count() == 1);
}

} // anonymous namespace

TEST_CASE("first_scan and next_scan work for every numeric type") {
    check_first_and_next<int8_t>(DataType::Int8, -5, 7);
    check_first_and_next<int16_t>(DataType::Int16, 1337, 1300);
    check_first_and_next<int32_t>(DataType::Int32, 424242, 424241);
    check_first_and_next<int64_t>(DataType::Int64, 5000000000LL, 4999999000LL);
    check_first_and_next<uint8_t>(DataType::UInt8, 200, 201);
    check_first_and_next<uint16_t>(DataType::UInt16, 60000, 59000);
    check_first_and_next<uint32_t>(DataType::UInt32, 3000000000u, 3000000001u);
    check_first_and_next<uint64_t>(DataType::UInt64, 0xA5A5A5A5A5ull, 0xA5A5A5A5A6ull);
    check_first_and_next<float>(DataType::Float, 250.5f, 248.0f);
    check_first_and_next<double>(DataType::Double, 12.3456, 12.5);
}

TEST_CASE("every first-scan and next-scan condition works for every numeric type") {
    check_value_conditions<int8_t>(DataType::Int8);
    check_value_conditions<int16_t>(DataType::Int16);
    check_value_conditions<int32_t>(DataType::Int32);
    check_value_conditions<int64_t>(DataType::Int64);
    check_value_conditions<uint8_t>(DataType::UInt8);
    check_value_conditions<uint16_t>(DataType::UInt16);
    check_value_conditions<uint32_t>(DataType::UInt32);
    check_value_conditions<uint64_t>(DataType::UInt64);
    check_value_conditions<float>(DataType::Float);
    check_value_conditions<double>(DataType::Double);
}

TEST_CASE("unknown initial value: snapshot, then compare live memory against it") {
    check_unknown_initial_value<int8_t>(DataType::Int8);
    check_unknown_initial_value<int16_t>(DataType::Int16);
    check_unknown_initial_value<int32_t>(DataType::Int32);
    check_unknown_initial_value<int64_t>(DataType::Int64);
    check_unknown_initial_value<uint8_t>(DataType::UInt8);
    check_unknown_initial_value<uint16_t>(DataType::UInt16);
    check_unknown_initial_value<uint32_t>(DataType::UInt32);
    check_unknown_initial_value<uint64_t>(DataType::UInt64);
    check_unknown_initial_value<float>(DataType::Float);
    check_unknown_initial_value<double>(DataType::Double);
}

TEST_CASE("first_scan_unknown refuses non-numeric types") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    scanner::MemoryScanner ms(process);
    CHECK(ms.first_scan_unknown(DataType::AOB).blocks.empty());
    CHECK(ms.first_scan_unknown(DataType::String).blocks.empty());
}

TEST_CASE("string scan finds UTF-8 and UTF-16 text and supports next changed / unchanged") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    scanner::MemoryScanner ms(process);

    const std::string ascii = "CyberWarrior";
    for (size_t i = 0; i < ascii.size(); ++i) {
        process->put<char>(0x100 + i, ascii[i]);
        process->put<char16_t>(0x400 + i * 2, static_cast<char16_t>(ascii[i])); // wide copy
    }

    auto narrow = ms.first_scan_string("CyberWarrior", false);
    REQUIRE(narrow.count() == 1);
    CHECK(narrow[0].address == FakeProcess::kBase + 0x100);
    CHECK(narrow[0].current_value.type == DataType::String);
    CHECK(narrow[0].current_value.to_string() == "\"CyberWarrior\"");

    auto wide = ms.first_scan_string("CyberWarrior", true);
    REQUIRE(wide.count() == 1);
    CHECK(wide[0].address == FakeProcess::kBase + 0x400);
    CHECK(wide[0].current_value.type == DataType::String16);
    CHECK(wide[0].current_value.to_string() == "\"CyberWarrior\"");

    CHECK(ms.first_scan_string("cyberwarrior", false).count() == 0); // case-sensitive
    CHECK(ms.first_scan_string("", false).count() == 0);

    CHECK(ms.next_scan(narrow, ScanCondition::Unchanged).count() == 1);
    process->put<char>(0x100, 'X');
    process->put<char16_t>(0x400, u'X');
    CHECK(ms.next_scan(narrow, ScanCondition::Changed).count() == 1);
    CHECK(ms.next_scan(wide, ScanCondition::Changed).count() == 1);
    CHECK(ms.next_scan(wide, ScanCondition::Unchanged).count() == 0);
}

TEST_CASE("rounded float range matches what the user sees, not just values within 0.0001") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    scanner::MemoryScanner ms(process);
    process->put<float>(0x10, 25.46f); // displays as 25.5 at one decimal
    process->put<float>(0x20, 25.56f); // displays as 25.6
    process->put<float>(0x30, 25.5f);

    auto range = utils::float_match_range("25.5", scanner::FloatMatchMode::Rounded);
    REQUIRE(range.has_value());
    auto results = ms.first_scan(DataType::Float, ScanCondition::Between,
                                 make_value(DataType::Float, static_cast<float>(range->first)),
                                 make_value(DataType::Float, static_cast<float>(range->second)), 4);
    CHECK(results.count() == 2);
    CHECK(contains_address(results, FakeProcess::kBase + 0x10));
    CHECK(contains_address(results, FakeProcess::kBase + 0x30));
    CHECK_FALSE(contains_address(results, FakeProcess::kBase + 0x20));
}

TEST_CASE("first_scan Between works for small integer types") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    scanner::MemoryScanner ms(process);
    process->put<int16_t>(0x40, 500);

    auto results = ms.first_scan(DataType::Int16, ScanCondition::Between,
                                 make_value(DataType::Int16, int16_t{400}), make_value(DataType::Int16, int16_t{600}), 2);
    CHECK(results.count() == 1);
    CHECK(contains_address(results, FakeProcess::kBase + 0x40));
}

TEST_CASE("AOB results support next changed / unchanged") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    scanner::MemoryScanner ms(process);
    process->put<uint32_t>(0x300, 0xEFBEADDE); // DE AD BE EF in memory

    auto first = ms.first_scan_aob("DE AD ? EF");
    REQUIRE(first.count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Unchanged).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Changed).count() == 0);

    process->put<uint8_t>(0x302, 0x00);
    CHECK(ms.next_scan(first, ScanCondition::Changed).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Unchanged).count() == 0);
}

TEST_CASE("a mismatched ScanValue throws on the caller's thread instead of terminating") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    scanner::MemoryScanner ms(process);
    scanner::ScanValue wrong; // holds an int32_t
    CHECK_THROWS_AS((void)ms.first_scan(DataType::Float, ScanCondition::ExactValue, wrong), std::bad_variant_access);
}

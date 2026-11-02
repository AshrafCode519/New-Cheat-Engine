#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/memory_scanner.hpp"
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

template <typename T>
void check_value_conditions(DataType type) {
    CAPTURE(static_cast<int>(type));
    auto process = std::make_shared<FakeProcess>(0x4000);
    scanner::MemoryScanner ms(process);
    auto v = [type](T x) { return make_value(type, x); };

    process->put<T>(0x200, T(100));
    auto first = ms.first_scan(type, ScanCondition::ExactValue, v(T(100)), {}, sizeof(T));
    REQUIRE(first.count() == 1);
    process->put<T>(0x200, T(150));

    // These used to compare against 0 instead of the given value
    CHECK(ms.next_scan(first, ScanCondition::GreaterThan, v(T(120))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::GreaterThan, v(T(200))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::LessThan, v(T(200))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::LessThan, v(T(120))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::Between, v(T(140)), v(T(160))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Between, v(T(10)), v(T(20))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::IncreasedBy, v(T(50))).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::IncreasedBy, v(T(10))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::DecreasedBy, v(T(50))).count() == 0);
    CHECK(ms.next_scan(first, ScanCondition::Increased).count() == 1);
    CHECK(ms.next_scan(first, ScanCondition::Decreased).count() == 0);
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

TEST_CASE("next_scan value conditions use the given value") {
    check_value_conditions<int32_t>(DataType::Int32);
    check_value_conditions<int64_t>(DataType::Int64);
    check_value_conditions<uint16_t>(DataType::UInt16);
    check_value_conditions<float>(DataType::Float);
    check_value_conditions<double>(DataType::Double);
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

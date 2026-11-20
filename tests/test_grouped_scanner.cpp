#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/grouped_scanner.hpp"
#include <memory>

using namespace nce;
using scanner::DataType;
using test::FakeProcess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

scanner::GroupedEntry member(DataType type, scanner::ScanValue value) {
    return {type, std::move(value), 0, false};
}
scanner::GroupedEntry i32(int32_t v) { return member(DataType::Int32, scanner::ScanValue::of(DataType::Int32, v)); }
scanner::GroupedEntry i16(int16_t v) { return member(DataType::Int16, scanner::ScanValue::of(DataType::Int16, v)); }
scanner::GroupedEntry f32(float v) { return member(DataType::Float, scanner::ScanValue::of(DataType::Float, v)); }

} // anonymous namespace

TEST_CASE("grouped scan: the order of the members doesn't matter") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(0x2000, 100);  // health
    process->put<int32_t>(0x2004, 50);   // mana
    process->put<float>(0x2008, 25.5f);  // armor
    scanner::GroupedScanner gs(process);

    // armor first, health before it: used to find nothing (only looked after the first member)
    const auto matches = gs.scan({f32(25.5f), i32(100)});
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].member_addresses == std::vector<uintptr_t>{kBase + 0x2008, kBase + 0x2000});
}

TEST_CASE("grouped scan: two members never share one address") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(0x3000, 100);
    scanner::GroupedScanner gs(process);
    CHECK(gs.scan({i32(100), i32(100)}).empty()); // only one 100 there

    process->put<int32_t>(0x3010, 100);
    const auto matches = gs.scan({i32(100), i32(100)});
    REQUIRE_FALSE(matches.empty());
    CHECK(matches[0].member_addresses[0] != matches[0].member_addresses[1]);
}

TEST_CASE("grouped scan: members are searched at their own alignment") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(0x4000, 7);
    process->put<int16_t>(0x4006, 9); // a 2-byte field at offset 6 (the old 4-byte step skipped it)
    scanner::GroupedScanner gs(process);

    const auto matches = gs.scan({i32(7), i16(9)});
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].member_addresses[1] == kBase + 0x4006);
}

TEST_CASE("grouped scan: members on both sides of a 1 MB chunk border are found") {
    auto process = std::make_shared<FakeProcess>(0x200000);
    process->put<int32_t>(0xFFFF8, 77);  // first member just before the border
    process->put<int32_t>(0x100004, 88); // second just after it
    process->put<int32_t>(0x100100, 66); // a first member after the border, its partner before it
    process->put<int32_t>(0x1000F0, 55);
    scanner::GroupedScanner gs(process);

    CHECK(gs.scan({i32(77), i32(88)}).size() == 1);
    CHECK(gs.scan({i32(66), i32(55)}).size() == 1);
}

TEST_CASE("grouped scan: an exact offset is honoured") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(0x5000, 1);
    process->put<int32_t>(0x5010, 2);
    process->put<int32_t>(0x5020, 2);
    scanner::GroupedScanner gs(process);

    auto second = i32(2);
    second.exact_offset = true;
    second.expected_offset = 0x20;
    const auto matches = gs.scan({i32(1), second});
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].member_addresses[1] == kBase + 0x5020); // not the closer 0x5010
}

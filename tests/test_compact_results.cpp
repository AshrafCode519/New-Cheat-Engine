#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/memory_scanner.hpp"
#include <memory>
#include <stdexcept>
#include <variant>

using namespace nce;
using scanner::DataType;
using scanner::ScanCondition;
using test::FakeProcess;
using test::contains_address;
using test::sorted_by_address;

namespace {

scanner::ScanValue i32(int32_t v) { return scanner::ScanValue::of(DataType::Int32, v); }

} // anonymous namespace

TEST_CASE("ScanResults stores an i32 match in 16 bytes and decodes it on demand") {
    scanner::ScanResults results(DataType::Int32, 4);
    results.reserve(1000);
    const int32_t current = 60, previous = 40;
    for (size_t i = 0; i < 1000; ++i) {
        results.add(0x1000 + i * 4, &current, &previous);
    }

    CHECK(results.memory_bytes() == 1000 * 16); // was ~104 bytes per match
    const auto m = results[999];
    CHECK(m.address == 0x1000 + 999 * 4);
    CHECK(std::get<int32_t>(m.current_value.value) == 60);
    CHECK(std::get<int32_t>(m.previous_value.value) == 40);

    CHECK_THROWS_AS(results.add_match(0x10, scanner::ScanValue::of(DataType::Double, 1.0)), std::invalid_argument);
}

TEST_CASE("first_scan results come back sorted by address across regions") {
    auto process = std::make_shared<FakeProcess>(0x300000); // 3 MB: several 1 MB chunks
    process->make_unreadable(0x150000, 0x20000);            // split into two regions
    scanner::MemoryScanner ms(process);

    size_t expected = 0;
    for (size_t offset = 0x100; offset < 0x300000; offset += 0x10000) {
        if (offset >= 0x150000 && offset < 0x170000) continue;
        process->put<int32_t>(offset, 7);
        ++expected;
    }

    auto results = ms.first_scan(DataType::Int32, ScanCondition::ExactValue, i32(7), {}, 4);
    CHECK(results.count() == expected);
    CHECK(sorted_by_address(results));

    auto next = ms.next_scan(results, ScanCondition::Unchanged);
    CHECK(next.count() == expected);
    CHECK(sorted_by_address(next));
}

TEST_CASE("values that straddle a 1 MB chunk border are found") {
    auto process = std::make_shared<FakeProcess>(0x200000);
    scanner::MemoryScanner ms(process);

    // DE AD BE EF starting 2 bytes before the 1 MB mark
    process->put<uint32_t>(0xFFFFE, 0xEFBEADDE);
    auto aob = ms.first_scan_aob("DE AD BE EF");
    CHECK(contains_address(aob, FakeProcess::kBase + 0xFFFFE));

    auto unaligned = ms.first_scan(DataType::Int32, ScanCondition::ExactValue,
                                   i32(static_cast<int32_t>(0xEFBEADDE)), {}, 1);
    CHECK(contains_address(unaligned, FakeProcess::kBase + 0xFFFFE));
}

TEST_CASE("first scan falls back to page reads when part of a chunk was freed after query_regions") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    scanner::MemoryScanner ms(process);
    process->put<int32_t>(0x1100, 7); // inside the freed page
    process->put<int32_t>(0x5000, 7);
    process->make_unreadable(0x1000, 0x1000, false); // still listed as a region, but reads fail

    auto results = ms.first_scan(DataType::Int32, ScanCondition::ExactValue, i32(7), {}, 4);
    REQUIRE(results.count() == 1); // used to lose the whole 1 MB chunk
    CHECK(results.address(0) == FakeProcess::kBase + 0x5000);
}

TEST_CASE("next_scan falls back to single reads when a shared read window hits unreadable memory") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    scanner::MemoryScanner ms(process);
    process->put<int32_t>(0x1000, 7);
    process->put<int32_t>(0x3000, 7);
    process->put<int32_t>(0x5000, 7);

    auto first = ms.first_scan(DataType::Int32, ScanCondition::ExactValue, i32(7), {}, 4);
    REQUIRE(first.count() == 3);

    process->make_unreadable(0x2000, 0x100); // between results: the 64 KB window read fails
    process->make_unreadable(0x5000, 4);     // a result itself becomes unreadable
    auto next = ms.next_scan(first, ScanCondition::Unchanged);
    CHECK(next.count() == 2);
    CHECK(contains_address(next, FakeProcess::kBase + 0x1000));
    CHECK(contains_address(next, FakeProcess::kBase + 0x3000));
}

TEST_CASE("filter_snapshot keeps only matching candidates and drops empty blocks") {
    auto process = std::make_shared<FakeProcess>(0x40000); // four 64 KB snapshot blocks
    scanner::MemoryScanner ms(process);
    process->put<int32_t>(0x100, 40);
    process->put<int32_t>(0x20000, 40);

    auto snapshot = ms.first_scan_unknown(DataType::Int32, 4);
    REQUIRE(snapshot.blocks.size() == 4);
    CHECK(snapshot.candidate_count() == 0x40000 / 4);

    process->put<int32_t>(0x100, 60);

    auto unchanged = ms.filter_snapshot(snapshot, ScanCondition::Unchanged);
    CHECK(unchanged.candidate_count() == 0x40000 / 4 - 1);
    CHECK(unchanged.blocks.size() == 4);

    auto changed = ms.filter_snapshot(snapshot, ScanCondition::Changed);
    CHECK(changed.candidate_count() == 1);
    REQUIRE(changed.blocks.size() == 1); // the three blocks with no candidates are freed
    CHECK(changed.memory_bytes() < snapshot.memory_bytes() / 3);

    auto results = scanner::MemoryScanner::snapshot_to_results(changed);
    REQUIRE(results.count() == 1);
    CHECK(results.address(0) == FakeProcess::kBase + 0x100);
    CHECK(std::get<int32_t>(results[0].current_value.value) == 60);

    // Filtering a filtered snapshot only looks at its remaining candidates
    process->put<int32_t>(0x100, 70);
    CHECK(ms.filter_snapshot(changed, ScanCondition::IncreasedBy, i32(10)).candidate_count() == 1);
    CHECK(ms.filter_snapshot(changed, ScanCondition::Unchanged).candidate_count() == 0);
}

TEST_CASE("next_scan(snapshot) and filter_snapshot agree") {
    auto process = std::make_shared<FakeProcess>(0x20000);
    scanner::MemoryScanner ms(process);
    for (size_t offset = 0; offset < 0x20000; offset += 0x400) {
        process->put<int32_t>(offset, static_cast<int32_t>(offset));
    }

    auto snapshot = ms.first_scan_unknown(DataType::Int32, 4);
    for (size_t offset = 0; offset < 0x20000; offset += 0x800) {
        process->put<int32_t>(offset, static_cast<int32_t>(offset) + 5);
    }

    auto direct = ms.next_scan(snapshot, ScanCondition::IncreasedBy, i32(5));
    auto via_filter = scanner::MemoryScanner::snapshot_to_results(
        ms.filter_snapshot(snapshot, ScanCondition::IncreasedBy, i32(5)));

    CHECK(direct.count() == 0x20000 / 0x800);
    REQUIRE(direct.count() == via_filter.count());
    CHECK(sorted_by_address(direct));
    for (size_t i = 0; i < direct.count(); ++i) {
        CHECK(direct.address(i) == via_filter.address(i));
    }
}

TEST_CASE("ScanResults spills large result sets to disk and supports sorted/concurrent access") {
    scanner::ScanResults results(DataType::Int32, 4);
    results.set_ram_limit(2048); // 2 KB RAM cap (~128 entries per chunk)

    constexpr size_t N = 5000;
    for (size_t i = 0; i < N; ++i) {
        const int32_t cur = static_cast<int32_t>(i * 3 + 7);
        const int32_t prev = static_cast<int32_t>(i);
        // Insert in reverse address order to exercise external chunked sort
        const uintptr_t addr = 0x1000000 + (N - 1 - i) * 8;
        results.add(addr, &cur, &prev);
    }

    REQUIRE(results.count() == N);
    CHECK(results.is_spilled());
    CHECK(results.spilled_count() > 4000);
    CHECK(results.disk_bytes() > 0);
    CHECK(results.in_memory_bytes() <= 4096);

    // Verify random/boundary access before sorting
    CHECK(results.address(0) == 0x1000000 + (N - 1) * 8);
    CHECK(std::get<int32_t>(results[0].current_value.value) == 7);
    CHECK(std::get<int32_t>(results[4999].current_value.value) == static_cast<int32_t>(4999 * 3 + 7));

    results.sort_by_address();
    REQUIRE(results.count() == N);
    CHECK(sorted_by_address(results));
    CHECK(results.address(0) == 0x1000000);
    CHECK(std::get<int32_t>(results[0].current_value.value) == static_cast<int32_t>(4999 * 3 + 7));

    size_t streamed = 0;
    uintptr_t prev_addr = 0;
    results.for_each([&](size_t idx, uintptr_t addr, const uint8_t* cur, const uint8_t*) {
        CHECK(idx == streamed);
        if (streamed > 0) CHECK(addr > prev_addr);
        int32_t v = 0;
        std::memcpy(&v, cur, 4);
        CHECK(v == static_cast<int32_t>((N - 1 - idx) * 3 + 7));
        prev_addr = addr;
        ++streamed;
    });
    CHECK(streamed == N);

    // Exercise multithreaded next_scan reading disk-spilled ScanResults under a tight RAM cap
    auto process = std::make_shared<FakeProcess>(0x40000);
    scanner::MemoryScanner ms(process);
    ms.set_disk_spill_limit(2048);
    for (size_t off = 0; off < 0x40000; off += 16) {
        process->put<int32_t>(off, 12345);
    }

    auto scanned = ms.first_scan(DataType::Int32, ScanCondition::ExactValue, i32(12345), {}, 16);
    REQUIRE(scanned.count() == 0x40000 / 16);
    CHECK(scanned.is_spilled());
    CHECK(sorted_by_address(scanned));

    process->put<int32_t>(0x1000, 99999);
    auto unchanged = ms.next_scan(scanned, ScanCondition::Unchanged);
    CHECK(unchanged.count() == (0x40000 / 16) - 1);
    CHECK(sorted_by_address(unchanged));
}

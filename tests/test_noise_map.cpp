#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/noise_map.hpp"
#include "scanner/value_tracker.hpp"
#include <functional>
#include <memory>

using namespace nce;
using scanner::DataType;
using test::FakeProcess;
using test::contains_address;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;
constexpr size_t kCounter = 0x100; // a frame counter: changes on every sample
constexpr size_t kHealth = 0x200;  // the user's value: changes now and then

// Learns noise over 16 samples; `tick(i)` changes memory before sample i
std::shared_ptr<scanner::NoiseMap> learn(FakeProcess& process, const std::function<void(int)>& tick) {
    auto noise = std::make_shared<scanner::NoiseMap>();
    noise->begin(process);
    for (int i = 1; i < 16; ++i) {
        tick(i);
        noise->sample(process);
    }
    noise->finish();
    return noise;
}

} // anonymous namespace

TEST_CASE("slots that change in most samples are noise; a value changed now and then is not") {
    auto process = std::make_shared<FakeProcess>(0x40000);
    auto noise = learn(*process, [&](int i) {
        process->put<int32_t>(kCounter, i);
        if (i == 5 || i == 11) process->put<int32_t>(kHealth, 1000 - i); // got hit twice while learning
    });

    CHECK(noise->samples_taken() == 16);
    CHECK(noise->is_noisy(kBase + kCounter, 4));
    CHECK(noise->is_noisy(kBase + kCounter + 2, 2)); // any byte of a noisy slot
    CHECK_FALSE(noise->is_noisy(kBase + kHealth, 4));
    CHECK_FALSE(noise->is_noisy(kBase + 0x300, 4));
    CHECK(noise->noisy_slots() == 1);
    CHECK(noise->skipped_bytes() == 0);
}

TEST_CASE("fewer than two comparisons never mark anything") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    scanner::NoiseMap noise;
    noise.begin(*process);
    process->put<int32_t>(kCounter, 1);
    noise.sample(*process); // one comparison only (e.g. stopped early)
    noise.finish();
    CHECK(noise.empty());
    CHECK_FALSE(noise.is_noisy(kBase + kCounter, 4));
}

TEST_CASE("a block that is mostly noise is skipped whole and not scanned") {
    auto process = std::make_shared<FakeProcess>(0x40000); // four 64 KB blocks
    auto noise = learn(*process, [&](int i) {
        for (size_t offset = 0x20000; offset < 0x30000; offset += 4) { // e.g. an audio buffer
            process->put<int32_t>(offset, i * 7 + static_cast<int32_t>(offset));
        }
    });
    CHECK(noise->skipped_bytes() == 0x10000);

    const auto regions = noise->filter_regions(process->query_regions());
    REQUIRE(regions.size() == 2);
    CHECK(regions[0].base_address == kBase);
    CHECK(regions[0].size == 0x20000);
    CHECK(regions[1].base_address == kBase + 0x30000);
    CHECK(regions[1].size == 0x10000);

    // The value 4242 sits in the skipped block and in a normal one: only the normal one is found
    process->put<int32_t>(0x24000, 4242);
    process->put<int32_t>(0x4000, 4242);
    scanner::MemoryScanner ms(process);
    ms.set_noise_map(noise);
    auto results = ms.first_scan(DataType::Int32, scanner::ScanCondition::ExactValue,
                                 scanner::ScanValue::of(DataType::Int32, int32_t{4242}), {}, 4);
    REQUIRE(results.count() == 1);
    CHECK(results.address(0) == kBase + 0x4000);
}

TEST_CASE("mask marks every caller slot that overlaps a noisy 4-byte slot") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    auto noise = learn(*process, [&](int i) { process->put<int32_t>(0x104, i); });
    REQUIRE(noise->is_noisy(kBase + 0x104, 4));

    auto bits = [&](size_t slot_size) { return noise->mask(kBase + 0x100, 0x10, slot_size)[0]; };
    CHECK(bits(1) == 0b11110000);  // bytes 4..7
    CHECK(bits(2) == 0b1100);      // halfwords 2, 3
    CHECK(bits(4) == 0b10);        // word 1
    CHECK(bits(8) == 0b1);         // the 8-byte slot holding bytes 0..7
    CHECK(noise->mask(kBase + 0x200, 0x10, 4)[0] == 0); // elsewhere: nothing
}

TEST_CASE("unknown-value scans and smart track never offer noisy addresses") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(kHealth, 1000);
    auto noise = learn(*process, [&](int i) { process->put<int32_t>(kCounter, i); });

    // The counter keeps running while the user changes health
    int32_t counter = 100;
    int32_t health = 1000;
    auto run = [&](std::shared_ptr<const scanner::NoiseMap> map) {
        scanner::ValueTracker tracker(process, DataType::Int32);
        tracker.set_noise_map(map);
        tracker.start();
        process->put<int32_t>(kCounter, ++counter);
        process->put<int32_t>(kHealth, health -= 100);
        tracker.observe_event({scanner::Expectation::Kind::Changed});
        return tracker.top(10);
    };

    const auto without = run(nullptr);
    CHECK(without.size() == 2); // health and the counter both "changed"

    const auto with = run(noise);
    REQUIRE(with.size() == 1);
    CHECK(with[0].address == kBase + kHealth);

    scanner::MemoryScanner ms(process);
    ms.set_noise_map(noise);
    const auto snapshot = ms.first_scan_unknown(DataType::Int32, 4);
    CHECK(snapshot.candidate_count() == 0x10000 / 4 - 1);
}

TEST_CASE("noise learned after a first scan is dropped from the next scan") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(kCounter, 7);
    process->put<int32_t>(kHealth, 7);

    scanner::MemoryScanner ms(process);
    auto first = ms.first_scan(DataType::Int32, scanner::ScanCondition::ExactValue,
                               scanner::ScanValue::of(DataType::Int32, int32_t{7}), {}, 4);
    REQUIRE(first.count() == 2);

    auto noise = learn(*process, [&](int i) { process->put<int32_t>(kCounter, i % 2 ? 8 : 7); });
    ms.set_noise_map(noise);
    process->put<int32_t>(kCounter, 7);
    auto next = ms.next_scan(first, scanner::ScanCondition::Unchanged);
    REQUIRE(next.count() == 1);
    CHECK(contains_address(next, kBase + kHealth));
}

#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/value_tracker.hpp"
#include <memory>
#include <stdexcept>

using namespace nce;
using scanner::DataType;
using scanner::Expectation;
using test::FakeProcess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;
constexpr size_t kHealth = 0x100;  // the value the user is looking for
constexpr size_t kCounter = 0x200; // a huge counter that happens to change at the same moments
constexpr size_t kNoise = 0x300;   // changes all the time on its own

Expectation decreased() { return {Expectation::Kind::Decreased}; }
Expectation increased() { return {Expectation::Kind::Increased}; }

bool listed(const std::vector<scanner::RankedCandidate>& ranked, uintptr_t address) {
    for (const auto& r : ranked) {
        if (r.address == address) return true;
    }
    return false;
}

// The target_dummy situation: health drops by 100 while a big counter drops by 1, both at the
// user's events. list_threshold decides whether the first rounds run on the snapshot or the list.
void run_health_and_counter(size_t list_threshold) {
    CAPTURE(list_threshold);
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(kHealth, 1000);
    process->put<int32_t>(kCounter, 220000000);

    scanner::ValueTracker tracker(process, DataType::Int32, list_threshold);
    tracker.start();
    CHECK(tracker.candidate_count() == 0x10000 / 4);

    for (int32_t i = 1; i <= 3; ++i) { // the user waits; the noise value keeps changing
        process->put<int32_t>(kNoise, i);
        tracker.observe_quiet();
    }

    process->put<int32_t>(kHealth, 900);
    process->put<int32_t>(kCounter, 219999999);
    tracker.observe_event(decreased());

    process->put<int32_t>(kHealth, 800);
    process->put<int32_t>(kCounter, 219999998);
    tracker.observe_event(decreased());

    REQUIRE(tracker.is_ranked());
    CHECK(tracker.candidate_count() == 2); // everything that did not move at the events is gone

    const auto ranked = tracker.top(10);
    REQUIRE(ranked.size() == 2);
    CHECK(ranked[0].address == kBase + kHealth); // a plain filter can't tell these two apart
    CHECK(std::get<int32_t>(ranked[0].value.value) == 800);
    CHECK(ranked[0].reason.find("same step -100") != std::string::npos);
    CHECK(ranked[1].address == kBase + kCounter);
    CHECK(ranked[1].reason.find("unusual value") != std::string::npos);
    CHECK(ranked[0].score > ranked[1].score);

    const auto results = tracker.to_results(); // best first, ready for 'list' and 'add #0'
    REQUIRE(results.count() == 2);
    CHECK(results.address(0) == kBase + kHealth);
}

} // anonymous namespace

TEST_CASE("smart tracking ranks the plausible value above a counter that changes with it") {
    run_health_and_counter(2'000'000); // ranked list from the start
    run_health_and_counter(4);         // snapshot first, list once few candidates remain
}

TEST_CASE("one wrong answer lowers the right address instead of removing it") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(kHealth, 1000);

    scanner::ValueTracker tracker(process, DataType::Int32, 4);
    tracker.start();

    process->put<int32_t>(kHealth, 900);
    tracker.observe_event(decreased());
    process->put<int32_t>(kHealth, 800);
    tracker.observe_event(increased()); // wrong: it went down
    process->put<int32_t>(kHealth, 700);
    tracker.observe_event(decreased());

    const auto ranked = tracker.top(10);
    REQUIRE(listed(ranked, kBase + kHealth));
    CHECK(ranked[0].reason.find("changed differently 1x") != std::string::npos);

    // The same answers as hard filters lose the address at the wrong one
    auto hard = std::make_shared<FakeProcess>(0x10000);
    hard->put<int32_t>(kHealth, 1000);
    scanner::MemoryScanner scanner(hard);
    auto snapshot = scanner.first_scan_unknown(DataType::Int32, 4);
    hard->put<int32_t>(kHealth, 900);
    auto results = scanner.next_scan(snapshot, scanner::ScanCondition::Decreased);
    hard->put<int32_t>(kHealth, 800);
    results = scanner.next_scan(results, scanner::ScanCondition::Increased);
    CHECK(results.empty());
}

TEST_CASE("two mistakes on the snapshot, three in the ranked list, remove a candidate") {
    for (const size_t threshold : {size_t{1}, size_t{2'000'000}}) {
        CAPTURE(threshold);
        auto process = std::make_shared<FakeProcess>(0x10000);
        process->put<int32_t>(kHealth, 1000);
        process->put<int32_t>(kNoise, 0);

        scanner::ValueTracker tracker(process, DataType::Int32, threshold);
        tracker.start();
        const size_t start_count = tracker.candidate_count();
        const int allowed = tracker.is_ranked() ? scanner::ValueTracker::MAX_OFFENSES : 2;

        for (int32_t i = 1; i <= allowed; ++i) {
            process->put<int32_t>(kNoise, i);
            tracker.observe_quiet();
            const bool removed = tracker.candidate_count() == start_count - 1;
            CHECK(removed == (i == allowed)); // tolerated until the last allowed mistake
        }
    }
}

TEST_CASE("an exact new value counts as a match only when it equals what the user typed") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(kHealth, 1000);
    process->put<int32_t>(kCounter, 50);

    scanner::ValueTracker tracker(process, DataType::Int32);
    tracker.start();
    process->put<int32_t>(kHealth, 900);
    process->put<int32_t>(kCounter, 60);
    tracker.observe_event({Expectation::Kind::Equals, 900.0, 900.0});

    const auto ranked = tracker.top(10);
    REQUIRE(ranked.size() == 2); // the other one changed too, so it stays with a strike
    CHECK(ranked[0].address == kBase + kHealth);
    CHECK(ranked[1].reason.find("changed differently 1x") != std::string::npos);
}

TEST_CASE("float values: tiny or non-finite numbers rank below normal ones") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    process->put<float>(0x10, 25.5f);
    process->put<float>(0x20, 3e-30f);

    scanner::ValueTracker tracker(process, DataType::Float);
    tracker.start();
    process->put<float>(0x10, 24.5f);
    process->put<float>(0x20, 2e-30f);
    tracker.observe_event(decreased());

    const auto ranked = tracker.top(10);
    REQUIRE(ranked.size() == 2);
    CHECK(ranked[0].address == kBase + 0x10);
}

TEST_CASE("ValueTracker only takes numeric types") {
    auto process = std::make_shared<FakeProcess>(0x1000);
    CHECK_THROWS_AS(scanner::ValueTracker(process, DataType::String), std::invalid_argument);
}

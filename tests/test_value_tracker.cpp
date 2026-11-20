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
    tracker.observe_event({Expectation::Kind::Equals, 900.0, 900.0, 900.0});

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
    CHECK_THROWS_AS(scanner::ValueTracker(process, std::vector<DataType>{}), std::invalid_argument);
}

namespace {

// Follows one value with every auto type at once; `step` writes the value's next state
template <typename T>
scanner::ValueTracker track_auto(std::shared_ptr<FakeProcess> process, size_t offset, std::initializer_list<T> values,
                                 size_t list_threshold = 2'000'000) {
    auto it = values.begin();
    process->put<T>(offset, *it++);
    scanner::ValueTracker tracker(process, scanner::ValueTracker::auto_types(), list_threshold);
    tracker.start();
    for (; it != values.end(); ++it) {
        process->put<T>(offset, *it);
        tracker.observe_event(decreased());
    }
    return tracker;
}

} // anonymous namespace

TEST_CASE("auto type: the type that reads plausibly wins") {
    for (const size_t threshold : {size_t{2'000'000}, size_t{8}}) { // ranked from the start / snapshot first
        CAPTURE(threshold);

        SUBCASE("an int health") {
            auto process = std::make_shared<FakeProcess>(0x10000);
            auto tracker = track_auto<int32_t>(process, kHealth, {1000, 900, 800}, threshold);
            REQUIRE(tracker.is_ranked());
            const auto best = tracker.top(1);
            REQUIRE(best.size() == 1);
            CHECK(best[0].address == kBase + kHealth);
            CHECK(best[0].value.type == DataType::Int32); // as f32 the same bytes are ~1e-42
            CHECK(tracker.best_type() == DataType::Int32);
        }
        SUBCASE("a float health") {
            auto process = std::make_shared<FakeProcess>(0x10000);
            auto tracker = track_auto<float>(process, kHealth, {25.5f, 24.5f, 23.5f}, threshold);
            const auto best = tracker.top(1);
            REQUIRE(best.size() == 1);
            CHECK(best[0].address == kBase + kHealth);
            CHECK(best[0].value.type == DataType::Float); // as i32 the same bytes are ~1.1e9

            const auto results = tracker.to_results(); // results carry the winning type only
            CHECK(results.type() == DataType::Float);
            REQUIRE_FALSE(results.empty());
            CHECK(results.address(0) == kBase + kHealth);
        }
        SUBCASE("a double speed") {
            auto process = std::make_shared<FakeProcess>(0x10000);
            auto tracker = track_auto<double>(process, kHealth, {12.3456, 11.5, 10.25}, threshold);
            const auto best = tracker.top(1);
            REQUIRE(best.size() == 1);
            CHECK(best[0].address == kBase + kHealth);
            CHECK(best[0].value.type == DataType::Double);
        }
    }
}

TEST_CASE("auto type: a float value beats float bit noise that drops to 0") {
    // Seen on target_dummy: mana 250.5 -> 225.5 -> 200.5 tied with denormals that decreased to 0
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<float>(kHealth, 250.5f);
    process->put<float>(kNoise, 3e-39f);
    scanner::ValueTracker tracker(process, scanner::ValueTracker::auto_types());
    tracker.start();

    process->put<float>(kHealth, 225.5f);
    process->put<float>(kNoise, 2e-39f);
    tracker.observe_event(decreased());
    process->put<float>(kHealth, 200.5f);
    process->put<float>(kNoise, 0.0f);
    tracker.observe_event(decreased());

    const auto ranked = tracker.top(10);
    REQUIRE_FALSE(ranked.empty());
    CHECK(ranked[0].address == kBase + kHealth);
    CHECK(ranked[0].value.type == DataType::Float);
    CHECK(ranked[0].score > ranked[1].score); // a clear winner, not a tie
    CHECK(tracker.best_type() == DataType::Float);
    for (const auto& r : ranked) {
        if (r.address == kBase + kNoise && r.value.type == DataType::Float) {
            CHECK(r.reason.find("tiny steps") != std::string::npos);
        }
    }
}

TEST_CASE("parse_expectation reads +, -, c and typed values") {
    using Kind = Expectation::Kind;
    CHECK(scanner::parse_expectation("+", scanner::FloatMatchMode::Rounded)->kind == Kind::Increased);
    CHECK(scanner::parse_expectation("-", scanner::FloatMatchMode::Rounded)->kind == Kind::Decreased);
    CHECK(scanner::parse_expectation("c", scanner::FloatMatchMode::Rounded)->kind == Kind::Changed);

    auto typed = scanner::parse_expectation("24.5", scanner::FloatMatchMode::Rounded);
    REQUIRE(typed.has_value());
    CHECK(typed->kind == Kind::Equals);
    CHECK(typed->value == 24.5);
    CHECK(typed->low == doctest::Approx(24.45));
    CHECK(typed->high == doctest::Approx(24.55));

    CHECK_FALSE(scanner::parse_expectation("abc", scanner::FloatMatchMode::Rounded).has_value());
    CHECK_FALSE(scanner::parse_expectation("", scanner::FloatMatchMode::Rounded).has_value());
}

TEST_CASE("an exact typed value: integers must equal it, floats may round to it") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<float>(kHealth, 25.5f);
    scanner::ValueTracker tracker(process, scanner::ValueTracker::auto_types());
    tracker.start();

    process->put<float>(kHealth, 24.46f); // shows as 24.5 at one decimal
    tracker.observe_event(*scanner::parse_expectation("24.5", scanner::FloatMatchMode::Rounded));

    const auto best = tracker.top(1);
    REQUIRE(best.size() == 1);
    CHECK(best[0].address == kBase + kHealth);
    CHECK(best[0].value.type == DataType::Float);
    CHECK(best[0].reason.find("changed as expected 1/1") != std::string::npos);
}

#pragma once

#include "../hal/process.hpp"
#include "scan_types.hpp"
#include "scan_results.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nce::scanner {

// What the user says happened to the value at an event
struct Expectation {
    enum class Kind { Changed, Increased, Decreased, Equals };
    Kind kind{Kind::Changed};
    double low{0.0};  // Equals: accepted range, inclusive (low == high for an exact integer)
    double high{0.0};
};

// The user's answer as an expectation: "+" increased, "-" decreased, "c" changed, or the new value
// (floats match the range the typed decimals stand for under `float_mode`). nullopt if not understood.
std::optional<Expectation> parse_expectation(DataType type, const std::string& answer, FloatMatchMode float_mode);

struct RankedCandidate {
    uintptr_t address{0};
    ScanValue value;
    int score{0};
    std::string reason; // why it ranks where it does, in plain words
};

// Guided search for a value the user can change but doesn't know ("unknown initial value"), made
// tolerant to mistakes. Quiet observations catch values that change on their own; events check that
// a value changed the way the user said. Candidates are scored instead of filtered on every detail,
// so one wrong answer lowers the right address instead of removing it.
//
// While millions of candidates remain it works on a memory snapshot with two bits per slot (alive,
// one strike), and a second strike removes a candidate. Below list_threshold it switches to a list
// where every candidate keeps counters, is removed after MAX_OFFENSES strikes, and is ranked by score.
class ValueTracker {
public:
    static constexpr int MAX_OFFENSES = 3;

    ValueTracker(std::shared_ptr<hal::IProcess> process, DataType type, size_t list_threshold = 2'000'000);
    ~ValueTracker();

    // Snapshot of every slot in the matching regions. Numeric types only.
    void start(uint32_t region_filter = hal::FilterFlags::DefaultScanFilter);

    // The value was left alone since the last observation: anything that changed is a strike
    void observe_quiet();

    // The user changed the value: candidates that did not change at all are removed, and those that
    // changed differently from `expected` get a strike
    void observe_event(const Expectation& expected);

    [[nodiscard]] DataType type() const noexcept { return m_type; }
    [[nodiscard]] size_t candidate_count() const;
    [[nodiscard]] size_t memory_bytes() const;
    [[nodiscard]] size_t events() const noexcept { return m_events; }
    [[nodiscard]] bool is_ranked() const noexcept { return !m_snapshot_phase; } // false while still a snapshot

    // Best candidates first (empty while still a snapshot)
    [[nodiscard]] std::vector<RankedCandidate> top(size_t count) const;

    // Every remaining candidate as scan results, best first (snapshot phase: address order)
    [[nodiscard]] ScanResults to_results() const;

private:
    struct Block {
        uintptr_t base_address{0};
        std::vector<uint8_t> bytes;    // value at the last observation
        std::vector<uint64_t> alive;   // one bit per slot
        std::vector<uint64_t> struck;  // one bit per slot: already made one mistake
    };

    struct Candidate {
        uintptr_t address{0};
        uint64_t raw{0};       // current value bytes (value_size of them)
        int16_t matched{0};    // events where it changed the way the user said
        int16_t wrong{0};      // events where it changed, but differently
        int16_t noise{0};      // changes while the user left the value alone
        int16_t same_step{0};  // matched events whose change equalled the first one
        double first_step{0.0};
    };

    void observe_snapshot(const Expectation* expected);
    void observe_list(const Expectation* expected);
    // previous (index-aligned with blocks) gives the values before the event that triggered the switch
    void switch_to_list(const std::vector<Block>& blocks, const std::vector<Block>* previous, const Expectation* expected);

    [[nodiscard]] double as_double(const uint8_t* bytes) const;
    [[nodiscard]] bool matches(const Expectation& expected, const uint8_t* current, const uint8_t* previous) const;
    [[nodiscard]] int score(const Candidate& c) const;
    [[nodiscard]] std::string reason(const Candidate& c) const;

    std::shared_ptr<hal::IProcess> m_process;
    DataType m_type;
    size_t m_value_size;
    size_t m_list_threshold;
    size_t m_thread_count;
    size_t m_events{0};

    bool m_snapshot_phase{true};
    std::vector<Block> m_blocks;
    std::vector<Candidate> m_candidates; // address order
};

} // namespace nce::scanner

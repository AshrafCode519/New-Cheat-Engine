#pragma once

#include "../hal/process.hpp"
#include "scan_types.hpp"
#include "scan_results.hpp"
#include "noise_map.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nce::scanner {

// What the user says happened to the value at an event
struct Expectation {
    enum class Kind { Changed, Increased, Decreased, Equals };
    Kind kind{Kind::Changed};
    double value{0.0}; // Equals: the typed value (integer types must equal it)
    double low{0.0};   // Equals: accepted range for float types, inclusive
    double high{0.0};
};

// The user's answer as an expectation: "+" increased, "-" decreased, "c" changed, or the new value
// (float types match the range the typed decimals stand for under `float_mode`). nullopt if not understood.
std::optional<Expectation> parse_expectation(const std::string& answer, FloatMatchMode float_mode);

struct RankedCandidate {
    uintptr_t address{0};
    ScanValue value; // value.type is the type this candidate was read as
    int score{0};
    std::string reason; // why it ranks where it does, in plain words
};

// Guided search for a value the user can change but doesn't know ("unknown initial value"), made
// tolerant to mistakes. Quiet observations catch values that change on their own; events check that
// a value changed the way the user said. Candidates are scored instead of filtered on every detail,
// so one wrong answer lowers the right address instead of removing it.
//
// It can follow several types at once over one copy of memory (auto_types(): i32, f32, f64). The same
// bytes read as the wrong type give implausible values (a float health read as i32 is ~10^9, an int
// read as f32 is ~10^-42), so the scoring picks the type along with the address.
//
// While millions of candidates remain it works on a memory snapshot with two bits per slot and type
// (alive, one strike), and a second strike removes a candidate. Below list_threshold it switches to a
// list where every candidate keeps counters, is removed after MAX_OFFENSES strikes, and is ranked.
class ValueTracker {
public:
    static constexpr int MAX_OFFENSES = 3;

    // The types followed when the user doesn't know the type
    static std::vector<DataType> auto_types() { return {DataType::Int32, DataType::Float, DataType::Double}; }

    ValueTracker(std::shared_ptr<hal::IProcess> process, DataType type, size_t list_threshold = 2'000'000);
    ValueTracker(std::shared_ptr<hal::IProcess> process, std::vector<DataType> types, size_t list_threshold = 2'000'000);
    ~ValueTracker();

    // Addresses known to change on their own are never candidates (call before start)
    void set_noise_map(std::shared_ptr<const NoiseMap> noise) { m_noise = std::move(noise); }

    // Snapshot of every slot in the matching regions. Numeric types only.
    void start(uint32_t region_filter = hal::FilterFlags::DefaultScanFilter);

    // The value was left alone since the last observation: anything that changed is a strike
    void observe_quiet();

    // The user changed the value: candidates that did not change at all are removed, and those that
    // changed differently from `expected` get a strike
    void observe_event(const Expectation& expected);

    [[nodiscard]] const std::vector<DataType>& types() const noexcept { return m_types; }
    [[nodiscard]] DataType best_type() const; // type of the best candidate (the first type until ranked)
    [[nodiscard]] size_t candidate_count() const;
    [[nodiscard]] size_t memory_bytes() const;
    [[nodiscard]] size_t events() const noexcept { return m_events; }
    [[nodiscard]] bool is_ranked() const noexcept { return !m_snapshot_phase; } // false while still a snapshot

    // Best candidates first (empty while still a snapshot)
    [[nodiscard]] std::vector<RankedCandidate> top(size_t count) const;

    // The remaining candidates of best_type() as scan results, best first (snapshot phase: address order)
    [[nodiscard]] ScanResults to_results() const;

private:
    struct Block {
        uintptr_t base_address{0};
        std::vector<uint8_t> bytes;                // memory at the last observation, shared by all types
        std::vector<std::vector<uint64_t>> alive;  // per type: one bit per slot
        std::vector<std::vector<uint64_t>> struck; // per type: one bit per slot, already made one mistake
    };

    struct Candidate {
        uintptr_t address{0};
        uint64_t raw{0};       // current value bytes (the type's size)
        uint8_t lane{0};       // index into m_types
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

    [[nodiscard]] size_t value_size(size_t lane) const { return m_sizes[lane]; }
    [[nodiscard]] double as_double(size_t lane, const uint8_t* bytes) const;
    [[nodiscard]] bool matches(size_t lane, const Expectation& expected, const uint8_t* current, const uint8_t* previous) const;
    [[nodiscard]] int score(const Candidate& c) const;
    [[nodiscard]] bool tiny_float_step(const Candidate& c) const;
    [[nodiscard]] std::string reason(const Candidate& c) const;
    [[nodiscard]] std::vector<size_t> ranked_order() const; // candidate indices, best first

    std::shared_ptr<hal::IProcess> m_process;
    std::shared_ptr<const NoiseMap> m_noise;
    std::vector<DataType> m_types;
    std::vector<size_t> m_sizes;
    size_t m_list_threshold;
    size_t m_thread_count;
    size_t m_events{0};

    bool m_snapshot_phase{true};
    std::vector<Block> m_blocks;
    std::vector<Candidate> m_candidates; // address order
};

} // namespace nce::scanner

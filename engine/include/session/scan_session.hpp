#pragma once

#include "../hal/process.hpp"
#include "../scanner/memory_scanner.hpp"
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace nce::session {

// What an operation did, in words a front end can show as is
struct Outcome {
    bool ok{false};
    std::string message; // the reason when !ok; an optional note when ok

    static Outcome fail(std::string message) { return {false, std::move(message)}; }
    static Outcome success(std::string note = {}) { return {true, std::move(note)}; }
};

struct NextCondition {
    const char* name;  // the CLI word: "exact", "changed", ...
    const char* label; // the UI label: "Exact value", "Changed", ...
    scanner::ScanCondition condition;
    int value_count;
};

// The current search: its results (or the unknown-value snapshot) and the undo history, driven by
// what the user typed. One thread at a time: the GUI runs scans as jobs and doesn't read the state meanwhile.
class ScanSession {
public:
    struct State {
        scanner::ScanResults results;
        std::shared_ptr<scanner::MemorySnapshot> snapshot; // after an unknown-value first scan
        scanner::DataType type{scanner::DataType::Int32};
        std::optional<uint64_t> xor_key;                 // when set, candidate values are stored ^ xor_key
    };

    static constexpr size_t MAX_UNDO_STEPS = 5;
    static const std::vector<NextCondition>& next_conditions();

    // The scanner of the attached process (nullptr when detached). Scans are refused once the process exited.
    void set_scanner(std::shared_ptr<scanner::MemoryScanner> scanner, std::shared_ptr<const hal::IProcess> process) {
        m_scanner = std::move(scanner);
        m_process = std::move(process);
    }
    void clear(); // results, snapshot and history (a new process)

    // type_name: "i8".."f64", "str", "wstr" or "aob". input: a number, "?" for an unknown initial value,
    // the text, or the AOB pattern. The previous state goes to the undo history.
    Outcome first_scan(const std::string& type_name, const std::string& input, scanner::FloatMatchMode float_mode);

    // Encrypted / XOR scan: key_text can be hex ("0xA5A5A5A5"), decimal, or "auto" (adjacent key pair).
    Outcome first_scan_xor(const std::string& type_name, const std::string& value_text, const std::string& key_text);

    // condition: a next_conditions() name. Values as typed (only the ones the condition needs).
    Outcome next_scan(const std::string& condition, const std::string& value1, const std::string& value2,
                      scanner::FloatMatchMode float_mode);

    bool undo();
    [[nodiscard]] bool can_undo() const noexcept { return !m_history.empty(); }

    // Results found another way (smart track, a results file); the current state goes to the undo history
    void replace(scanner::ScanResults results, scanner::DataType type);

    [[nodiscard]] const State& state() const noexcept { return m_state; }
    [[nodiscard]] bool empty() const noexcept { return m_state.results.empty() && !m_state.snapshot; }
    [[nodiscard]] std::string describe() const; // "12 matches" or "340480 candidates, snapshot 1 MB"

private:
    [[nodiscard]] std::optional<Outcome> refuse() const;
    void push_history();
    void filter_into_current(const State& source, scanner::ScanCondition condition,
                             const scanner::ScanValue& value1, const scanner::ScanValue& value2);

    std::shared_ptr<scanner::MemoryScanner> m_scanner;
    std::shared_ptr<const hal::IProcess> m_process;
    State m_state;
    std::vector<State> m_history;
};

// For f32/f64 under the rounded/truncated float mode: the [low, high] range a typed exact value stands for
std::optional<std::pair<scanner::ScanValue, scanner::ScanValue>> float_exact_range(
    scanner::DataType type, const std::string& text, scanner::FloatMatchMode mode);

// A value as the user would type it back (text without quotes)
std::string value_text(const scanner::ScanValue& value);

// "532 KB", "12 MB"
std::string format_size(size_t bytes);

const char* float_mode_name(scanner::FloatMatchMode mode);

} // namespace nce::session

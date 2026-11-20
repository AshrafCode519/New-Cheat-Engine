#include "../../include/scanner/value_tracker.hpp"
#include "../../include/scanner/memory_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "parallel.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace nce::scanner {

namespace {

constexpr size_t READ_WINDOW = 64 * 1024; // one read covers neighbouring candidates up to 64 KB apart
constexpr size_t LIST_SLICE = 1 << 14;    // candidates per work item in the list phase

bool test_bit(const std::vector<uint64_t>& bits, size_t i) { return (bits[i / 64] >> (i % 64)) & 1; }
void set_bit(std::vector<uint64_t>& bits, size_t i) { bits[i / 64] |= uint64_t{1} << (i % 64); }
void clear_bit(std::vector<uint64_t>& bits, size_t i) { bits[i / 64] &= ~(uint64_t{1} << (i % 64)); }

size_t count_bits(const std::vector<uint64_t>& bits) {
    size_t total = 0;
    for (const uint64_t word : bits) total += std::popcount(word);
    return total;
}

template <typename Fn>
void for_each_bit(const std::vector<uint64_t>& bits, Fn&& fn) {
    for (size_t w = 0; w < bits.size(); ++w) {
        uint64_t word = bits[w];
        while (word != 0) {
            fn(w * 64 + static_cast<size_t>(std::countr_zero(word)));
            word &= word - 1;
        }
    }
}

bool same_step(double a, double b) {
    return std::fabs(a - b) <= 1e-6 * std::max({1.0, std::fabs(a), std::fabs(b)});
}

} // anonymous namespace

std::optional<Expectation> parse_expectation(DataType type, const std::string& answer, FloatMatchMode float_mode) {
    using Kind = Expectation::Kind;
    if (answer == "+") return Expectation{Kind::Increased};
    if (answer == "-") return Expectation{Kind::Decreased};
    if (answer == "c") return Expectation{Kind::Changed};

    auto value = utils::parse_scan_value(type, answer);
    if (!value) return std::nullopt;
    double exact = 0.0;
    dispatch_numeric(type, [&]<typename T>() { exact = static_cast<double>(std::get<T>(value->value)); });

    Expectation expected{Kind::Equals, exact, exact};
    if (type == DataType::Float || type == DataType::Double) {
        if (auto range = utils::float_match_range(answer, float_mode)) {
            expected.low = range->first;
            expected.high = range->second;
        } else {
            expected.low = exact - 0.0001; // FloatMatchMode::Exact
            expected.high = exact + 0.0001;
        }
    }
    return expected;
}

ValueTracker::ValueTracker(std::shared_ptr<hal::IProcess> process, DataType type, size_t list_threshold)
    : m_process(std::move(process))
    , m_type(type)
    , m_value_size(get_data_type_size(type))
    , m_list_threshold(list_threshold)
    , m_thread_count(detail::default_thread_count())
{
    if (!dispatch_numeric(type, []<typename T>() {})) {
        throw std::invalid_argument("ValueTracker: only numeric types can be tracked");
    }
}

ValueTracker::~ValueTracker() = default;

void ValueTracker::start(uint32_t region_filter) {
    m_blocks.clear();
    m_candidates.clear();
    m_snapshot_phase = true;
    m_events = 0;

    MemoryScanner scanner(m_process);
    auto snapshot = scanner.first_scan_unknown(m_type, m_value_size, region_filter);
    m_blocks.reserve(snapshot.blocks.size());
    for (auto& b : snapshot.blocks) {
        Block block;
        block.base_address = b.base_address;
        block.bytes = std::move(b.bytes);
        block.alive = std::move(b.alive);
        block.struck.assign(block.alive.size(), 0);
        m_blocks.push_back(std::move(block));
    }

    if (candidate_count() <= m_list_threshold) {
        switch_to_list(m_blocks, nullptr, nullptr);
    }
}

void ValueTracker::observe_quiet() {
    if (m_snapshot_phase) observe_snapshot(nullptr);
    else observe_list(nullptr);
}

void ValueTracker::observe_event(const Expectation& expected) {
    ++m_events;
    if (m_snapshot_phase) observe_snapshot(&expected);
    else observe_list(&expected);
}

double ValueTracker::as_double(const uint8_t* bytes) const {
    double out = 0.0;
    dispatch_numeric(m_type, [&]<typename T>() {
        T value;
        std::memcpy(&value, bytes, sizeof(T));
        out = static_cast<double>(value);
    });
    return out;
}

bool ValueTracker::matches(const Expectation& expected, const uint8_t* current, const uint8_t* previous) const {
    const double now = as_double(current);
    const double before = as_double(previous);
    switch (expected.kind) {
        case Expectation::Kind::Changed:   return std::memcmp(current, previous, m_value_size) != 0;
        case Expectation::Kind::Increased: return now > before;
        case Expectation::Kind::Decreased: return now < before;
        case Expectation::Kind::Equals:    return now >= expected.low && now <= expected.high;
    }
    return false;
}

// One pass over the snapshot. Quiet (expected == nullptr): a change is a mistake. Event: no change
// removes the candidate, a change that differs from `expected` is a mistake. A second mistake removes it.
void ValueTracker::observe_snapshot(const Expectation* expected) {
    std::vector<Block> next(m_blocks.size());

    detail::parallel_for(m_blocks.size(), m_thread_count, [] { return 0; }, [&](int&, size_t i) {
        const Block& old = m_blocks[i];
        Block& out = next[i];
        out.bytes.resize(old.bytes.size());
        if (!m_process->read_raw(old.base_address, out.bytes.data(), out.bytes.size())) {
            out = {};
            return;
        }
        out.base_address = old.base_address;
        out.alive = old.alive;
        out.struck = old.struck;

        size_t kept = 0;
        for_each_bit(old.alive, [&](size_t slot) {
            const size_t offset = slot * m_value_size;
            const uint8_t* current = out.bytes.data() + offset;
            const uint8_t* previous = old.bytes.data() + offset;
            const bool changed = std::memcmp(current, previous, m_value_size) != 0;

            bool mistake = false;
            if (!expected) {
                mistake = changed;
            } else if (!changed) {
                clear_bit(out.alive, slot); // the user changed the value; this one didn't move
                return;
            } else {
                mistake = !matches(*expected, current, previous);
            }

            if (mistake) {
                if (test_bit(out.struck, slot)) {
                    clear_bit(out.alive, slot);
                    return;
                }
                set_bit(out.struck, slot);
            }
            ++kept;
        });

        if (kept == 0) out = {};
    });

    size_t remaining = 0;
    for (const auto& b : next) remaining += count_bits(b.alive);

    if (remaining <= m_list_threshold) {
        switch_to_list(next, &m_blocks, expected);
        return;
    }

    std::vector<Block> kept;
    kept.reserve(next.size());
    for (auto& b : next) {
        if (!b.bytes.empty()) kept.push_back(std::move(b));
    }
    m_blocks = std::move(kept);
}

// Turns the snapshot into ranked candidates. A snapshot only remembers one strike per slot, not what
// caused it: before the first event it was noise, afterwards it is counted as a wrong answer.
void ValueTracker::switch_to_list(const std::vector<Block>& blocks, const std::vector<Block>* previous,
                                  const Expectation* expected) {
    std::vector<Candidate> candidates;
    size_t total = 0;
    for (const auto& b : blocks) total += count_bits(b.alive);
    candidates.reserve(total);

    for (size_t i = 0; i < blocks.size(); ++i) {
        const Block& block = blocks[i];
        if (block.bytes.empty()) continue;
        const Block* before = previous ? &(*previous)[i] : nullptr; // `previous` is index-aligned with `blocks`

        for_each_bit(block.alive, [&](size_t slot) {
            const size_t offset = slot * m_value_size;
            const uint8_t* current = block.bytes.data() + offset;

            Candidate c;
            c.address = block.base_address + offset;
            std::memcpy(&c.raw, current, m_value_size);

            const bool struck = test_bit(block.struck, slot);
            if (m_events == 0) {
                c.noise = struck ? 1 : 0;
            } else {
                c.wrong = struck ? 1 : 0;
                c.matched = static_cast<int16_t>(std::max<int>(0, static_cast<int>(m_events) - c.wrong));
                if (expected && before && matches(*expected, current, before->bytes.data() + offset)) {
                    c.first_step = as_double(current) - as_double(before->bytes.data() + offset);
                    c.same_step = 1;
                }
            }
            candidates.push_back(c);
        });
    }

    m_candidates = std::move(candidates);
    m_blocks.clear();
    m_blocks.shrink_to_fit();
    m_snapshot_phase = false;
}

void ValueTracker::observe_list(const Expectation* expected) {
    const size_t total = m_candidates.size();
    std::vector<char> keep(total, 1);
    const size_t slices = (total + LIST_SLICE - 1) / LIST_SLICE;

    // Updates one candidate from its live bytes (nullptr = unreadable)
    auto update = [&](size_t k, const uint8_t* live) {
        Candidate& c = m_candidates[k];
        if (!live) {
            keep[k] = 0;
            return;
        }
        const auto* previous = reinterpret_cast<const uint8_t*>(&c.raw);
        const bool changed = std::memcmp(live, previous, m_value_size) != 0;

        if (!expected) {
            if (changed) ++c.noise;
        } else if (!changed) {
            keep[k] = 0; // the user changed the value; this one didn't move
            return;
        } else if (matches(*expected, live, previous)) {
            ++c.matched;
            const double step = as_double(live) - as_double(previous);
            if (c.same_step == 0) {
                c.first_step = step;
                c.same_step = 1;
            } else if (same_step(step, c.first_step)) {
                ++c.same_step;
            }
        } else {
            ++c.wrong;
        }

        if (c.wrong + c.noise >= MAX_OFFENSES) keep[k] = 0;
        std::memcpy(&c.raw, live, m_value_size);
    };

    detail::parallel_for(slices, m_thread_count,
        [] { return std::vector<uint8_t>(READ_WINDOW + sizeof(uint64_t)); },
        [&](std::vector<uint8_t>& buffer, size_t s) {
            const size_t begin = s * LIST_SLICE;
            const size_t end = std::min(total, begin + LIST_SLICE);

            size_t i = begin;
            while (i < end) {
                // Neighbouring candidates (address order) share one read
                const uintptr_t window_start = m_candidates[i].address;
                size_t j = i + 1;
                while (j < end && m_candidates[j].address - window_start + m_value_size <= READ_WINDOW) ++j;
                const size_t window_size = m_candidates[j - 1].address - window_start + m_value_size;

                if (m_process->read_raw(window_start, buffer.data(), window_size)) {
                    for (size_t k = i; k < j; ++k) update(k, buffer.data() + (m_candidates[k].address - window_start));
                } else {
                    for (size_t k = i; k < j; ++k) {
                        const bool ok = m_process->read_raw(m_candidates[k].address, buffer.data(), m_value_size);
                        update(k, ok ? buffer.data() : nullptr);
                    }
                }
                i = j;
            }
        });

    size_t out = 0;
    for (size_t k = 0; k < total; ++k) {
        if (keep[k]) m_candidates[out++] = m_candidates[k];
    }
    m_candidates.resize(out);
}

int ValueTracker::score(const Candidate& c) const {
    int s = 10 * c.matched - 8 * c.wrong - 4 * c.noise + 3 * std::max(0, c.same_step - 1);

    // Values a game would show the player rank above huge counters, addresses and float noise
    const double v = as_double(reinterpret_cast<const uint8_t*>(&c.raw));
    const double magnitude = std::fabs(v);
    const bool is_float = (m_type == DataType::Float || m_type == DataType::Double);
    if (!std::isfinite(v)) s -= 20;
    else if (magnitude > 1e9) s -= 10;
    else if (magnitude > 1e7) s -= 4;
    else if (is_float && magnitude != 0.0 && magnitude < 1e-4) s -= 5;
    else if (magnitude <= 1e6) s += 2;
    return s;
}

std::string ValueTracker::reason(const Candidate& c) const {
    std::ostringstream ss;
    if (m_events == 0) ss << "waiting for your first change";
    else ss << "changed as expected " << c.matched << "/" << m_events;
    if (c.same_step >= 2) ss << ", same step " << c.first_step << " each time";
    if (c.wrong > 0) ss << ", changed differently " << c.wrong << "x";
    if (c.noise > 0) ss << ", changed on its own " << c.noise << "x";

    const double v = as_double(reinterpret_cast<const uint8_t*>(&c.raw));
    if (!std::isfinite(v) || std::fabs(v) > 1e7) ss << ", unusual value";
    return ss.str();
}

size_t ValueTracker::candidate_count() const {
    if (!m_snapshot_phase) return m_candidates.size();
    size_t total = 0;
    for (const auto& b : m_blocks) total += count_bits(b.alive);
    return total;
}

size_t ValueTracker::memory_bytes() const {
    if (!m_snapshot_phase) return m_candidates.capacity() * sizeof(Candidate);
    size_t total = 0;
    for (const auto& b : m_blocks) {
        total += b.bytes.size() + (b.alive.size() + b.struck.size()) * sizeof(uint64_t);
    }
    return total;
}

std::vector<RankedCandidate> ValueTracker::top(size_t count) const {
    std::vector<RankedCandidate> best;
    if (m_snapshot_phase) return best;

    std::vector<std::pair<int, size_t>> order; // (score, index)
    order.reserve(m_candidates.size());
    for (size_t i = 0; i < m_candidates.size(); ++i) order.emplace_back(score(m_candidates[i]), i);

    const size_t n = std::min(count, order.size());
    std::partial_sort(order.begin(), order.begin() + static_cast<std::ptrdiff_t>(n), order.end(),
        [&](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first > b.first;
            return m_candidates[a.second].address < m_candidates[b.second].address;
        });

    best.reserve(n);
    for (size_t k = 0; k < n; ++k) {
        const Candidate& c = m_candidates[order[k].second];
        RankedCandidate r;
        r.address = c.address;
        r.value = value_from_bytes(m_type, reinterpret_cast<const uint8_t*>(&c.raw), m_value_size).value();
        r.score = order[k].first;
        r.reason = reason(c);
        best.push_back(std::move(r));
    }
    return best;
}

ScanResults ValueTracker::to_results() const {
    ScanResults results(m_type, m_value_size);
    if (m_snapshot_phase) {
        for (const auto& b : m_blocks) {
            for_each_bit(b.alive, [&](size_t slot) {
                const uint8_t* value = b.bytes.data() + slot * m_value_size;
                results.add(b.base_address + slot * m_value_size, value, value);
            });
        }
        return results;
    }

    for (const auto& r : top(m_candidates.size())) {
        const auto bytes = value_to_bytes(r.value);
        results.add(r.address, bytes.data(), bytes.data());
    }
    return results;
}

} // namespace nce::scanner

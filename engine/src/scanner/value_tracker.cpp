#include "../../include/scanner/value_tracker.hpp"
#include "../../include/scanner/memory_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "parallel.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
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

// Aligned slots (offset = slot * value_size) a value of value_size bytes fits at
std::vector<uint64_t> all_slots(size_t bytes, size_t value_size) {
    const size_t slots = bytes >= value_size ? (bytes - value_size) / value_size + 1 : 0;
    std::vector<uint64_t> bits((slots + 63) / 64, ~uint64_t{0});
    if (!bits.empty() && slots % 64 != 0) bits.back() = (uint64_t{1} << (slots % 64)) - 1;
    return bits;
}

bool same_step(double a, double b) {
    return std::fabs(a - b) <= 1e-6 * std::max({1.0, std::fabs(a), std::fabs(b)});
}

bool is_float_type(DataType type) {
    return type == DataType::Float || type == DataType::Double;
}

} // anonymous namespace

std::optional<Expectation> parse_expectation(const std::string& answer, FloatMatchMode float_mode) {
    using Kind = Expectation::Kind;
    if (answer == "+") return Expectation{Kind::Increased};
    if (answer == "-") return Expectation{Kind::Decreased};
    if (answer == "c") return Expectation{Kind::Changed};

    double typed = 0.0;
    const char* last = answer.data() + answer.size();
    auto [ptr, ec] = std::from_chars(answer.data(), last, typed);
    if (answer.empty() || ec != std::errc() || ptr != last) return std::nullopt;

    Expectation expected{Kind::Equals, typed, typed, typed};
    if (auto range = utils::float_match_range(answer, float_mode)) {
        expected.low = range->first;
        expected.high = range->second;
    } else {
        expected.low = typed - 0.0001; // FloatMatchMode::Exact
        expected.high = typed + 0.0001;
    }
    return expected;
}

ValueTracker::ValueTracker(std::shared_ptr<hal::IProcess> process, DataType type, size_t list_threshold)
    : ValueTracker(std::move(process), std::vector<DataType>{type}, list_threshold)
{}

ValueTracker::ValueTracker(std::shared_ptr<hal::IProcess> process, std::vector<DataType> types, size_t list_threshold)
    : m_process(std::move(process))
    , m_types(std::move(types))
    , m_list_threshold(list_threshold)
    , m_thread_count(detail::default_thread_count())
{
    if (m_types.empty() || m_types.size() > 8) {
        throw std::invalid_argument("ValueTracker: track between 1 and 8 types");
    }
    for (const auto type : m_types) {
        if (!dispatch_numeric(type, []<typename T>() {})) {
            throw std::invalid_argument("ValueTracker: only numeric types can be tracked");
        }
        m_sizes.push_back(get_data_type_size(type));
    }
}

ValueTracker::~ValueTracker() = default;

void ValueTracker::start(uint32_t region_filter) {
    m_blocks.clear();
    m_candidates.clear();
    m_snapshot_phase = true;
    m_events = 0;

    // One copy of memory for every type; each type gets its own candidate bitmaps.
    // Known noise: the scanner skips whole noisy blocks, and noisy slots are cleared here per type.
    MemoryScanner scanner(m_process);
    scanner.set_noise_map(m_noise);
    const bool use_noise = m_noise && !m_noise->empty();
    auto snapshot = scanner.first_scan_unknown(m_types.front(), m_sizes.front(), region_filter);
    m_blocks.reserve(snapshot.blocks.size());
    for (auto& b : snapshot.blocks) {
        Block block;
        block.base_address = b.base_address;
        block.bytes = std::move(b.bytes);
        for (size_t lane = 0; lane < m_types.size(); ++lane) {
            auto alive = all_slots(block.bytes.size(), m_sizes[lane]);
            if (use_noise) {
                const auto noisy = m_noise->mask(block.base_address, block.bytes.size(), m_sizes[lane]);
                for (size_t w = 0; w < alive.size(); ++w) alive[w] &= ~noisy[w];
            }
            block.struck.emplace_back(alive.size(), 0);
            block.alive.push_back(std::move(alive));
        }
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

double ValueTracker::as_double(size_t lane, const uint8_t* bytes) const {
    double out = 0.0;
    const bool is_be = is_big_endian(m_types[lane]);
    dispatch_numeric(m_types[lane], [&]<typename T>() {
        T value;
        std::memcpy(&value, bytes, sizeof(T));
        if (is_be) value = swap_bytes(value);
        out = static_cast<double>(value);
    });
    return out;
}

bool ValueTracker::matches(size_t lane, const Expectation& expected, const uint8_t* current, const uint8_t* previous) const {
    const double now = as_double(lane, current);
    const double before = as_double(lane, previous);
    switch (expected.kind) {
        case Expectation::Kind::Changed:   return std::memcmp(current, previous, value_size(lane)) != 0;
        case Expectation::Kind::Increased: return now > before;
        case Expectation::Kind::Decreased: return now < before;
        case Expectation::Kind::Equals:
            return is_float_type(m_types[lane]) ? (now >= expected.low && now <= expected.high) : now == expected.value;
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
        for (size_t lane = 0; lane < m_types.size(); ++lane) {
            const size_t size = value_size(lane);
            for_each_bit(old.alive[lane], [&](size_t slot) {
                const size_t offset = slot * size;
                const uint8_t* current = out.bytes.data() + offset;
                const uint8_t* previous = old.bytes.data() + offset;
                const bool changed = std::memcmp(current, previous, size) != 0;

                bool mistake = false;
                if (!expected) {
                    mistake = changed;
                } else if (!changed) {
                    clear_bit(out.alive[lane], slot); // the user changed the value; this one didn't move
                    return;
                } else {
                    mistake = !matches(lane, *expected, current, previous);
                }

                if (mistake) {
                    if (test_bit(out.struck[lane], slot)) {
                        clear_bit(out.alive[lane], slot);
                        return;
                    }
                    set_bit(out.struck[lane], slot);
                }
                ++kept;
            });
        }

        if (kept == 0) out = {};
    });

    size_t remaining = 0;
    for (const auto& b : next) {
        for (const auto& lane_bits : b.alive) remaining += count_bits(lane_bits);
    }

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
    for (const auto& b : blocks) {
        for (const auto& lane_bits : b.alive) total += count_bits(lane_bits);
    }
    candidates.reserve(total);

    for (size_t i = 0; i < blocks.size(); ++i) {
        const Block& block = blocks[i];
        if (block.bytes.empty()) continue;
        const Block* before = previous ? &(*previous)[i] : nullptr; // `previous` is index-aligned with `blocks`
        const size_t block_start = candidates.size();

        for (size_t lane = 0; lane < m_types.size(); ++lane) {
            const size_t size = value_size(lane);
            for_each_bit(block.alive[lane], [&](size_t slot) {
                const size_t offset = slot * size;
                const uint8_t* current = block.bytes.data() + offset;

                Candidate c;
                c.address = block.base_address + offset;
                c.lane = static_cast<uint8_t>(lane);
                std::memcpy(&c.raw, current, size);

                const bool struck = test_bit(block.struck[lane], slot);
                if (m_events == 0) {
                    c.noise = struck ? 1 : 0;
                } else {
                    c.wrong = struck ? 1 : 0;
                    c.matched = static_cast<int16_t>(std::max<int>(0, static_cast<int>(m_events) - c.wrong));
                    const uint8_t* old_value = before ? before->bytes.data() + offset : nullptr;
                    if (expected && old_value && matches(lane, *expected, current, old_value)) {
                        c.first_step = as_double(lane, current) - as_double(lane, old_value);
                        c.same_step = 1;
                    }
                }
                candidates.push_back(c);
            });
        }

        // Keep address order across types within the block (blocks are already in address order)
        std::sort(candidates.begin() + static_cast<std::ptrdiff_t>(block_start), candidates.end(),
            [](const Candidate& a, const Candidate& b) {
                return a.address != b.address ? a.address < b.address : a.lane < b.lane;
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
        const size_t size = value_size(c.lane);
        const auto* previous = reinterpret_cast<const uint8_t*>(&c.raw);
        const bool changed = std::memcmp(live, previous, size) != 0;

        if (!expected) {
            if (changed) ++c.noise;
        } else if (!changed) {
            keep[k] = 0; // the user changed the value; this one didn't move
            return;
        } else if (matches(c.lane, *expected, live, previous)) {
            ++c.matched;
            const double step = as_double(c.lane, live) - as_double(c.lane, previous);
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
        std::memcpy(&c.raw, live, size);
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
                uintptr_t window_end = window_start + value_size(m_candidates[i].lane);
                size_t j = i + 1;
                while (j < end) {
                    const uintptr_t candidate_end = m_candidates[j].address + value_size(m_candidates[j].lane);
                    if (candidate_end - window_start > READ_WINDOW) break;
                    window_end = std::max(window_end, candidate_end);
                    ++j;
                }

                if (m_process->read_raw(window_start, buffer.data(), window_end - window_start)) {
                    for (size_t k = i; k < j; ++k) update(k, buffer.data() + (m_candidates[k].address - window_start));
                } else {
                    for (size_t k = i; k < j; ++k) {
                        const bool ok = m_process->read_raw(m_candidates[k].address, buffer.data(),
                                                            value_size(m_candidates[k].lane));
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

    // Values a game would show the player rank above huge counters, addresses and float noise.
    // This is also what picks the type: the same bytes read as the wrong type look implausible.
    const double v = as_double(c.lane, reinterpret_cast<const uint8_t*>(&c.raw));
    const double magnitude = std::fabs(v);
    if (!std::isfinite(v)) s -= 20;
    else if (magnitude > 1e9) s -= 10;
    else if (magnitude > 1e7) s -= 4;
    else if (is_float_type(m_types[c.lane]) && magnitude != 0.0 && magnitude < 1e-4) s -= 5;
    else if (magnitude <= 1e6) s += 2;

    // Floats that only ever move by ~1e-38 are bit noise (or another type's bytes), even if they read 0 now
    if (tiny_float_step(c)) s -= 5;
    return s;
}

bool ValueTracker::tiny_float_step(const Candidate& c) const {
    return is_float_type(m_types[c.lane]) && c.same_step > 0 && c.first_step != 0.0 && std::fabs(c.first_step) < 1e-4;
}

std::string ValueTracker::reason(const Candidate& c) const {
    std::ostringstream ss;
    if (m_events == 0) ss << "waiting for your first change";
    else ss << "changed as expected " << c.matched << "/" << m_events;
    if (c.same_step >= 2) ss << ", same step " << c.first_step << " each time";
    if (c.wrong > 0) ss << ", changed differently " << c.wrong << "x";
    if (c.noise > 0) ss << ", changed on its own " << c.noise << "x";

    const double v = as_double(c.lane, reinterpret_cast<const uint8_t*>(&c.raw));
    const double magnitude = std::fabs(v);
    if (!std::isfinite(v) || magnitude > 1e7 ||
        (is_float_type(m_types[c.lane]) && magnitude != 0.0 && magnitude < 1e-4)) {
        ss << ", unusual value";
    }
    if (tiny_float_step(c)) ss << ", tiny steps";
    return ss.str();
}

std::vector<size_t> ValueTracker::ranked_order() const {
    std::vector<std::pair<int, size_t>> scored;
    scored.reserve(m_candidates.size());
    for (size_t i = 0; i < m_candidates.size(); ++i) scored.emplace_back(score(m_candidates[i]), i);

    std::sort(scored.begin(), scored.end(), [&](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first > b.first;
        const Candidate& ca = m_candidates[a.second];
        const Candidate& cb = m_candidates[b.second];
        return ca.address != cb.address ? ca.address < cb.address : ca.lane < cb.lane;
    });

    std::vector<size_t> order;
    order.reserve(scored.size());
    for (const auto& s : scored) order.push_back(s.second);
    return order;
}

DataType ValueTracker::best_type() const {
    if (m_snapshot_phase || m_candidates.empty()) return m_types.front();
    size_t best = 0;
    int best_score = score(m_candidates[0]);
    for (size_t i = 1; i < m_candidates.size(); ++i) {
        const int s = score(m_candidates[i]);
        if (s > best_score) {
            best = i;
            best_score = s;
        }
    }
    return m_types[m_candidates[best].lane];
}

size_t ValueTracker::candidate_count() const {
    if (!m_snapshot_phase) return m_candidates.size();
    size_t total = 0;
    for (const auto& b : m_blocks) {
        for (const auto& lane_bits : b.alive) total += count_bits(lane_bits);
    }
    return total;
}

size_t ValueTracker::memory_bytes() const {
    if (!m_snapshot_phase) return m_candidates.capacity() * sizeof(Candidate);
    size_t total = 0;
    for (const auto& b : m_blocks) {
        total += b.bytes.size();
        for (size_t lane = 0; lane < b.alive.size(); ++lane) {
            total += (b.alive[lane].size() + b.struck[lane].size()) * sizeof(uint64_t);
        }
    }
    return total;
}

std::vector<RankedCandidate> ValueTracker::top(size_t count) const {
    std::vector<RankedCandidate> best;
    if (m_snapshot_phase) return best;

    const auto order = ranked_order();
    const size_t n = std::min(count, order.size());
    best.reserve(n);
    for (size_t k = 0; k < n; ++k) {
        const Candidate& c = m_candidates[order[k]];
        RankedCandidate r;
        r.address = c.address;
        r.value = value_from_bytes(m_types[c.lane], reinterpret_cast<const uint8_t*>(&c.raw), value_size(c.lane)).value();
        r.score = score(c);
        r.reason = reason(c);
        best.push_back(std::move(r));
    }
    return best;
}

ScanResults ValueTracker::to_results() const {
    // Results hold one type: the best candidate's, or the first type while still a snapshot
    const DataType type = best_type();
    const size_t lane = static_cast<size_t>(std::find(m_types.begin(), m_types.end(), type) - m_types.begin());
    const size_t size = value_size(lane);
    ScanResults results(type, size);

    if (m_snapshot_phase) {
        for (const auto& b : m_blocks) {
            for_each_bit(b.alive[lane], [&](size_t slot) {
                const uint8_t* value = b.bytes.data() + slot * size;
                results.add(b.base_address + slot * size, value, value);
            });
        }
        return results;
    }

    for (const size_t i : ranked_order()) {
        const Candidate& c = m_candidates[i];
        if (c.lane != lane) continue;
        const auto* value = reinterpret_cast<const uint8_t*>(&c.raw);
        results.add(c.address, value, value);
    }
    return results;
}

} // namespace nce::scanner

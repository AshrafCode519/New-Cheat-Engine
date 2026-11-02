#include "../../include/scanner/memory_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/utils/text_encoding.hpp"
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <cstring>
#include <exception>
#include <type_traits>
#include <algorithm>

namespace nce::scanner {

namespace {

constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1 MB chunk

template <typename T>
bool match_condition(T current, ScanCondition cond, T target1, T target2 = 0) {
    switch (cond) {
        case ScanCondition::ExactValue:  return current == target1;
        case ScanCondition::GreaterThan: return current > target1;
        case ScanCondition::LessThan:    return current < target1;
        case ScanCondition::Between:     return current >= target1 && current <= target2;
        default:                         return false;
    }
}

// Floats: ExactValue keeps a small epsilon; Between is an exact inclusive range, which is what
// the rounded/truncated float modes rely on.
template <>
bool match_condition<float>(float current, ScanCondition cond, float target1, float target2) {
    constexpr float epsilon = 0.0001f;
    switch (cond) {
        case ScanCondition::ExactValue:  return std::fabs(current - target1) <= epsilon;
        case ScanCondition::GreaterThan: return current > target1;
        case ScanCondition::LessThan:    return current < target1;
        case ScanCondition::Between:     return current >= target1 && current <= target2;
        default:                         return false;
    }
}

template <>
bool match_condition<double>(double current, ScanCondition cond, double target1, double target2) {
    constexpr double epsilon = 0.000001;
    switch (cond) {
        case ScanCondition::ExactValue:  return std::fabs(current - target1) <= epsilon;
        case ScanCondition::GreaterThan: return current > target1;
        case ScanCondition::LessThan:    return current < target1;
        case ScanCondition::Between:     return current >= target1 && current <= target2;
        default:                         return false;
    }
}

// base +/- delta; integers wrap around instead of hitting signed-overflow UB
template <typename T>
T offset_value(T base, T delta, bool add) {
    if constexpr (std::is_integral_v<T>) {
        using U = std::make_unsigned_t<T>;
        const U b = static_cast<U>(base);
        const U d = static_cast<U>(delta);
        return static_cast<T>(add ? b + d : b - d);
    } else {
        return add ? base + delta : base - delta;
    }
}

template <typename T>
bool match_next_condition(T current, T previous, ScanCondition cond, T val1 = 0, T val2 = 0) {
    switch (cond) {
        case ScanCondition::ExactValue:  return match_condition(current, ScanCondition::ExactValue, val1);
        case ScanCondition::GreaterThan: return match_condition(current, ScanCondition::GreaterThan, val1);
        case ScanCondition::LessThan:    return match_condition(current, ScanCondition::LessThan, val1);
        case ScanCondition::Between:     return match_condition(current, ScanCondition::Between, val1, val2);
        case ScanCondition::Changed:     return current != previous;
        case ScanCondition::Unchanged:   return current == previous;
        case ScanCondition::Increased:   return current > previous;
        case ScanCondition::Decreased:   return current < previous;
        case ScanCondition::IncreasedBy: return match_condition(current, ScanCondition::ExactValue, offset_value(previous, val1, true));
        case ScanCondition::DecreasedBy: return match_condition(current, ScanCondition::ExactValue, offset_value(previous, val1, false));
    }
    return false;
}

bool condition_uses_value(ScanCondition cond) {
    switch (cond) {
        case ScanCondition::Changed:
        case ScanCondition::Unchanged:
        case ScanCondition::Increased:
        case ScanCondition::Decreased:
            return false;
        default:
            return true;
    }
}

// Raw bytes held by a String / String16 / AOB value
std::pair<const uint8_t*, size_t> raw_bytes(const ScanValue& v) {
    if (const auto* s = std::get_if<std::string>(&v.value)) {
        return {reinterpret_cast<const uint8_t*>(s->data()), s->size()};
    }
    if (const auto* b = std::get_if<std::vector<uint8_t>>(&v.value)) {
        return {b->data(), b->size()};
    }
    return {nullptr, 0};
}

ScanValue bytes_value(DataType type, std::vector<uint8_t> bytes) {
    if (type == DataType::String) return ScanValue::of(type, std::string(bytes.begin(), bytes.end()));
    return ScanValue::of(type, std::move(bytes));
}

template <typename T>
void scan_chunk_typed(
    const uint8_t* buffer,
    size_t buffer_size,
    uintptr_t chunk_base,
    ScanCondition cond,
    T target1,
    T target2,
    size_t alignment,
    DataType type,
    std::vector<ScanMatch>& local_matches
) {
    if (buffer_size < sizeof(T)) return;
    const size_t max_offset = buffer_size - sizeof(T);

    for (size_t offset = 0; offset <= max_offset; offset += alignment) {
        T value;
        std::memcpy(&value, buffer + offset, sizeof(T));

        if (match_condition(value, cond, target1, target2)) {
            const auto sv = ScanValue::of(type, value);
            local_matches.push_back({chunk_base + offset, sv, sv});
        }
    }
}

void scan_chunk_aob(
    const uint8_t* buffer,
    size_t buffer_size,
    uintptr_t chunk_base,
    const AOBPattern& pattern,
    size_t alignment,
    DataType result_type,
    std::vector<ScanMatch>& local_matches
) {
    const size_t pattern_size = pattern.bytes.size();
    if (buffer_size < pattern_size) return;
    const size_t max_offset = buffer_size - pattern_size;

    for (size_t offset = 0; offset <= max_offset; offset += alignment) {
        bool match = true;
        for (size_t j = 0; j < pattern_size; ++j) {
            if (pattern.mask[j] && buffer[offset + j] != pattern.bytes[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            const auto sv = bytes_value(result_type, std::vector<uint8_t>(buffer + offset, buffer + offset + pattern_size));
            local_matches.push_back({chunk_base + offset, sv, sv});
        }
    }
}

// Runs body(state, i) for every i in [0, count) on up to thread_count threads; each thread gets
// its own state from make_state(). The first exception (e.g. bad_alloc on huge result sets) stops
// the remaining work and is rethrown on the calling thread instead of terminating the process.
template <typename MakeState, typename Body>
void parallel_for(size_t count, size_t thread_count, MakeState&& make_state, Body&& body) {
    std::atomic<size_t> next_index{0};
    std::atomic<bool> failed{false};
    std::mutex error_mutex;
    std::exception_ptr error;

    auto worker = [&]() {
        try {
            auto state = make_state();
            while (!failed) {
                const size_t i = next_index.fetch_add(1);
                if (i >= count) break;
                body(state, i);
            }
        } catch (...) {
            std::lock_guard<std::mutex> lock(error_mutex);
            if (!error) error = std::current_exception();
            failed = true;
        }
    };

    const size_t worker_count = std::clamp<size_t>(thread_count, 1, std::max<size_t>(1, count));
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    if (error) std::rethrow_exception(error);
}

// Splits the matching regions across worker threads and hands every 1 MB chunk to scan_chunk
template <typename ChunkScanner>
ScanResults scan_regions(
    const hal::IProcess& process,
    uint32_t region_filter,
    size_t thread_count,
    const ScanProgressCallback& progress,
    ChunkScanner&& scan_chunk
) {
    ScanResults results;

    const auto regions = process.query_regions(region_filter);
    if (regions.empty()) return results;

    size_t total_bytes = 0;
    for (const auto& r : regions) total_bytes += r.size;

    std::atomic<size_t> scanned_bytes{0};
    std::mutex results_mutex;

    struct WorkerState {
        std::vector<uint8_t> chunk_buffer = std::vector<uint8_t>(CHUNK_SIZE);
        std::vector<ScanMatch> local_matches;
    };

    parallel_for(regions.size(), thread_count, [] { return WorkerState{}; }, [&](WorkerState& state, size_t idx) {
        const auto& reg = regions[idx];
        uintptr_t current_addr = reg.base_address;
        size_t remaining = reg.size;

        while (remaining > 0) {
            size_t to_read = std::min(remaining, CHUNK_SIZE);
            if (process.read_raw(current_addr, state.chunk_buffer.data(), to_read)) {
                scan_chunk(state.chunk_buffer.data(), to_read, current_addr, state.local_matches);
            }

            current_addr += to_read;
            remaining -= to_read;
            scanned_bytes.fetch_add(to_read);

            if (progress) {
                progress(scanned_bytes.load(), total_bytes, state.local_matches.size());
            }
        }

        if (!state.local_matches.empty()) {
            std::lock_guard<std::mutex> lock(results_mutex);
            for (const auto& m : state.local_matches) {
                results.add_match(m.address, m.current_value, m.previous_value);
            }
            state.local_matches.clear();
        }
    });

    return results;
}

} // anonymous namespace

MemoryScanner::MemoryScanner(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
    , m_thread_count(std::max(1u, std::thread::hardware_concurrency()))
{}

ScanResults MemoryScanner::first_scan(
    DataType type,
    ScanCondition condition,
    const ScanValue& val1,
    const ScanValue& val2,
    size_t alignment,
    uint32_t region_filter,
    ScanProgressCallback progress
) {
    ScanResults results;
    if (!m_process || !m_process->is_attached()) return results;

    const size_t step = std::max<size_t>(1, alignment);

    dispatch_numeric(type, [&]<typename T>() {
        // Read the targets here so a ScanValue of the wrong type throws on the caller's thread, not in a worker
        const T target1 = std::get<T>(val1.value);
        const T target2 = (condition == ScanCondition::Between) ? std::get<T>(val2.value) : T{};

        results = scan_regions(*m_process, region_filter, m_thread_count, progress,
            [&](const uint8_t* buffer, size_t size, uintptr_t base, std::vector<ScanMatch>& out) {
                scan_chunk_typed<T>(buffer, size, base, condition, target1, target2, step, type, out);
            });
    });

    return results;
}

ScanResults MemoryScanner::first_scan_aob(
    const std::string& aob_pattern,
    size_t alignment,
    uint32_t region_filter,
    ScanProgressCallback progress
) {
    if (!m_process || !m_process->is_attached()) return {};

    auto opt_pattern = utils::parse_aob_pattern(aob_pattern);
    if (!opt_pattern) return {};
    const auto& pattern = *opt_pattern;
    const size_t step = std::max<size_t>(1, alignment);

    return scan_regions(*m_process, region_filter, m_thread_count, progress,
        [&](const uint8_t* buffer, size_t size, uintptr_t base, std::vector<ScanMatch>& out) {
            scan_chunk_aob(buffer, size, base, pattern, step, DataType::AOB, out);
        });
}

ScanResults MemoryScanner::first_scan_string(
    const std::string& utf8_text,
    bool utf16,
    size_t alignment,
    uint32_t region_filter,
    ScanProgressCallback progress
) {
    if (!m_process || !m_process->is_attached() || utf8_text.empty()) return {};

    AOBPattern pattern;
    if (utf16) {
        auto encoded = utils::utf8_to_utf16le(utf8_text);
        if (!encoded) return {};
        pattern.bytes = std::move(*encoded);
    } else {
        pattern.bytes.assign(utf8_text.begin(), utf8_text.end());
    }
    pattern.mask.assign(pattern.bytes.size(), true);

    const DataType type = utf16 ? DataType::String16 : DataType::String;
    const size_t step = std::max<size_t>(1, alignment);

    return scan_regions(*m_process, region_filter, m_thread_count, progress,
        [&](const uint8_t* buffer, size_t size, uintptr_t base, std::vector<ScanMatch>& out) {
            scan_chunk_aob(buffer, size, base, pattern, step, type, out);
        });
}

MemorySnapshot MemoryScanner::first_scan_unknown(
    DataType type,
    size_t alignment,
    uint32_t region_filter,
    ScanProgressCallback progress
) {
    MemorySnapshot snapshot;
    snapshot.type = type;
    snapshot.alignment = std::max<size_t>(1, alignment);

    const bool is_numeric = dispatch_numeric(type, []<typename T>() {});
    if (!m_process || !m_process->is_attached() || !is_numeric) return snapshot;

    // Allocate every block up front on this thread, so running out of memory throws here
    for (const auto& reg : m_process->query_regions(region_filter)) {
        for (size_t offset = 0; offset < reg.size; offset += CHUNK_SIZE) {
            MemorySnapshot::Block block;
            block.base_address = reg.base_address + offset;
            block.bytes.resize(std::min(CHUNK_SIZE, reg.size - offset));
            snapshot.blocks.push_back(std::move(block));
        }
    }

    const size_t total_bytes = snapshot.total_bytes();
    std::atomic<size_t> copied_bytes{0};
    std::vector<char> read_ok(snapshot.blocks.size(), 0);

    parallel_for(snapshot.blocks.size(), m_thread_count, [] { return 0; }, [&](int&, size_t i) {
        auto& block = snapshot.blocks[i];
        read_ok[i] = m_process->read_raw(block.base_address, block.bytes.data(), block.bytes.size()) ? 1 : 0;
        copied_bytes.fetch_add(block.bytes.size());
        if (progress) {
            progress(copied_bytes.load(), total_bytes, 0);
        }
    });

    // Drop blocks that could not be read (e.g. freed since query_regions)
    std::vector<MemorySnapshot::Block> readable;
    readable.reserve(snapshot.blocks.size());
    for (size_t i = 0; i < snapshot.blocks.size(); ++i) {
        if (read_ok[i]) readable.push_back(std::move(snapshot.blocks[i]));
    }
    snapshot.blocks = std::move(readable);

    return snapshot;
}

ScanResults MemoryScanner::next_scan(
    const ScanResults& previous_results,
    ScanCondition condition,
    const ScanValue& val1,
    const ScanValue& val2,
    ScanProgressCallback progress
) {
    ScanResults results;
    if (!m_process || !m_process->is_attached() || previous_results.empty()) return results;

    const auto& prev_matches = previous_results.get_matches();
    results.reserve(prev_matches.size());

    const bool uses_val1 = condition_uses_value(condition);
    const bool uses_val2 = (condition == ScanCondition::Between);

    size_t processed = 0;
    const size_t total = prev_matches.size();

    for (const auto& match : prev_matches) {
        DataType type = match.current_value.type;
        ScanValue current_val;
        current_val.type = type;
        bool matched = false;

        const bool is_numeric = dispatch_numeric(type, [&]<typename T>() {
            T live_val{};
            if (!m_process->read(match.address, live_val)) return;

            const T prev_val = std::get<T>(match.current_value.value);
            const T target1 = uses_val1 ? std::get<T>(val1.value) : T{};
            const T target2 = uses_val2 ? std::get<T>(val2.value) : T{};

            if (match_next_condition(live_val, prev_val, condition, target1, target2)) {
                current_val.value = live_val;
                matched = true;
            }
        });

        // String / String16 / AOB results only support Changed / Unchanged against the bytes
        // captured by the previous scan
        if (!is_numeric && (condition == ScanCondition::Changed || condition == ScanCondition::Unchanged)) {
            const auto [prev_data, prev_size] = raw_bytes(match.current_value);
            std::vector<uint8_t> live_bytes(prev_size);
            if (prev_size > 0 && m_process->read_raw(match.address, live_bytes.data(), prev_size)) {
                const bool unchanged = std::memcmp(live_bytes.data(), prev_data, prev_size) == 0;
                if (unchanged == (condition == ScanCondition::Unchanged)) {
                    current_val = bytes_value(type, std::move(live_bytes));
                    matched = true;
                }
            }
        }

        if (matched) {
            results.add_match(match.address, current_val, match.current_value);
        }

        processed++;
        if (progress && (processed % 1000 == 0 || processed == total)) {
            progress(processed, total, results.count());
        }
    }

    return results;
}

ScanResults MemoryScanner::next_scan(
    const MemorySnapshot& snapshot,
    ScanCondition condition,
    const ScanValue& val1,
    const ScanValue& val2,
    ScanProgressCallback progress
) {
    ScanResults results;
    if (!m_process || !m_process->is_attached() || snapshot.blocks.empty()) return results;

    const bool uses_val1 = condition_uses_value(condition);
    const bool uses_val2 = (condition == ScanCondition::Between);
    const size_t step = std::max<size_t>(1, snapshot.alignment);
    const DataType type = snapshot.type;

    dispatch_numeric(type, [&]<typename T>() {
        const T target1 = uses_val1 ? std::get<T>(val1.value) : T{};
        const T target2 = uses_val2 ? std::get<T>(val2.value) : T{};

        const size_t total_bytes = snapshot.total_bytes();
        std::atomic<size_t> compared_bytes{0};
        std::atomic<size_t> found{0};
        std::mutex results_mutex;

        struct WorkerState {
            std::vector<uint8_t> live;
            std::vector<ScanMatch> local_matches;
        };

        parallel_for(snapshot.blocks.size(), m_thread_count, [] { return WorkerState{}; }, [&](WorkerState& state, size_t i) {
            const auto& block = snapshot.blocks[i];
            const size_t size = block.bytes.size();
            state.live.resize(size);

            if (size >= sizeof(T) && m_process->read_raw(block.base_address, state.live.data(), size)) {
                for (size_t offset = 0; offset + sizeof(T) <= size; offset += step) {
                    T current, previous;
                    std::memcpy(&current, state.live.data() + offset, sizeof(T));
                    std::memcpy(&previous, block.bytes.data() + offset, sizeof(T));

                    if (match_next_condition(current, previous, condition, target1, target2)) {
                        state.local_matches.push_back({
                            block.base_address + offset, ScanValue::of(type, current), ScanValue::of(type, previous)
                        });
                    }
                }
            }

            found.fetch_add(state.local_matches.size());
            if (!state.local_matches.empty()) {
                std::lock_guard<std::mutex> lock(results_mutex);
                for (const auto& m : state.local_matches) {
                    results.add_match(m.address, m.current_value, m.previous_value);
                }
                state.local_matches.clear();
            }

            compared_bytes.fetch_add(size);
            if (progress) {
                progress(compared_bytes.load(), total_bytes, found.load());
            }
        });
    });

    return results;
}

} // namespace nce::scanner

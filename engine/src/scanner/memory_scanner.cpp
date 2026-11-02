#include "../../include/scanner/memory_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
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

template <>
bool match_condition<float>(float current, ScanCondition cond, float target1, float target2) {
    constexpr float epsilon = 0.0001f;
    switch (cond) {
        case ScanCondition::ExactValue:  return std::fabs(current - target1) <= epsilon;
        case ScanCondition::GreaterThan: return current > target1;
        case ScanCondition::LessThan:    return current < target1;
        case ScanCondition::Between:     return current >= (target1 - epsilon) && current <= (target2 + epsilon);
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
        case ScanCondition::Between:     return current >= (target1 - epsilon) && current <= (target2 + epsilon);
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
            ScanValue sv;
            sv.type = type;
            sv.value = value;
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
            std::vector<uint8_t> matched_bytes(buffer + offset, buffer + offset + pattern_size);
            ScanValue sv;
            sv.type = DataType::AOB;
            sv.value = matched_bytes;
            local_matches.push_back({chunk_base + offset, sv, sv});
        }
    }
}

// Splits the matching regions across worker threads and hands every 1 MB chunk to scan_chunk.
// An exception in a worker (e.g. bad_alloc on huge result sets) is rethrown on the calling thread
// instead of terminating the process.
template <typename ChunkScanner>
ScanResults scan_regions(
    const hal::IProcess& process,
    uint32_t region_filter,
    size_t thread_count,
    const ScanProgressCallback& progress,
    ChunkScanner&& scan_chunk
) {
    ScanResults results;

    auto regions = process.query_regions(region_filter);
    if (regions.empty()) return results;

    size_t total_bytes = 0;
    for (const auto& r : regions) total_bytes += r.size;

    std::atomic<size_t> scanned_bytes{0};
    std::atomic<size_t> region_index{0};
    std::atomic<bool> failed{false};
    std::mutex results_mutex;
    std::exception_ptr worker_error;

    constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1 MB chunk

    auto worker = [&]() {
        try {
            std::vector<uint8_t> chunk_buffer(CHUNK_SIZE);
            std::vector<ScanMatch> local_matches;
            local_matches.reserve(4096);

            while (!failed) {
                size_t idx = region_index.fetch_add(1);
                if (idx >= regions.size()) break;

                const auto& reg = regions[idx];
                uintptr_t current_addr = reg.base_address;
                size_t remaining = reg.size;

                while (remaining > 0) {
                    size_t to_read = std::min(remaining, CHUNK_SIZE);
                    if (process.read_raw(current_addr, chunk_buffer.data(), to_read)) {
                        scan_chunk(chunk_buffer.data(), to_read, current_addr, local_matches);
                    }

                    current_addr += to_read;
                    remaining -= to_read;
                    scanned_bytes.fetch_add(to_read);

                    if (progress) {
                        progress(scanned_bytes.load(), total_bytes, local_matches.size());
                    }
                }

                if (!local_matches.empty()) {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    for (const auto& m : local_matches) {
                        results.add_match(m.address, m.current_value, m.previous_value);
                    }
                    local_matches.clear();
                }
            }
        } catch (...) {
            std::lock_guard<std::mutex> lock(results_mutex);
            if (!worker_error) worker_error = std::current_exception();
            failed = true;
        }
    };

    const size_t worker_count = std::max<size_t>(1, thread_count);
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    if (worker_error) std::rethrow_exception(worker_error);
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
            scan_chunk_aob(buffer, size, base, pattern, step, out);
        });
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

        // AOB results only support Changed / Unchanged against the bytes captured by the previous scan
        if (!is_numeric && type == DataType::AOB &&
            (condition == ScanCondition::Changed || condition == ScanCondition::Unchanged)) {
            const auto& prev_bytes = std::get<std::vector<uint8_t>>(match.current_value.value);
            std::vector<uint8_t> live_bytes(prev_bytes.size());
            if (!live_bytes.empty() && m_process->read_raw(match.address, live_bytes.data(), live_bytes.size())) {
                const bool unchanged = (live_bytes == prev_bytes);
                if (unchanged == (condition == ScanCondition::Unchanged)) {
                    current_val.value = std::move(live_bytes);
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

} // namespace nce::scanner

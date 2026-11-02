#include "../../include/scanner/memory_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <cstring>
#include <iostream>

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
        case ScanCondition::IncreasedBy: return current == (previous + val1);
        case ScanCondition::DecreasedBy: return current == (previous - val1);
    }
    return false;
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

    auto regions = m_process->query_regions(region_filter);
    if (regions.empty()) return results;

    size_t total_bytes = 0;
    for (const auto& r : regions) total_bytes += r.size;

    std::atomic<size_t> scanned_bytes{0};
    std::atomic<size_t> region_index{0};
    std::mutex results_mutex;

    constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1 MB chunk

    auto worker = [&]() {
        std::vector<uint8_t> chunk_buffer(CHUNK_SIZE);
        std::vector<ScanMatch> local_matches;
        local_matches.reserve(4096);

        while (true) {
            size_t idx = region_index.fetch_add(1);
            if (idx >= regions.size()) break;

            const auto& reg = regions[idx];
            uintptr_t current_addr = reg.base_address;
            size_t remaining = reg.size;

            while (remaining > 0) {
                size_t to_read = std::min(remaining, CHUNK_SIZE);
                if (m_process->read_raw(current_addr, chunk_buffer.data(), to_read)) {
                    switch (type) {
                        case DataType::Int8:
                            scan_chunk_typed<int8_t>(chunk_buffer.data(), to_read, current_addr, condition,
                                std::get<int8_t>(val1.value), 0, alignment, type, local_matches);
                            break;
                        case DataType::Int16:
                            scan_chunk_typed<int16_t>(chunk_buffer.data(), to_read, current_addr, condition,
                                std::get<int16_t>(val1.value), 0, alignment, type, local_matches);
                            break;
                        case DataType::Int32:
                            scan_chunk_typed<int32_t>(chunk_buffer.data(), to_read, current_addr, condition,
                                std::get<int32_t>(val1.value),
                                (condition == ScanCondition::Between ? std::get<int32_t>(val2.value) : 0),
                                alignment, type, local_matches);
                            break;
                        case DataType::Int64:
                            scan_chunk_typed<int64_t>(chunk_buffer.data(), to_read, current_addr, condition,
                                std::get<int64_t>(val1.value),
                                (condition == ScanCondition::Between ? std::get<int64_t>(val2.value) : 0),
                                alignment, type, local_matches);
                            break;
                        case DataType::Float:
                            scan_chunk_typed<float>(chunk_buffer.data(), to_read, current_addr, condition,
                                std::get<float>(val1.value),
                                (condition == ScanCondition::Between ? std::get<float>(val2.value) : 0.0f),
                                alignment, type, local_matches);
                            break;
                        case DataType::Double:
                            scan_chunk_typed<double>(chunk_buffer.data(), to_read, current_addr, condition,
                                std::get<double>(val1.value),
                                (condition == ScanCondition::Between ? std::get<double>(val2.value) : 0.0),
                                alignment, type, local_matches);
                            break;
                        default:
                            break;
                    }
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
    };

    std::vector<std::thread> threads;
    threads.reserve(m_thread_count);
    for (size_t i = 0; i < m_thread_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    return results;
}

ScanResults MemoryScanner::first_scan_aob(
    const std::string& aob_pattern,
    size_t alignment,
    uint32_t region_filter,
    ScanProgressCallback progress
) {
    ScanResults results;
    if (!m_process || !m_process->is_attached()) return results;

    auto opt_pattern = utils::parse_aob_pattern(aob_pattern);
    if (!opt_pattern) return results;
    const auto& pattern = *opt_pattern;

    auto regions = m_process->query_regions(region_filter);
    if (regions.empty()) return results;

    size_t total_bytes = 0;
    for (const auto& r : regions) total_bytes += r.size;

    std::atomic<size_t> scanned_bytes{0};
    std::atomic<size_t> region_index{0};
    std::mutex results_mutex;

    constexpr size_t CHUNK_SIZE = 1024 * 1024;

    auto worker = [&]() {
        std::vector<uint8_t> chunk_buffer(CHUNK_SIZE);
        std::vector<ScanMatch> local_matches;

        while (true) {
            size_t idx = region_index.fetch_add(1);
            if (idx >= regions.size()) break;

            const auto& reg = regions[idx];
            uintptr_t current_addr = reg.base_address;
            size_t remaining = reg.size;

            while (remaining > 0) {
                size_t to_read = std::min(remaining, CHUNK_SIZE);
                if (m_process->read_raw(current_addr, chunk_buffer.data(), to_read)) {
                    scan_chunk_aob(chunk_buffer.data(), to_read, current_addr, pattern, alignment, local_matches);
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
    };

    std::vector<std::thread> threads;
    threads.reserve(m_thread_count);
    for (size_t i = 0; i < m_thread_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    return results;
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

    size_t processed = 0;
    const size_t total = prev_matches.size();

    for (const auto& match : prev_matches) {
        DataType type = match.current_value.type;
        ScanValue current_val;
        current_val.type = type;
        bool matched = false;

        switch (type) {
            case DataType::Int32: {
                int32_t live_val = 0;
                if (m_process->read(match.address, live_val)) {
                    int32_t prev_val = std::get<int32_t>(match.current_value.value);
                    int32_t target1 = (condition == ScanCondition::ExactValue || condition == ScanCondition::IncreasedBy || condition == ScanCondition::DecreasedBy) ? std::get<int32_t>(val1.value) : 0;
                    int32_t target2 = (condition == ScanCondition::Between) ? std::get<int32_t>(val2.value) : 0;

                    if (match_next_condition(live_val, prev_val, condition, target1, target2)) {
                        current_val.value = live_val;
                        matched = true;
                    }
                }
                break;
            }
            case DataType::Int64: {
                int64_t live_val = 0;
                if (m_process->read(match.address, live_val)) {
                    int64_t prev_val = std::get<int64_t>(match.current_value.value);
                    int64_t target1 = (condition == ScanCondition::ExactValue) ? std::get<int64_t>(val1.value) : 0;
                    int64_t target2 = (condition == ScanCondition::Between) ? std::get<int64_t>(val2.value) : 0;

                    if (match_next_condition(live_val, prev_val, condition, target1, target2)) {
                        current_val.value = live_val;
                        matched = true;
                    }
                }
                break;
            }
            case DataType::Float: {
                float live_val = 0.0f;
                if (m_process->read(match.address, live_val)) {
                    float prev_val = std::get<float>(match.current_value.value);
                    float target1 = (condition == ScanCondition::ExactValue) ? std::get<float>(val1.value) : 0.0f;
                    float target2 = (condition == ScanCondition::Between) ? std::get<float>(val2.value) : 0.0f;

                    if (match_next_condition(live_val, prev_val, condition, target1, target2)) {
                        current_val.value = live_val;
                        matched = true;
                    }
                }
                break;
            }
            case DataType::Double: {
                double live_val = 0.0;
                if (m_process->read(match.address, live_val)) {
                    double prev_val = std::get<double>(match.current_value.value);
                    double target1 = (condition == ScanCondition::ExactValue) ? std::get<double>(val1.value) : 0.0;
                    double target2 = (condition == ScanCondition::Between) ? std::get<double>(val2.value) : 0.0;

                    if (match_next_condition(live_val, prev_val, condition, target1, target2)) {
                        current_val.value = live_val;
                        matched = true;
                    }
                }
                break;
            }
            default:
                break;
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


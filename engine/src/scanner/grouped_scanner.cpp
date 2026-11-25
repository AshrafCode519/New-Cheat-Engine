#include "../../include/scanner/grouped_scanner.hpp"
#include <algorithm>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <optional>
#include <utility>

namespace nce::scanner {

namespace {

template <typename T>
bool check_val_at(const uint8_t* ptr, T expected) {
    T actual;
    std::memcpy(&actual, ptr, sizeof(T));
    return actual == expected;
}

template <>
bool check_val_at<float>(const uint8_t* ptr, float expected) {
    float actual;
    std::memcpy(&actual, ptr, sizeof(float));
    return std::fabs(actual - expected) <= 0.0001f;
}

template <>
bool check_val_at<double>(const uint8_t* ptr, double expected) {
    double actual;
    std::memcpy(&actual, ptr, sizeof(double));
    return std::fabs(actual - expected) <= 0.000001;
}

bool check_entry_match(const uint8_t* ptr, const GroupedEntry& entry) {
    bool matched = false;
    dispatch_numeric(entry.type, [&]<typename T>() {
        matched = check_val_at<T>(ptr, std::get<T>(entry.value.value));
    });
    return matched;
}

} // anonymous namespace

GroupedScanner::GroupedScanner(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
{}

std::vector<GroupedMatch> GroupedScanner::scan(
    const std::vector<GroupedEntry>& entries,
    size_t window_size,
    uint32_t region_filter
) {
    std::vector<GroupedMatch> results;
    if (!m_process || !m_process->is_attached() || entries.empty()) return results;

    auto regions = m_process->query_regions(region_filter);
    if (regions.empty()) return results;

    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    constexpr size_t MAX_VALUE_SIZE = 8;
    // Each chunk is read with window_size bytes of margin on both sides, so other members are found on
    // either side of the first one, also across chunk borders
    std::vector<uint8_t> buffer(CHUNK_SIZE + 2 * window_size + MAX_VALUE_SIZE);

    const auto& first_entry = entries[0];
    const size_t first_size = get_data_type_size(first_entry.type);

    for (const auto& reg : regions) {
        for (size_t chunk_start = 0; chunk_start < reg.size; chunk_start += CHUNK_SIZE) {
            const size_t chunk_end = std::min(reg.size, chunk_start + CHUNK_SIZE);
            const size_t read_start = chunk_start >= window_size ? chunk_start - window_size : 0;
            const size_t read_size = std::min(reg.size, chunk_end + window_size + MAX_VALUE_SIZE) - read_start;
            if (!m_process->read_raw(reg.base_address + read_start, buffer.data(), read_size)) continue;
            const uintptr_t buffer_base = reg.base_address + read_start;

            // The first member, aligned to its own size (region bases are page aligned)
            for (size_t pos = chunk_start; pos < chunk_end; pos += first_size) {
                const size_t first_at = pos - read_start; // index in buffer
                if (first_at + first_size > read_size) break;
                if (!check_entry_match(buffer.data() + first_at, first_entry)) continue;

                std::vector<uintptr_t> matched_addrs{reg.base_address + pos};
                std::vector<std::pair<size_t, size_t>> taken{{first_at, first_at + first_size}}; // buffer ranges in use
                bool all_matched = true;

                for (size_t e = 1; e < entries.size() && all_matched; ++e) {
                    const auto& entry = entries[e];
                    const size_t size = get_data_type_size(entry.type);
                    auto is_free = [&](size_t at) {
                        for (const auto& [begin, end] : taken) {
                            if (at < end && at + size > begin) return false;
                        }
                        return true;
                    };

                    std::optional<size_t> found;
                    if (entry.exact_offset) {
                        const size_t at = first_at + entry.expected_offset;
                        if (at + size <= read_size && is_free(at) && check_entry_match(buffer.data() + at, entry)) found = at;
                    } else {
                        // Every aligned spot within the window on either side; the closest match wins
                        size_t at = first_at >= window_size ? first_at - window_size : 0;
                        if (const size_t misaligned = (buffer_base + at) % size; misaligned != 0) at += size - misaligned;
                        size_t best_distance = SIZE_MAX;
                        for (; at + size <= read_size && at <= first_at + window_size; at += size) {
                            if (!is_free(at) || !check_entry_match(buffer.data() + at, entry)) continue;
                            const size_t distance = at > first_at ? at - first_at : first_at - at;
                            if (distance < best_distance) {
                                best_distance = distance;
                                found = at;
                            }
                        }
                    }

                    if (!found) {
                        all_matched = false;
                    } else {
                        matched_addrs.push_back(buffer_base + *found);
                        taken.emplace_back(*found, *found + size);
                    }
                }

                if (all_matched) {
                    results.push_back({reg.base_address + pos, matched_addrs});
                }
            }
        }
    }

    return results;
}

} // namespace nce::scanner


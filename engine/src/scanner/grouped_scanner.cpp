#include "../../include/scanner/grouped_scanner.hpp"
#include <cstring>
#include <cmath>

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
    switch (entry.type) {
        case DataType::Int8:   return check_val_at<int8_t>(ptr, std::get<int8_t>(entry.value.value));
        case DataType::Int16:  return check_val_at<int16_t>(ptr, std::get<int16_t>(entry.value.value));
        case DataType::Int32:  return check_val_at<int32_t>(ptr, std::get<int32_t>(entry.value.value));
        case DataType::Int64:  return check_val_at<int64_t>(ptr, std::get<int64_t>(entry.value.value));
        case DataType::Float:  return check_val_at<float>(ptr, std::get<float>(entry.value.value));
        case DataType::Double: return check_val_at<double>(ptr, std::get<double>(entry.value.value));
        default: return false;
    }
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
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    const auto& first_entry = entries[0];
    const size_t first_size = get_data_type_size(first_entry.type);

    for (const auto& reg : regions) {
        uintptr_t current_addr = reg.base_address;
        size_t remaining = reg.size;

        while (remaining >= window_size) {
            size_t to_read = std::min(remaining, CHUNK_SIZE);
            if (m_process->read_raw(current_addr, buffer.data(), to_read)) {
                size_t limit = (to_read >= window_size) ? (to_read - window_size) : 0;

                for (size_t offset = 0; offset <= limit; offset += 4) {
                    if (check_entry_match(buffer.data() + offset, first_entry)) {
                        bool all_matched = true;
                        std::vector<uintptr_t> matched_addrs;
                        matched_addrs.push_back(current_addr + offset);

                        for (size_t e = 1; e < entries.size(); ++e) {
                            const auto& entry = entries[e];
                            const size_t entry_size = get_data_type_size(entry.type);
                            bool found = false;

                            if (entry.exact_offset) {
                                if (offset + entry.expected_offset + entry_size <= to_read) {
                                    if (check_entry_match(buffer.data() + offset + entry.expected_offset, entry)) {
                                        matched_addrs.push_back(current_addr + offset + entry.expected_offset);
                                        found = true;
                                    }
                                }
                            } else {
                                size_t search_limit = std::min(to_read - entry_size, offset + window_size);
                                for (size_t s = offset + first_size; s <= search_limit; s += 4) {
                                    if (check_entry_match(buffer.data() + s, entry)) {
                                        matched_addrs.push_back(current_addr + s);
                                        found = true;
                                        break;
                                    }
                                }
                            }

                            if (!found) {
                                all_matched = false;
                                break;
                            }
                        }

                        if (all_matched) {
                            results.push_back({current_addr + offset, matched_addrs});
                        }
                    }
                }
            }

            current_addr += to_read;
            remaining -= to_read;
        }
    }

    return results;
}

} // namespace nce::scanner


#include "../../include/scanner/memory_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/utils/text_encoding.hpp"
#include "parallel.hpp"
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <bit>
#include <cstring>
#include <exception>
#include <type_traits>
#include <algorithm>

namespace nce::scanner {

namespace {

using detail::parallel_for;

constexpr size_t CHUNK_SIZE = 1024 * 1024;        // first scans read regions in 1 MB chunks
constexpr size_t PAGE_SIZE = 4096;                // fallback read size when a chunk read fails
constexpr size_t SNAPSHOT_BLOCK_SIZE = 64 * 1024; // unknown-value snapshots are kept in 64 KB blocks
constexpr size_t NEXT_SCAN_SLICE = 1 << 16;       // results per next-scan work item
constexpr size_t NEXT_SCAN_WINDOW = 64 * 1024;    // one read covers up to 64 KB of neighbouring results

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

// Same comparison on raw bytes (values read from memory are not necessarily aligned)
template <typename T>
bool match_next_bytes(const uint8_t* live, const uint8_t* prev, ScanCondition cond, T val1, T val2) {
    T current, previous;
    std::memcpy(&current, live, sizeof(T));
    std::memcpy(&previous, prev, sizeof(T));
    return match_next_condition(current, previous, cond, val1, val2);
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

// Number of positions a value of value_size bytes fits at in `bytes`, stepping by `step`
size_t slot_count(size_t bytes, size_t value_size, size_t step) {
    return bytes >= value_size ? (bytes - value_size) / step + 1 : 0;
}

std::vector<uint64_t> all_slots_alive(size_t slots) {
    std::vector<uint64_t> bits((slots + 63) / 64, ~uint64_t{0});
    if (!bits.empty() && slots % 64 != 0) {
        bits.back() = (uint64_t{1} << (slots % 64)) - 1;
    }
    return bits;
}

template <typename Fn>
void for_each_alive_slot(const std::vector<uint64_t>& alive, Fn&& fn) {
    for (size_t w = 0; w < alive.size(); ++w) {
        uint64_t word = alive[w];
        while (word != 0) {
            fn(w * 64 + static_cast<size_t>(std::countr_zero(word)));
            word &= word - 1;
        }
    }
}

// Scans start offsets [0, start_limit); buffer_size may extend past start_limit so values that
// straddle the end of a chunk are still compared in full.
template <typename T>
void scan_chunk_typed(
    const uint8_t* buffer,
    size_t buffer_size,
    size_t start_limit,
    uintptr_t chunk_base,
    ScanCondition cond,
    T target1,
    T target2,
    size_t alignment,
    ScanResults& out
) {
    for (size_t offset = 0; offset < start_limit && offset + sizeof(T) <= buffer_size; offset += alignment) {
        T value;
        std::memcpy(&value, buffer + offset, sizeof(T));

        if (match_condition(value, cond, target1, target2)) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }
}

void scan_chunk_aob(
    const uint8_t* buffer,
    size_t buffer_size,
    size_t start_limit,
    uintptr_t chunk_base,
    const AOBPattern& pattern,
    size_t alignment,
    ScanResults& out
) {
    const size_t pattern_size = pattern.bytes.size();

    for (size_t offset = 0; offset < start_limit && offset + pattern_size <= buffer_size; offset += alignment) {
        bool match = true;
        for (size_t j = 0; j < pattern_size; ++j) {
            if (pattern.mask[j] && buffer[offset + j] != pattern.bytes[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }
}

// Concatenates per-work-item results in order, freeing each part as it goes
ScanResults merge_parts(std::vector<ScanResults>& parts, DataType type, size_t value_size) {
    ScanResults merged(type, value_size);
    size_t total = 0;
    for (const auto& p : parts) total += p.count();
    merged.reserve(total);
    for (auto& p : parts) {
        merged.append(p);
        p = ScanResults();
    }
    return merged;
}

// Splits the matching regions across worker threads and hands every 1 MB chunk to scan_chunk.
// Results come back in address order (regions are queried in ascending order).
template <typename ChunkScanner>
ScanResults scan_regions(
    const hal::IProcess& process,
    uint32_t region_filter,
    size_t thread_count,
    const ScanProgressCallback& progress,
    DataType type,
    size_t value_size,
    ChunkScanner&& scan_chunk
) {
    const auto regions = process.query_regions(region_filter);
    if (regions.empty() || value_size == 0) return ScanResults(type, value_size);

    size_t total_bytes = 0;
    for (const auto& r : regions) total_bytes += r.size;

    std::atomic<size_t> scanned_bytes{0};
    std::vector<ScanResults> parts(regions.size(), ScanResults(type, value_size));

    // Each chunk is read with value_size - 1 extra bytes, so a match that straddles two chunks is found
    const size_t overlap = value_size - 1;

    parallel_for(regions.size(), thread_count,
        [&] { return std::vector<uint8_t>(CHUNK_SIZE + overlap); },
        [&](std::vector<uint8_t>& buffer, size_t idx) {
            const auto& reg = regions[idx];
            auto& out = parts[idx];

            for (size_t offset = 0; offset < reg.size; offset += CHUNK_SIZE) {
                const uintptr_t base = reg.base_address + offset;
                const size_t chunk = std::min(CHUNK_SIZE, reg.size - offset);
                const size_t to_read = std::min(chunk + overlap, reg.size - offset);

                if (process.read_raw(base, buffer.data(), to_read)) {
                    scan_chunk(buffer.data(), to_read, chunk, base, out);
                } else {
                    // Part of the chunk is unreadable (e.g. freed since query_regions): retry page by page
                    for (size_t page = 0; page < chunk; page += PAGE_SIZE) {
                        const size_t page_len = std::min(PAGE_SIZE, chunk - page);
                        size_t page_read = std::min(page_len + overlap, reg.size - offset - page);
                        if (!process.read_raw(base + page, buffer.data(), page_read)) {
                            if (page_read == page_len || !process.read_raw(base + page, buffer.data(), page_len)) continue;
                            page_read = page_len;
                        }
                        scan_chunk(buffer.data(), page_read, page_len, base + page, out);
                    }
                }

                scanned_bytes.fetch_add(chunk);
                if (progress) {
                    progress(scanned_bytes.load(), total_bytes, out.count());
                }
            }
        });

    return merge_parts(parts, type, value_size);
}

// Keeps the previous results for which match(live_bytes, previous_bytes) holds. Neighbouring results
// share one read of up to NEXT_SCAN_WINDOW bytes; the output keeps the input order.
template <typename Match>
ScanResults filter_results(
    const hal::IProcess& process,
    const ScanResults& previous,
    size_t thread_count,
    const ScanProgressCallback& progress,
    Match&& match
) {
    const size_t total = previous.count();
    const size_t value_size = previous.value_size();
    if (total == 0 || value_size == 0) return ScanResults(previous.type(), value_size);

    const size_t slices = (total + NEXT_SCAN_SLICE - 1) / NEXT_SCAN_SLICE;
    std::vector<ScanResults> parts(slices, ScanResults(previous.type(), value_size));
    std::atomic<size_t> processed{0};
    std::atomic<size_t> found{0};

    parallel_for(slices, thread_count,
        [&] { return std::vector<uint8_t>(std::max(NEXT_SCAN_WINDOW, value_size)); },
        [&](std::vector<uint8_t>& buffer, size_t s) {
            const size_t begin = s * NEXT_SCAN_SLICE;
            const size_t end = std::min(total, begin + NEXT_SCAN_SLICE);
            auto& out = parts[s];

            size_t i = begin;
            while (i < end) {
                // Group the following results whose values fit in one read window
                const uintptr_t window_start = previous.address(i);
                size_t j = i + 1;
                while (j < end && previous.address(j) >= window_start &&
                       previous.address(j) - window_start + value_size <= NEXT_SCAN_WINDOW) {
                    ++j;
                }
                const size_t window_size = previous.address(j - 1) - window_start + value_size;

                if (process.read_raw(window_start, buffer.data(), window_size)) {
                    for (size_t k = i; k < j; ++k) {
                        const uint8_t* live = buffer.data() + (previous.address(k) - window_start);
                        if (match(live, previous.current_bytes(k))) {
                            out.add(previous.address(k), live, previous.current_bytes(k));
                        }
                    }
                } else {
                    // The window spans unreadable memory: fall back to one read per result
                    for (size_t k = i; k < j; ++k) {
                        if (process.read_raw(previous.address(k), buffer.data(), value_size) &&
                            match(buffer.data(), previous.current_bytes(k))) {
                            out.add(previous.address(k), buffer.data(), previous.current_bytes(k));
                        }
                    }
                }
                i = j;
            }

            found.fetch_add(out.count());
            processed.fetch_add(end - begin);
            if (progress) {
                progress(processed.load(), total, found.load());
            }
        });

    return merge_parts(parts, previous.type(), value_size);
}

} // anonymous namespace

MemoryScanner::MemoryScanner(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
    , m_thread_count(detail::default_thread_count())
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

        results = scan_regions(*m_process, region_filter, m_thread_count, progress, type, sizeof(T),
            [&](const uint8_t* buffer, size_t size, size_t limit, uintptr_t base, ScanResults& out) {
                scan_chunk_typed<T>(buffer, size, limit, base, condition, target1, target2, step, out);
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

    return scan_regions(*m_process, region_filter, m_thread_count, progress, DataType::AOB, pattern.bytes.size(),
        [&](const uint8_t* buffer, size_t size, size_t limit, uintptr_t base, ScanResults& out) {
            scan_chunk_aob(buffer, size, limit, base, pattern, step, out);
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

    return scan_regions(*m_process, region_filter, m_thread_count, progress, type, pattern.bytes.size(),
        [&](const uint8_t* buffer, size_t size, size_t limit, uintptr_t base, ScanResults& out) {
            scan_chunk_aob(buffer, size, limit, base, pattern, step, out);
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

    size_t value_size = 0;
    const bool is_numeric = dispatch_numeric(type, [&]<typename T>() { value_size = sizeof(T); });
    if (!m_process || !m_process->is_attached() || !is_numeric) return snapshot;

    // Allocate every block up front on this thread, so running out of memory throws here.
    // Slots never cross a block, which is fine while alignment == value size (64 KB is a multiple).
    for (const auto& reg : m_process->query_regions(region_filter)) {
        for (size_t offset = 0; offset < reg.size; offset += SNAPSHOT_BLOCK_SIZE) {
            MemorySnapshot::Block block;
            block.base_address = reg.base_address + offset;
            block.bytes.resize(std::min(SNAPSHOT_BLOCK_SIZE, reg.size - offset));
            block.alive = all_slots_alive(slot_count(block.bytes.size(), value_size, snapshot.alignment));
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
    const DataType type = previous_results.type();
    ScanResults results(type, previous_results.value_size());
    if (!m_process || !m_process->is_attached() || previous_results.empty()) return results;

    const bool uses_val1 = condition_uses_value(condition);
    const bool uses_val2 = (condition == ScanCondition::Between);

    const bool is_numeric = dispatch_numeric(type, [&]<typename T>() {
        const T target1 = uses_val1 ? std::get<T>(val1.value) : T{};
        const T target2 = uses_val2 ? std::get<T>(val2.value) : T{};

        results = filter_results(*m_process, previous_results, m_thread_count, progress,
            [&](const uint8_t* live, const uint8_t* prev) {
                return match_next_bytes<T>(live, prev, condition, target1, target2);
            });
    });

    // String / String16 / AOB results only support Changed / Unchanged against the previous bytes
    if (!is_numeric && (condition == ScanCondition::Changed || condition == ScanCondition::Unchanged)) {
        const bool want_unchanged = (condition == ScanCondition::Unchanged);
        const size_t size = previous_results.value_size();
        results = filter_results(*m_process, previous_results, m_thread_count, progress,
            [&](const uint8_t* live, const uint8_t* prev) {
                return (std::memcmp(live, prev, size) == 0) == want_unchanged;
            });
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

        std::vector<ScanResults> parts(snapshot.blocks.size(), ScanResults(type, sizeof(T)));
        std::atomic<size_t> compared_bytes{0};
        std::atomic<size_t> found{0};
        const size_t total_bytes = snapshot.total_bytes();

        parallel_for(snapshot.blocks.size(), m_thread_count, [] { return std::vector<uint8_t>(); },
            [&](std::vector<uint8_t>& live, size_t i) {
                const auto& block = snapshot.blocks[i];
                live.resize(block.bytes.size());

                if (m_process->read_raw(block.base_address, live.data(), live.size())) {
                    for_each_alive_slot(block.alive, [&](size_t slot) {
                        const size_t offset = slot * step;
                        if (match_next_bytes<T>(live.data() + offset, block.bytes.data() + offset, condition, target1, target2)) {
                            parts[i].add(block.base_address + offset, live.data() + offset, block.bytes.data() + offset);
                        }
                    });
                }

                found.fetch_add(parts[i].count());
                compared_bytes.fetch_add(block.bytes.size());
                if (progress) {
                    progress(compared_bytes.load(), total_bytes, found.load());
                }
            });

        results = merge_parts(parts, type, sizeof(T));
    });

    return results;
}

MemorySnapshot MemoryScanner::filter_snapshot(
    const MemorySnapshot& snapshot,
    ScanCondition condition,
    const ScanValue& val1,
    const ScanValue& val2,
    ScanProgressCallback progress
) {
    MemorySnapshot filtered;
    filtered.type = snapshot.type;
    filtered.alignment = snapshot.alignment;
    if (!m_process || !m_process->is_attached() || snapshot.blocks.empty()) return filtered;

    const bool uses_val1 = condition_uses_value(condition);
    const bool uses_val2 = (condition == ScanCondition::Between);
    const size_t step = std::max<size_t>(1, snapshot.alignment);

    dispatch_numeric(snapshot.type, [&]<typename T>() {
        const T target1 = uses_val1 ? std::get<T>(val1.value) : T{};
        const T target2 = uses_val2 ? std::get<T>(val2.value) : T{};

        std::vector<MemorySnapshot::Block> next_blocks(snapshot.blocks.size());
        std::atomic<size_t> compared_bytes{0};
        std::atomic<size_t> kept_total{0};
        const size_t total_bytes = snapshot.total_bytes();

        parallel_for(snapshot.blocks.size(), m_thread_count, [] { return 0; }, [&](int&, size_t i) {
            const auto& block = snapshot.blocks[i];
            auto& out = next_blocks[i];
            compared_bytes.fetch_add(block.bytes.size());

            out.bytes.resize(block.bytes.size());
            if (m_process->read_raw(block.base_address, out.bytes.data(), out.bytes.size())) {
                out.base_address = block.base_address;
                out.alive.assign(block.alive.size(), 0);

                size_t kept = 0;
                for_each_alive_slot(block.alive, [&](size_t slot) {
                    const size_t offset = slot * step;
                    if (match_next_bytes<T>(out.bytes.data() + offset, block.bytes.data() + offset, condition, target1, target2)) {
                        out.alive[slot / 64] |= uint64_t{1} << (slot % 64);
                        ++kept;
                    }
                });

                kept_total.fetch_add(kept);
                if (kept == 0) out = {};
            } else {
                out = {};
            }

            if (progress) {
                progress(compared_bytes.load(), total_bytes, kept_total.load());
            }
        });

        size_t kept_blocks = 0;
        for (const auto& b : next_blocks) kept_blocks += b.bytes.empty() ? 0 : 1;
        filtered.blocks.reserve(kept_blocks);
        for (auto& b : next_blocks) {
            if (!b.bytes.empty()) filtered.blocks.push_back(std::move(b));
        }
    });

    return filtered;
}

ScanResults MemoryScanner::snapshot_to_results(const MemorySnapshot& snapshot) {
    size_t value_size = 0;
    dispatch_numeric(snapshot.type, [&]<typename T>() { value_size = sizeof(T); });

    ScanResults results(snapshot.type, value_size);
    if (value_size == 0) return results;

    const size_t step = std::max<size_t>(1, snapshot.alignment);
    results.reserve(snapshot.candidate_count());
    for (const auto& block : snapshot.blocks) {
        for_each_alive_slot(block.alive, [&](size_t slot) {
            const uint8_t* value = block.bytes.data() + slot * step;
            results.add(block.base_address + slot * step, value, value);
        });
    }
    return results;
}

} // namespace nce::scanner

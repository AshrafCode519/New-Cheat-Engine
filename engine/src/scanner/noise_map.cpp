#include "../../include/scanner/noise_map.hpp"
#include "parallel.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <thread>
#include <utility>

namespace nce::scanner {

namespace {

constexpr size_t BLOCK_SIZE = 64 * 1024;
constexpr size_t SLOT_SIZE = 4;
constexpr uint8_t MAX_COUNT = 15; // the change counter is a nibble

// 4-bit fingerprint of a slot: catches every single-byte change, and most others
uint8_t fingerprint(const uint8_t* p) {
    const uint8_t h = p[0] ^ p[1] ^ p[2] ^ p[3];
    return static_cast<uint8_t>((h ^ (h >> 4)) & 0x0F);
}

void set_bit(std::vector<uint64_t>& bits, size_t i) { bits[i / 64] |= uint64_t{1} << (i % 64); }
bool test_bit(const std::vector<uint64_t>& bits, size_t i) { return (bits[i / 64] >> (i % 64)) & 1; }

} // anonymous namespace

void NoiseMap::clear() {
    m_blocks.clear();
    m_samples = 0;
    m_noisy_slots = 0;
    m_skipped_bytes = 0;
}

void NoiseMap::begin(const hal::IProcess& process, const Options& options) {
    clear();
    m_options = options;
    for (const auto& region : process.query_regions(options.region_filter)) {
        for (size_t offset = 0; offset < region.size; offset += BLOCK_SIZE) {
            Block block;
            block.base = region.base_address + offset;
            block.size = std::min(BLOCK_SIZE, region.size - offset);
            block.state.resize(block.size / SLOT_SIZE);
            m_blocks.push_back(std::move(block));
        }
    }
    sample(process);
}

void NoiseMap::sample(const hal::IProcess& process) {
    const bool first = (m_samples == 0);

    detail::parallel_for(m_blocks.size(), detail::default_thread_count(),
        [] { return std::vector<uint8_t>(BLOCK_SIZE); },
        [&](std::vector<uint8_t>& buffer, size_t i) {
            Block& block = m_blocks[i];
            if (block.state.empty()) return; // dropped earlier
            if (!process.read_raw(block.base, buffer.data(), block.size)) {
                block.state = {}; // freed or protected since: forget it
                return;
            }
            for (size_t s = 0; s < block.state.size(); ++s) {
                const uint8_t hash = fingerprint(buffer.data() + s * SLOT_SIZE);
                uint8_t count = block.state[s] >> 4;
                if (!first && (block.state[s] & 0x0F) != hash && count < MAX_COUNT) ++count;
                block.state[s] = static_cast<uint8_t>((count << 4) | hash);
            }
        });

    ++m_samples;
}

void NoiseMap::finish() {
    m_noisy_slots = 0;
    m_skipped_bytes = 0;
    std::vector<Block> kept;

    // Two comparisons at least, and a slot must change at least twice: one change is never noise
    const size_t comparisons = m_samples > 0 ? m_samples - 1 : 0;
    if (comparisons >= 2) {
        const auto wanted = static_cast<size_t>(std::ceil(m_options.noisy_share * static_cast<double>(comparisons)));
        const uint8_t threshold = static_cast<uint8_t>(std::clamp<size_t>(wanted, 2, MAX_COUNT));

        for (auto& block : m_blocks) {
            const size_t slots = block.state.size();
            if (slots == 0) continue;

            std::vector<uint64_t> noisy((slots + 63) / 64, 0);
            size_t noisy_count = 0;
            for (size_t s = 0; s < slots; ++s) {
                if ((block.state[s] >> 4) >= threshold) {
                    set_bit(noisy, s);
                    ++noisy_count;
                }
            }
            block.state = {};
            if (noisy_count == 0) continue;

            if (static_cast<double>(noisy_count) >= m_options.skip_block_share * static_cast<double>(slots)) {
                block.skipped = true;
                m_skipped_bytes += block.size;
                m_noisy_slots += slots;
            } else {
                block.noisy = std::move(noisy);
                m_noisy_slots += noisy_count;
            }
            kept.push_back(std::move(block));
        }
    }

    m_blocks = std::move(kept);
}

void NoiseMap::learn(const hal::IProcess& process, const Options& options, const std::atomic<bool>* stop,
                     const std::function<void(size_t, size_t)>& progress) {
    begin(process, options);
    if (progress) progress(m_samples, options.samples);

    while (m_samples < options.samples) {
        // Wait in small steps so `stop` is noticed quickly
        const auto wake = std::chrono::steady_clock::now() + options.interval;
        while (std::chrono::steady_clock::now() < wake) {
            if (stop && *stop) {
                finish();
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        sample(process);
        if (progress) progress(m_samples, options.samples);
    }
    finish();
}

const NoiseMap::Block* NoiseMap::find(uintptr_t address) const {
    auto it = std::upper_bound(m_blocks.begin(), m_blocks.end(), address,
        [](uintptr_t a, const Block& b) { return a < b.base; });
    if (it == m_blocks.begin()) return nullptr;
    --it;
    return address < it->base + it->size ? &*it : nullptr;
}

bool NoiseMap::is_noisy(uintptr_t address, size_t size) const {
    if (m_blocks.empty() || size == 0) return false;
    for (uintptr_t slot = address & ~uintptr_t{SLOT_SIZE - 1}; slot < address + size; slot += SLOT_SIZE) {
        const Block* block = find(slot);
        if (!block) continue;
        if (block->skipped || test_bit(block->noisy, (slot - block->base) / SLOT_SIZE)) return true;
    }
    return false;
}

std::vector<uint64_t> NoiseMap::mask(uintptr_t base, size_t size, size_t slot_size) const {
    const size_t slots = size >= slot_size ? (size - slot_size) / slot_size + 1 : 0;
    std::vector<uint64_t> bits((slots + 63) / 64, 0);
    if (slots == 0 || m_blocks.empty()) return bits;

    const uintptr_t end = base + size;
    // Marks the caller's slots that overlap the noisy bytes [lo, hi)
    auto mark = [&](uintptr_t lo, uintptr_t hi) {
        if (hi <= base || lo >= end) return;
        const size_t rel_lo = lo > base ? lo - base : 0;
        const size_t rel_hi = std::min(hi, end) - base;
        const size_t last = std::min(slots - 1, (rel_hi - 1) / slot_size);
        for (size_t i = rel_lo / slot_size; i <= last; ++i) set_bit(bits, i);
    };

    auto it = std::upper_bound(m_blocks.begin(), m_blocks.end(), base,
        [](uintptr_t a, const Block& b) { return a < b.base; });
    if (it != m_blocks.begin()) --it;
    for (; it != m_blocks.end() && it->base < end; ++it) {
        if (it->base + it->size <= base) continue;
        if (it->skipped) {
            mark(it->base, it->base + it->size);
            continue;
        }
        for (size_t w = 0; w < it->noisy.size(); ++w) {
            uint64_t word = it->noisy[w];
            while (word != 0) {
                const uintptr_t slot = it->base + (w * 64 + static_cast<size_t>(std::countr_zero(word))) * SLOT_SIZE;
                mark(slot, slot + SLOT_SIZE);
                word &= word - 1;
            }
        }
    }
    return bits;
}

std::vector<hal::MemoryRegion> NoiseMap::filter_regions(const std::vector<hal::MemoryRegion>& regions) const {
    std::vector<std::pair<uintptr_t, uintptr_t>> skipped;
    for (const auto& b : m_blocks) {
        if (b.skipped) skipped.emplace_back(b.base, b.base + b.size);
    }
    if (skipped.empty()) return regions;

    std::vector<hal::MemoryRegion> out;
    out.reserve(regions.size());
    for (const auto& region : regions) {
        uintptr_t cursor = region.base_address;
        const uintptr_t end = region.end_address();
        auto it = std::lower_bound(skipped.begin(), skipped.end(), std::make_pair(cursor, uintptr_t{0}),
            [](const auto& a, const auto& b) { return a.second <= b.first; }); // first interval ending after cursor

        for (; it != skipped.end() && it->first < end; ++it) {
            if (it->first > cursor) {
                hal::MemoryRegion piece = region;
                piece.base_address = cursor;
                piece.size = it->first - cursor;
                out.push_back(piece);
            }
            cursor = std::max(cursor, it->second);
        }
        if (cursor < end) {
            hal::MemoryRegion piece = region;
            piece.base_address = cursor;
            piece.size = end - cursor;
            out.push_back(piece);
        }
    }
    return out;
}

ScanResults NoiseMap::filter(const ScanResults& results) const {
    if (m_blocks.empty()) return results;
    ScanResults out(results.type(), results.value_size());
    out.reserve(results.count());
    for (size_t i = 0; i < results.count(); ++i) {
        if (!is_noisy(results.address(i), results.value_size())) {
            out.add(results.address(i), results.current_bytes(i), results.previous_bytes(i));
        }
    }
    return out;
}

} // namespace nce::scanner

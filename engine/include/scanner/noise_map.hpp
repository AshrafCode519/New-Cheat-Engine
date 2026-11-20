#pragma once

#include "../hal/process.hpp"
#include "scan_results.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <vector>

namespace nce::scanner {

struct NoiseOptions {
    size_t samples{16};                          // ~4 s at the default interval
    std::chrono::milliseconds interval{250};
    double noisy_share{0.5};                     // changed in at least this share of the comparisons
    double skip_block_share{0.5};                // skip a whole 64 KB block when this share of it is noise
    uint32_t region_filter{hal::FilterFlags::DefaultScanFilter};
};

// Addresses that change all the time on their own (frame counters, timers, animation, audio and render
// buffers), learned by sampling memory while the user leaves the target alone. Scans then ignore them.
//
// Only frequent change counts: a slot is noise if it changed in at least `noisy_share` of the samples.
// A value the user is looking for (health, ammo) changes when the user acts, so it stays far below that.
// Memory is tracked in 4-byte slots; a block in which most slots are noise is skipped whole.
class NoiseMap {
public:
    using Options = NoiseOptions;

    // Blocking: options.samples reads options.interval apart. `stop` ends it early (what was seen so far
    // is kept if it covers at least two comparisons). progress(samples_taken, samples).
    void learn(const hal::IProcess& process, const Options& options = {}, const std::atomic<bool>* stop = nullptr,
               const std::function<void(size_t, size_t)>& progress = nullptr);

    // learn() in steps, for callers that drive the timing themselves: begin() takes the first sample,
    // sample() each further one, finish() turns the counts into the ignore map
    void begin(const hal::IProcess& process, const Options& options = {});
    void sample(const hal::IProcess& process);
    void finish();

    void clear();
    [[nodiscard]] bool empty() const noexcept { return m_blocks.empty(); }
    [[nodiscard]] size_t noisy_slots() const noexcept { return m_noisy_slots; } // 4-byte slots ignored
    [[nodiscard]] size_t skipped_bytes() const noexcept { return m_skipped_bytes; } // inside whole skipped blocks
    [[nodiscard]] size_t samples_taken() const noexcept { return m_samples; }

    // True if any byte of [address, address + size) lies in a noisy slot
    [[nodiscard]] bool is_noisy(uintptr_t address, size_t size) const;

    // Bit i set if slot i of a caller's block ([base + i*slot_size, + slot_size), as many slots as fit in
    // `size`) overlaps noise. Callers clear their candidate bits with it: alive[w] &= ~mask[w].
    [[nodiscard]] std::vector<uint64_t> mask(uintptr_t base, size_t size, size_t slot_size) const;

    // The regions without the blocks that are skipped whole (regions are split around them)
    [[nodiscard]] std::vector<hal::MemoryRegion> filter_regions(const std::vector<hal::MemoryRegion>& regions) const;

    // The results without noisy addresses (order kept)
    [[nodiscard]] ScanResults filter(const ScanResults& results) const;

private:
    struct Block {
        uintptr_t base{0};
        size_t size{0};
        bool skipped{false};           // the whole block is noise
        std::vector<uint64_t> noisy;   // one bit per 4-byte slot (empty when skipped)
        std::vector<uint8_t> state;    // while learning: per slot, low nibble = hash of the last value,
                                       // high nibble = number of changes seen (saturates at 15)
    };

    [[nodiscard]] const Block* find(uintptr_t address) const;

    Options m_options;
    std::vector<Block> m_blocks; // address order
    size_t m_samples{0};
    size_t m_noisy_slots{0};
    size_t m_skipped_bytes{0};
};

} // namespace nce::scanner

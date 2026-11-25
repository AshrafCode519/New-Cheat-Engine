#pragma once

#include "scan_results.hpp"
#include "../utils/hex_utils.hpp"
#include <cstddef>
#include <cstdint>

namespace nce::scanner::simd {

// Returns true if the host CPU supports AVX2 (and BMI2) instructions at runtime
bool cpu_supports_avx2() noexcept;

// AVX2-accelerated exact value scans for contiguous memory chunks.
// Returns true if processed by AVX2, or false if fallback to scalar is required.

bool scan_chunk_exact_i16_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, int16_t target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_u16_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, uint16_t target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_i32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, int32_t target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_u32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, uint32_t target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_float_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, float target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_i64_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, int64_t target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_u64_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, uint64_t target, size_t alignment, ScanResults& out
);

bool scan_chunk_exact_double_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, double target, size_t alignment, ScanResults& out
);

// AVX2-accelerated AOB pattern scanner (processes 32 candidate offsets per iteration)
bool scan_chunk_aob_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, const AOBPattern& pattern, size_t alignment, ScanResults& out
);

// AVX2-accelerated condition scans (GreaterThan, LessThan, Between)
bool scan_chunk_cond_i32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, int32_t val1, int32_t val2,
    size_t alignment, ScanResults& out
);

bool scan_chunk_cond_u32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, uint32_t val1, uint32_t val2,
    size_t alignment, ScanResults& out
);

bool scan_chunk_cond_float_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, float val1, float val2,
    size_t alignment, ScanResults& out
);

bool scan_chunk_cond_double_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, double val1, double val2,
    size_t alignment, ScanResults& out
);

} // namespace nce::scanner::simd

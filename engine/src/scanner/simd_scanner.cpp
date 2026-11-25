#include "../../include/scanner/simd_scanner.hpp"
#include <algorithm>
#include <bit>
#include <cstring>
#include <immintrin.h>

#if defined(_MSC_VER)
#include <intrin.h>
#define NCE_AVX2_TARGET
#elif defined(__GNUC__) || defined(__clang__)
#define NCE_AVX2_TARGET __attribute__((target("avx2,bmi2")))
#else
#define NCE_AVX2_TARGET
#endif

namespace nce::scanner::simd {

bool cpu_supports_avx2() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("avx2");
#elif defined(_MSC_VER)
    int cpu_info[4];
    __cpuidex(cpu_info, 7, 0);
    return (cpu_info[1] & (1 << 5)) != 0;
#else
    return false;
#endif
#else
    return false;
#endif
}

NCE_AVX2_TARGET
bool scan_chunk_exact_i32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, int32_t target, size_t alignment, ScanResults& out
) {
    if (alignment < 4 || alignment % 4 != 0) return false;

    const __m256i target_vec = _mm256_set1_epi32(target);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset));
        const __m256i cmp = _mm256_cmpeq_epi32(chunk, target_vec);
        int mask = _mm256_movemask_ps(_mm256_castsi256_ps(cmp));

        if (mask != 0) {
            if (alignment == 8) mask &= 0x55;
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 4;
                if (alignment <= 4 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(int32_t) <= buffer_size; offset += alignment) {
        int32_t val;
        std::memcpy(&val, buffer + offset, sizeof(int32_t));
        if (val == target) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }

    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_exact_u32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, uint32_t target, size_t alignment, ScanResults& out
) {
    return scan_chunk_exact_i32_avx2(
        buffer, buffer_size, start_limit, chunk_base,
        static_cast<int32_t>(target), alignment, out
    );
}

NCE_AVX2_TARGET
bool scan_chunk_exact_float_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, float target, size_t alignment, ScanResults& out
) {
    if (alignment < 4 || alignment % 4 != 0) return false;

    constexpr float epsilon = 0.0001f;
    const __m256 target_vec = _mm256_set1_ps(target);
    const __m256 eps_vec = _mm256_set1_ps(epsilon);
    const __m256 sign_mask = _mm256_set1_ps(-0.0f);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256 chunk = _mm256_loadu_ps(reinterpret_cast<const float*>(buffer + offset));
        const __m256 diff = _mm256_sub_ps(chunk, target_vec);
        const __m256 abs_diff = _mm256_andnot_ps(sign_mask, diff);
        const __m256 cmp = _mm256_cmp_ps(abs_diff, eps_vec, _CMP_LE_OQ);
        int mask = _mm256_movemask_ps(cmp);

        if (mask != 0) {
            if (alignment == 8) mask &= 0x55;
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 4;
                if (alignment <= 4 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(float) <= buffer_size; offset += alignment) {
        float val;
        std::memcpy(&val, buffer + offset, sizeof(float));
        if (std::abs(val - target) <= epsilon) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }

    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_exact_i64_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, int64_t target, size_t alignment, ScanResults& out
) {
    if (alignment < 8 || alignment % 8 != 0) return false;

    const __m256i target_vec = _mm256_set1_epi64x(target);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset));
        const __m256i cmp = _mm256_cmpeq_epi64(chunk, target_vec);
        int mask = _mm256_movemask_pd(_mm256_castsi256_pd(cmp)); // 4 bits

        if (mask != 0) {
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 8;
                if (alignment <= 8 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(int64_t) <= buffer_size; offset += alignment) {
        int64_t val;
        std::memcpy(&val, buffer + offset, sizeof(int64_t));
        if (val == target) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }

    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_exact_u64_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, uint64_t target, size_t alignment, ScanResults& out
) {
    return scan_chunk_exact_i64_avx2(
        buffer, buffer_size, start_limit, chunk_base,
        static_cast<int64_t>(target), alignment, out
    );
}

NCE_AVX2_TARGET
bool scan_chunk_exact_double_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, double target, size_t alignment, ScanResults& out
) {
    if (alignment < 8 || alignment % 8 != 0) return false;

    constexpr double epsilon = 0.000001;
    const __m256d target_vec = _mm256_set1_pd(target);
    const __m256d eps_vec = _mm256_set1_pd(epsilon);
    const __m256d sign_mask = _mm256_set1_pd(-0.0);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256d chunk = _mm256_loadu_pd(reinterpret_cast<const double*>(buffer + offset));
        const __m256d diff = _mm256_sub_pd(chunk, target_vec);
        const __m256d abs_diff = _mm256_andnot_pd(sign_mask, diff);
        const __m256d cmp = _mm256_cmp_pd(abs_diff, eps_vec, _CMP_LE_OQ);
        int mask = _mm256_movemask_pd(cmp);

        if (mask != 0) {
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 8;
                if (alignment <= 8 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(double) <= buffer_size; offset += alignment) {
        double val;
        std::memcpy(&val, buffer + offset, sizeof(double));
        if (std::abs(val - target) <= epsilon) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }

    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_exact_i16_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, int16_t target, size_t alignment, ScanResults& out
) {
    if (alignment < 2 || alignment % 2 != 0) return false;

    const __m256i target_vec = _mm256_set1_epi16(target);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset));
        const __m256i cmp = _mm256_cmpeq_epi16(chunk, target_vec);
        const int byte_mask = _mm256_movemask_epi8(cmp);

        if (byte_mask != 0) {
            uint32_t even_mask = static_cast<uint32_t>(byte_mask) & 0x55555555u;
            while (even_mask != 0) {
                const int bit = std::countr_zero(even_mask);
                const size_t match_offset = offset + static_cast<size_t>(bit);
                if (alignment <= 2 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                even_mask &= even_mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(int16_t) <= buffer_size; offset += alignment) {
        int16_t val;
        std::memcpy(&val, buffer + offset, sizeof(int16_t));
        if (val == target) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }

    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_exact_u16_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, uint16_t target, size_t alignment, ScanResults& out
) {
    return scan_chunk_exact_i16_avx2(
        buffer, buffer_size, start_limit, chunk_base,
        static_cast<int16_t>(target), alignment, out
    );
}

NCE_AVX2_TARGET
bool scan_chunk_aob_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, const AOBPattern& pattern, size_t alignment, ScanResults& out
) {
    const size_t pattern_size = pattern.bytes.size();
    if (pattern_size == 0) return false;

    // Find the first and last unmasked byte indices
    size_t first = static_cast<size_t>(-1);
    size_t last = static_cast<size_t>(-1);

    for (size_t i = 0; i < pattern_size; ++i) {
        if (pattern.mask[i]) {
            if (first == static_cast<size_t>(-1)) first = i;
            last = i;
        }
    }

    if (first == static_cast<size_t>(-1)) return false; // all wildcards: fall back to scalar

    const uint8_t b_first = pattern.bytes[first];
    const uint8_t b_last = pattern.bytes[last];
    const __m256i v_first = _mm256_set1_epi8(static_cast<char>(b_first));
    const __m256i v_last = _mm256_set1_epi8(static_cast<char>(b_last));

    size_t offset = 0;

    for (; offset + 32 + pattern_size <= buffer_size && offset + 32 <= start_limit; offset += 32) {
        const __m256i block_first = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset + first));
        const __m256i cmp_first = _mm256_cmpeq_epi8(block_first, v_first);
        int mask = _mm256_movemask_epi8(cmp_first);
        if (mask == 0) continue;

        if (first != last) {
            const __m256i block_last = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset + last));
            const __m256i cmp_last = _mm256_cmpeq_epi8(block_last, v_last);
            const int mask_last = _mm256_movemask_epi8(cmp_last);
            mask &= mask_last;
            if (mask == 0) continue;
        }

        if (alignment == 4) {
            mask &= 0x11111111;
        } else if (alignment == 2) {
            mask &= 0x55555555;
        }

        while (mask != 0) {
            const int bit = std::countr_zero(static_cast<unsigned int>(mask));
            const size_t cand = offset + static_cast<size_t>(bit);
            if (cand < start_limit && cand + pattern_size <= buffer_size &&
                (alignment <= 1 || cand % alignment == 0)) {
                bool ok = true;
                for (size_t j = 0; j < pattern_size; ++j) {
                    if (j == first || j == last) continue;
                    if (pattern.mask[j] && buffer[cand + j] != pattern.bytes[j]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    out.add(chunk_base + cand, buffer + cand, buffer + cand);
                }
            }
            mask &= mask - 1;
        }
    }

    // Scalar tail
    for (; offset < start_limit && offset + pattern_size <= buffer_size; offset += alignment) {
        bool ok = true;
        for (size_t j = 0; j < pattern_size; ++j) {
            if (pattern.mask[j] && buffer[offset + j] != pattern.bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }

    return true;
}

namespace {

inline bool scalar_match_cond(int32_t v, ScanCondition cond, int32_t v1, int32_t v2) {
    if (cond == ScanCondition::GreaterThan) return v > v1;
    if (cond == ScanCondition::LessThan) return v < v1;
    if (cond == ScanCondition::Between) return v >= v1 && v <= v2;
    return false;
}

inline bool scalar_match_cond(uint32_t v, ScanCondition cond, uint32_t v1, uint32_t v2) {
    if (cond == ScanCondition::GreaterThan) return v > v1;
    if (cond == ScanCondition::LessThan) return v < v1;
    if (cond == ScanCondition::Between) return v >= v1 && v <= v2;
    return false;
}

inline bool scalar_match_cond(float v, ScanCondition cond, float v1, float v2) {
    if (cond == ScanCondition::GreaterThan) return v > v1;
    if (cond == ScanCondition::LessThan) return v < v1;
    if (cond == ScanCondition::Between) return v >= v1 && v <= v2;
    return false;
}

inline bool scalar_match_cond(double v, ScanCondition cond, double v1, double v2) {
    if (cond == ScanCondition::GreaterThan) return v > v1;
    if (cond == ScanCondition::LessThan) return v < v1;
    if (cond == ScanCondition::Between) return v >= v1 && v <= v2;
    return false;
}

inline bool is_range_cond(ScanCondition cond) noexcept {
    return cond == ScanCondition::GreaterThan || cond == ScanCondition::LessThan || cond == ScanCondition::Between;
}

} // namespace

NCE_AVX2_TARGET
bool scan_chunk_cond_i32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, int32_t val1, int32_t val2,
    size_t alignment, ScanResults& out
) {
    if (!is_range_cond(cond) || alignment < 4 || alignment % 4 != 0) return false;

    const __m256i vec1 = _mm256_set1_epi32(val1);
    const __m256i vec2 = _mm256_set1_epi32(val2);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset));
        int mask = 0;
        if (cond == ScanCondition::GreaterThan) {
            mask = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpgt_epi32(chunk, vec1)));
        } else if (cond == ScanCondition::LessThan) {
            mask = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpgt_epi32(vec1, chunk)));
        } else { // Between: !(chunk < val1) && !(chunk > val2)
            const __m256i lt1 = _mm256_cmpgt_epi32(vec1, chunk);
            const __m256i gt2 = _mm256_cmpgt_epi32(chunk, vec2);
            const int bad = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_or_si256(lt1, gt2)));
            mask = (~bad) & 0xFF;
        }
        if (mask != 0) {
            if (alignment == 8) mask &= 0x55;
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 4;
                if (alignment <= 4 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(int32_t) <= buffer_size; offset += alignment) {
        int32_t val;
        std::memcpy(&val, buffer + offset, sizeof(int32_t));
        if (scalar_match_cond(val, cond, val1, val2)) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }
    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_cond_u32_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, uint32_t val1, uint32_t val2,
    size_t alignment, ScanResults& out
) {
    if (!is_range_cond(cond) || alignment < 4 || alignment % 4 != 0) return false;

    const __m256i sign_flip = _mm256_set1_epi32(static_cast<int32_t>(0x80000000u));
    const __m256i vec1 = _mm256_set1_epi32(static_cast<int32_t>(val1 ^ 0x80000000u));
    const __m256i vec2 = _mm256_set1_epi32(static_cast<int32_t>(val2 ^ 0x80000000u));
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256i chunk = _mm256_xor_si256(
            _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + offset)), sign_flip);
        int mask = 0;
        if (cond == ScanCondition::GreaterThan) {
            mask = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpgt_epi32(chunk, vec1)));
        } else if (cond == ScanCondition::LessThan) {
            mask = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpgt_epi32(vec1, chunk)));
        } else {
            const __m256i lt1 = _mm256_cmpgt_epi32(vec1, chunk);
            const __m256i gt2 = _mm256_cmpgt_epi32(chunk, vec2);
            const int bad = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_or_si256(lt1, gt2)));
            mask = (~bad) & 0xFF;
        }
        if (mask != 0) {
            if (alignment == 8) mask &= 0x55;
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 4;
                if (alignment <= 4 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(uint32_t) <= buffer_size; offset += alignment) {
        uint32_t val;
        std::memcpy(&val, buffer + offset, sizeof(uint32_t));
        if (scalar_match_cond(val, cond, val1, val2)) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }
    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_cond_float_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, float val1, float val2,
    size_t alignment, ScanResults& out
) {
    if (!is_range_cond(cond) || alignment < 4 || alignment % 4 != 0) return false;

    const __m256 vec1 = _mm256_set1_ps(val1);
    const __m256 vec2 = _mm256_set1_ps(val2);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256 chunk = _mm256_loadu_ps(reinterpret_cast<const float*>(buffer + offset));
        __m256 cmp;
        if (cond == ScanCondition::GreaterThan) {
            cmp = _mm256_cmp_ps(chunk, vec1, _CMP_GT_OQ);
        } else if (cond == ScanCondition::LessThan) {
            cmp = _mm256_cmp_ps(chunk, vec1, _CMP_LT_OQ);
        } else {
            cmp = _mm256_and_ps(_mm256_cmp_ps(chunk, vec1, _CMP_GE_OQ), _mm256_cmp_ps(chunk, vec2, _CMP_LE_OQ));
        }
        int mask = _mm256_movemask_ps(cmp);
        if (mask != 0) {
            if (alignment == 8) mask &= 0x55;
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 4;
                if (alignment <= 4 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(float) <= buffer_size; offset += alignment) {
        float val;
        std::memcpy(&val, buffer + offset, sizeof(float));
        if (scalar_match_cond(val, cond, val1, val2)) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }
    return true;
}

NCE_AVX2_TARGET
bool scan_chunk_cond_double_avx2(
    const uint8_t* buffer, size_t buffer_size, size_t start_limit,
    uintptr_t chunk_base, ScanCondition cond, double val1, double val2,
    size_t alignment, ScanResults& out
) {
    if (!is_range_cond(cond) || alignment < 8 || alignment % 8 != 0) return false;

    const __m256d vec1 = _mm256_set1_pd(val1);
    const __m256d vec2 = _mm256_set1_pd(val2);
    size_t offset = 0;

    for (; offset + 32 <= start_limit && offset + 32 <= buffer_size; offset += 32) {
        const __m256d chunk = _mm256_loadu_pd(reinterpret_cast<const double*>(buffer + offset));
        __m256d cmp;
        if (cond == ScanCondition::GreaterThan) {
            cmp = _mm256_cmp_pd(chunk, vec1, _CMP_GT_OQ);
        } else if (cond == ScanCondition::LessThan) {
            cmp = _mm256_cmp_pd(chunk, vec1, _CMP_LT_OQ);
        } else {
            cmp = _mm256_and_pd(_mm256_cmp_pd(chunk, vec1, _CMP_GE_OQ), _mm256_cmp_pd(chunk, vec2, _CMP_LE_OQ));
        }
        int mask = _mm256_movemask_pd(cmp);
        if (mask != 0) {
            while (mask != 0) {
                const int bit = std::countr_zero(static_cast<unsigned int>(mask));
                const size_t match_offset = offset + static_cast<size_t>(bit) * 8;
                if (alignment <= 8 || match_offset % alignment == 0) {
                    out.add(chunk_base + match_offset, buffer + match_offset, buffer + match_offset);
                }
                mask &= mask - 1;
            }
        }
    }

    for (; offset < start_limit && offset + sizeof(double) <= buffer_size; offset += alignment) {
        double val;
        std::memcpy(&val, buffer + offset, sizeof(double));
        if (scalar_match_cond(val, cond, val1, val2)) {
            out.add(chunk_base + offset, buffer + offset, buffer + offset);
        }
    }
    return true;
}

} // namespace nce::scanner::simd

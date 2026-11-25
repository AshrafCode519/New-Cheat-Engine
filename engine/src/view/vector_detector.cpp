#include "../../include/view/vector_detector.hpp"
#include <algorithm>
#include <cstring>

namespace nce::view {

namespace {

size_t vec_byte_size(VectorFormat fmt) {
    return (fmt == VectorFormat::Double3) ? sizeof(Vector3d) : sizeof(Vector3);
}

bool read_vec_from_buf(const uint8_t* ptr, VectorFormat fmt, Vector3d& out) {
    if (fmt == VectorFormat::Double3) {
        Vector3d vd;
        std::memcpy(&vd, ptr, sizeof(Vector3d));
        if (!vd.is_valid()) return false;
        out = vd;
        return true;
    }
    Vector3 vf;
    std::memcpy(&vf, ptr, sizeof(Vector3));
    if (!vf.is_valid()) return false;
    out = {vf.x, vf.y, vf.z};
    return true;
}

bool read_vec_unfiltered(const uint8_t* ptr, VectorFormat fmt, Vector3d& out) {
    if (fmt == VectorFormat::Double3) {
        Vector3d vd;
        std::memcpy(&vd, ptr, sizeof(Vector3d));
        if (!std::isfinite(vd.x) || !std::isfinite(vd.y) || !std::isfinite(vd.z)) return false;
        out = vd;
        return true;
    }
    Vector3 vf;
    std::memcpy(&vf, ptr, sizeof(Vector3));
    if (!std::isfinite(vf.x) || !std::isfinite(vf.y) || !std::isfinite(vf.z)) return false;
    out = {vf.x, vf.y, vf.z};
    return true;
}

} // namespace

size_t VectorDetector::take_snapshot(
    const hal::IProcess& process,
    uint32_t region_filter,
    VectorFormat format)
{
    m_snapshot.clear();
    m_format = format;
    if (!process.is_attached()) return 0;

    const auto regions = process.query_regions(region_filter);
    constexpr size_t CHUNK_SIZE = 512 * 1024;
    const size_t vsz  = vec_byte_size(format);
    const size_t step = (format == VectorFormat::Double3) ? 8 : 4;
    // Extra overlap bytes prevent missing vectors that cross the 512 KB chunk boundary.
    std::vector<uint8_t> buffer(CHUNK_SIZE + vsz);

    for (const auto& reg : regions) {
        if (!reg.is_writable || reg.size < vsz) continue;

        for (size_t offset = 0; offset + vsz <= reg.size; offset += CHUNK_SIZE) {
            const size_t remaining = reg.size - offset;
            const size_t to_read = std::min(CHUNK_SIZE + vsz - step, remaining);
            if (!process.read_raw(reg.base_address + offset, buffer.data(), to_read)) {
                continue;
            }

            // Only emit vectors whose START address lies within [0, CHUNK_SIZE) of this chunk
            const size_t start_limit = std::min(CHUNK_SIZE, to_read - vsz + 1);
            for (size_t i = 0; i < start_limit; i += step) {
                Vector3d v;
                if (read_vec_from_buf(buffer.data() + i, format, v)) {
                    m_snapshot.push_back({reg.base_address + offset + i, v});
                }
            }
        }
    }

    return m_snapshot.size();
}

std::vector<VectorCandidate> VectorDetector::batch_read_and_eval(
    const hal::IProcess& process,
    const std::vector<SnapshotEntry>& entries,
    std::vector<Vector3d>* out_live_values) const
{
    std::vector<VectorCandidate> out;
    if (!process.is_attached() || entries.empty()) return out;

    const size_t vsz = vec_byte_size(m_format);
    constexpr size_t kMaxGapBytes   = 64 * 1024;   // Merge reads separated by <= 64 KB
    constexpr size_t kMaxBatchBytes = 1024 * 1024; // Cap single read at 1 MB

    if (out_live_values) {
        out_live_values->assign(entries.size(), Vector3d{});
    }

    std::vector<uint8_t> batch_buf;
    size_t idx = 0;
    while (idx < entries.size()) {
        const uintptr_t batch_start = entries[idx].address;
        uintptr_t batch_end = batch_start + vsz;
        size_t end_idx = idx + 1;

        while (end_idx < entries.size()) {
            const uintptr_t next_addr = entries[end_idx].address;
            if (next_addr < batch_start) break; // guard unsorted safety
            const uintptr_t next_end = next_addr + vsz;
            if (next_addr > batch_end + kMaxGapBytes) break;
            if (next_end - batch_start > kMaxBatchBytes) break;
            batch_end = std::max(batch_end, next_end);
            ++end_idx;
        }

        const size_t span = static_cast<size_t>(batch_end - batch_start);
        batch_buf.resize(span);
        bool batch_ok = process.read_raw(batch_start, batch_buf.data(), span);

        for (size_t j = idx; j < end_idx; ++j) {
            Vector3d cur;
            bool got = false;
            if (batch_ok) {
                const size_t off = static_cast<size_t>(entries[j].address - batch_start);
                got = read_vec_unfiltered(batch_buf.data() + off, m_format, cur);
            } else {
                // Fallback per-entry only if batch crossed an unmapped hole inside gap
                uint8_t single[sizeof(Vector3d)]{};
                if (process.read_raw(entries[j].address, single, vsz)) {
                    got = read_vec_unfiltered(single, m_format, cur);
                }
            }

            if (!got) continue;
            if (out_live_values) (*out_live_values)[j] = cur;

            if (!cur.is_valid()) continue;
            const double dist = entries[j].value.distance_to(cur);
            VectorCandidate cand;
            cand.address      = entries[j].address;
            cand.format       = m_format;
            cand.initial_d    = entries[j].value;
            cand.current_d    = cur;
            cand.delta_dist_d = dist;
            cand.initial      = entries[j].value.to_f32();
            cand.current      = cur.to_f32();
            cand.delta_dist   = static_cast<float>(dist);
            out.push_back(std::move(cand));
        }

        idx = end_idx;
    }

    return out;
}

std::vector<VectorCandidate> VectorDetector::detect_motion(
    const hal::IProcess& process,
    float min_dist,
    float max_dist)
{
    auto all = batch_read_and_eval(process, m_snapshot);
    std::vector<VectorCandidate> results;
    results.reserve(all.size());
    for (auto& c : all) {
        if (c.delta_dist_d >= static_cast<double>(min_dist) &&
            c.delta_dist_d <= static_cast<double>(max_dist)) {
            results.push_back(std::move(c));
        }
    }
    std::sort(results.begin(), results.end(), [](const VectorCandidate& a, const VectorCandidate& b) {
        return a.delta_dist_d < b.delta_dist_d;
    });
    return results;
}

size_t VectorDetector::filter_stationary(const hal::IProcess& process, double epsilon) {
    if (!process.is_attached() || m_snapshot.empty()) return m_snapshot.size();
    std::vector<Vector3d> live;
    auto all = batch_read_and_eval(process, m_snapshot, &live);

    // Rebuild kept entries whose live coordinate is valid and stayed within epsilon
    std::vector<SnapshotEntry> kept;
    kept.reserve(all.size());
    for (const auto& c : all) {
        if (c.delta_dist_d <= epsilon) {
            kept.push_back({c.address, c.current_d});
        }
    }
    m_snapshot = std::move(kept);
    return m_snapshot.size();
}

std::vector<VectorCandidate> VectorDetector::filter_moved(
    const hal::IProcess& process,
    double min_dist,
    double max_dist)
{
    std::vector<VectorCandidate> results;
    if (!process.is_attached() || m_snapshot.empty()) return results;

    auto all = batch_read_and_eval(process, m_snapshot);
    std::vector<SnapshotEntry> kept;
    for (auto& c : all) {
        if (c.delta_dist_d >= min_dist && c.delta_dist_d <= max_dist) {
            kept.push_back({c.address, c.current_d});
            results.push_back(std::move(c));
        }
    }
    m_snapshot = std::move(kept);
    std::sort(results.begin(), results.end(), [](const VectorCandidate& a, const VectorCandidate& b) {
        return a.delta_dist_d < b.delta_dist_d;
    });
    return results;
}

std::optional<Vector3> VectorDetector::read_vector(const hal::IProcess& process, uintptr_t address) {
    if (!process.is_attached() || address == 0) return std::nullopt;
    Vector3 v;
    if (process.read_raw(address, &v, sizeof(Vector3)) &&
        std::isfinite(v.x) && std::isfinite(v.y) && std::isfinite(v.z)) {
        return v;
    }
    return std::nullopt;
}

std::optional<Vector3d> VectorDetector::read_vector_d(const hal::IProcess& process, uintptr_t address) {
    if (!process.is_attached() || address == 0) return std::nullopt;
    Vector3d v;
    if (process.read_raw(address, &v, sizeof(Vector3d)) &&
        std::isfinite(v.x) && std::isfinite(v.y) && std::isfinite(v.z)) {
        return v;
    }
    return std::nullopt;
}

bool VectorDetector::write_vector(const hal::IProcess& process, uintptr_t address, const Vector3& pos) {
    if (!process.is_attached() || address == 0) return false;
    return process.write_raw(address, &pos, sizeof(Vector3));
}

bool VectorDetector::write_vector_d(const hal::IProcess& process, uintptr_t address, const Vector3d& pos) {
    if (!process.is_attached() || address == 0) return false;
    return process.write_raw(address, &pos, sizeof(Vector3d));
}

bool VectorDetector::nudge(const hal::IProcess& process, uintptr_t address, float dx, float dy, float dz) {
    auto v = read_vector(process, address);
    if (!v) return false;
    v->x += dx;
    v->y += dy;
    v->z += dz;
    return write_vector(process, address, *v);
}

bool VectorDetector::nudge_d(const hal::IProcess& process, uintptr_t address, double dx, double dy, double dz) {
    auto v = read_vector_d(process, address);
    if (!v) return false;
    v->x += dx;
    v->y += dy;
    v->z += dz;
    return write_vector_d(process, address, *v);
}

void VectorDetector::add_waypoint(const std::string& name, const Vector3& pos) {
    m_waypoints.push_back({name, pos, {pos.x, pos.y, pos.z}, VectorFormat::Float3});
}

void VectorDetector::add_waypoint_d(const std::string& name, const Vector3d& pos, VectorFormat fmt) {
    m_waypoints.push_back({name, pos.to_f32(), pos, fmt});
}

void VectorDetector::remove_waypoint(size_t index) {
    if (index < m_waypoints.size()) {
        m_waypoints.erase(m_waypoints.begin() + index);
    }
}

} // namespace nce::view

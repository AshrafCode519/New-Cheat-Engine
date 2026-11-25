#pragma once

#include "../hal/process.hpp"
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nce::view {

enum class VectorFormat {
    Float3,  // 3x float (12 bytes) - standard Unity / UE4 / C++ games
    Double3  // 3x double (24 bytes) - UE5 Large World Coordinates (LWC)
};

struct Vector3 {
    float x{0.0f};
    float y{0.0f};
    float z{0.0f};

    [[nodiscard]] float distance_to(const Vector3& o) const noexcept {
        const float dx = x - o.x;
        const float dy = y - o.y;
        const float dz = z - o.z;
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return std::isfinite(x) && std::isfinite(y) && std::isfinite(z) &&
               std::abs(x) < 10000000.0f && std::abs(y) < 10000000.0f && std::abs(z) < 10000000.0f &&
               (std::abs(x) > 0.001f || std::abs(y) > 0.001f || std::abs(z) > 0.001f);
    }
};

struct Vector3d {
    double x{0.0};
    double y{0.0};
    double z{0.0};

    [[nodiscard]] double distance_to(const Vector3d& o) const noexcept {
        const double dx = x - o.x;
        const double dy = y - o.y;
        const double dz = z - o.z;
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return std::isfinite(x) && std::isfinite(y) && std::isfinite(z) &&
               std::abs(x) < 1e9 && std::abs(y) < 1e9 && std::abs(z) < 1e9 &&
               (std::abs(x) > 0.001 || std::abs(y) > 0.001 || std::abs(z) > 0.001);
    }

    [[nodiscard]] Vector3 to_f32() const noexcept {
        return {static_cast<float>(x), static_cast<float>(y), static_cast<float>(z)};
    }
};

struct VectorCandidate {
    uintptr_t address{0};
    Vector3 initial;
    Vector3 current;
    float delta_dist{0.0f};
    VectorFormat format{VectorFormat::Float3};
    Vector3d initial_d;
    Vector3d current_d;
    double delta_dist_d{0.0};
};

struct Waypoint {
    std::string name;
    Vector3 position;
    Vector3d position_d;
    VectorFormat format{VectorFormat::Float3};
};

class VectorDetector {
public:
    VectorDetector() = default;

    /// Takes a snapshot of all valid float3 (12B) or double3 (24B) triplets across writable memory regions.
    size_t take_snapshot(
        const hal::IProcess& process,
        uint32_t region_filter = hal::FilterFlags::DefaultScanFilter,
        VectorFormat format = VectorFormat::Float3);

    /// Coalesced batch read comparing live memory against snapshot without filtering out candidates.
    std::vector<VectorCandidate> detect_motion(
        const hal::IProcess& process,
        float min_dist = 0.5f,
        float max_dist = 2000.0f);

    /// Removes candidates from the active snapshot that moved while character should be standing still.
    size_t filter_stationary(const hal::IProcess& process, double epsilon = 0.05);

    /// Keeps only candidates in the active snapshot that moved by [min_dist, max_dist],
    /// updating their snapshot coordinates for subsequent iterative narrowing rounds.
    std::vector<VectorCandidate> filter_moved(
        const hal::IProcess& process,
        double min_dist = 0.5,
        double max_dist = 2000.0);

    // Direct read/write/nudge (Float3 & Double3)
    static std::optional<Vector3> read_vector(const hal::IProcess& process, uintptr_t address);
    static std::optional<Vector3d> read_vector_d(const hal::IProcess& process, uintptr_t address);
    static bool write_vector(const hal::IProcess& process, uintptr_t address, const Vector3& pos);
    static bool write_vector_d(const hal::IProcess& process, uintptr_t address, const Vector3d& pos);
    static bool nudge(const hal::IProcess& process, uintptr_t address, float dx, float dy, float dz);
    static bool nudge_d(const hal::IProcess& process, uintptr_t address, double dx, double dy, double dz);

    // Waypoints
    void add_waypoint(const std::string& name, const Vector3& pos);
    void add_waypoint_d(const std::string& name, const Vector3d& pos, VectorFormat fmt = VectorFormat::Double3);
    void remove_waypoint(size_t index);
    [[nodiscard]] const std::vector<Waypoint>& waypoints() const noexcept { return m_waypoints; }

    [[nodiscard]] size_t snapshot_count() const noexcept { return m_snapshot.size(); }
    [[nodiscard]] VectorFormat snapshot_format() const noexcept { return m_format; }
    void clear_snapshot() noexcept { m_snapshot.clear(); }

private:
    struct SnapshotEntry {
        uintptr_t address{0};
        Vector3d value;
    };

    std::vector<VectorCandidate> batch_read_and_eval(
        const hal::IProcess& process,
        const std::vector<SnapshotEntry>& entries,
        std::vector<Vector3d>* out_live_values = nullptr) const;

    VectorFormat m_format{VectorFormat::Float3};
    std::vector<SnapshotEntry> m_snapshot;
    std::vector<Waypoint> m_waypoints;
};

} // namespace nce::view

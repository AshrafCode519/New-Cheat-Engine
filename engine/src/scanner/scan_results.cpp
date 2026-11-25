#include "../../include/scanner/scan_results.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <mutex>
#include <queue>
#include "../../include/utils/hex_utils.hpp"
#include <bit>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace nce::scanner {

namespace {

constexpr const char* FILE_MAGIC = "NCE-RESULTS";
constexpr int FILE_VERSION = 1;

std::optional<std::vector<uint8_t>> parse_hex_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        const char* first = hex.data() + i * 2;
        auto [ptr, ec] = std::from_chars(first, first + 2, bytes[i], 16);
        if (ec != std::errc() || ptr != first + 2) return std::nullopt;
    }
    return bytes;
}

} // anonymous namespace

std::vector<uint8_t> value_to_bytes(const ScanValue& value) {
    std::vector<uint8_t> bytes;
    const bool is_be = is_big_endian(value.type);
    const bool numeric = dispatch_numeric(value.type, [&]<typename T>() {
        T x = std::get<T>(value.value);
        if (is_be) x = swap_bytes(x);
        bytes.resize(sizeof(T));
        std::memcpy(bytes.data(), &x, sizeof(T));
    });
    if (numeric) return bytes;

    if (const auto* s = std::get_if<std::string>(&value.value)) return {s->begin(), s->end()};
    if (const auto* b = std::get_if<std::vector<uint8_t>>(&value.value)) return *b;
    return bytes;
}

std::optional<ScanValue> value_from_bytes(DataType type, const uint8_t* data, size_t size) {
    std::optional<ScanValue> result;
    const bool is_be = is_big_endian(type);
    const bool numeric = dispatch_numeric(type, [&]<typename T>() {
        if (size != sizeof(T)) return;
        T x{};
        std::memcpy(&x, data, sizeof(T));
        if (is_be) x = swap_bytes(x);
        result = ScanValue::of(type, x);
    });
    if (numeric) return result;

    if (type == DataType::String) return ScanValue::of(type, std::string(data, data + size));
    return ScanValue::of(type, std::vector<uint8_t>(data, data + size));
}

void ScanResults::add_match(uintptr_t address, const ScanValue& current_val, const ScanValue& prev_val) {
    const auto current = value_to_bytes(current_val);
    if (empty()) {
        m_type = current_val.type;
        m_value_size = current.size();
    }
    if (current_val.type != m_type || current.size() != m_value_size) {
        throw std::invalid_argument("ScanResults::add_match: value does not match the result set's type");
    }

    // A previous value of another type (e.g. the default {}) falls back to the current value
    auto previous = value_to_bytes(prev_val);
    if (prev_val.type != m_type || previous.size() != m_value_size) previous = current;

    add(address, current.data(), previous.data());
}

void ScanResults::append(const ScanResults& other) {
    if (other.empty()) return;
    if (empty() && m_value_size == 0) {
        m_type = other.m_type;
        m_value_size = other.m_value_size;
    }
    if (other.m_type != m_type || other.m_value_size != m_value_size) {
        throw std::invalid_argument("ScanResults::append: result sets have different types");
    }
    const bool append_needs_spill = !other.m_chunks.empty() ||
        (m_ram_limit_bytes != SIZE_MAX &&
         (in_memory_bytes_used() + other.m_addresses.size() * (sizeof(uintptr_t) + 2 * m_value_size)) > m_ram_limit_bytes);

    if (!other.m_chunks.empty() && !m_addresses.empty()) {
        flush_to_disk();
    }

    for (const auto& ch : other.m_chunks) {
        SpillChunkRef copy = ch;
        copy.start_index = m_spilled_total;
        m_spilled_total += copy.count;
        m_chunks.push_back(std::move(copy));
    }

    m_addresses.insert(m_addresses.end(), other.m_addresses.begin(), other.m_addresses.end());
    m_current.insert(m_current.end(), other.m_current.begin(), other.m_current.end());
    m_previous.insert(m_previous.end(), other.m_previous.begin(), other.m_previous.end());

    if (append_needs_spill && in_memory_bytes_used() > m_ram_limit_bytes) {
        flush_to_disk();
    }
}

ScanMatch ScanResults::operator[](size_t index) const {
    return {
        address(index),
        value_from_bytes(m_type, current_bytes(index), m_value_size).value(),
        value_from_bytes(m_type, previous_bytes(index), m_value_size).value(),
    };
}

struct ScanResults::SpillStorage {
    uint64_t id{0};
    std::filesystem::path path;
    std::fstream file;
    std::mutex io_mutex;

    SpillStorage() {
        static std::atomic<uint64_t> s_next_id{1};
        id = s_next_id.fetch_add(1, std::memory_order_relaxed);
        std::error_code ec;
        auto dir = std::filesystem::temp_directory_path(ec);
        if (ec || dir.empty()) dir = std::filesystem::current_path(ec);
        path = dir / ("nce_scan_spill_" + std::to_string(id) + ".bin");
        file.open(path, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    }

    ~SpillStorage() {
        if (file.is_open()) file.close();
        if (!path.empty()) {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }
    }

    SpillStorage(const SpillStorage&) = delete;
    SpillStorage& operator=(const SpillStorage&) = delete;

    bool append_chunk(
        const std::vector<uintptr_t>& addrs,
        const std::vector<uint8_t>& cur,
        const std::vector<uint8_t>& prev,
        uint64_t& out_offset)
    {
        std::lock_guard lock(io_mutex);
        if (!file.is_open()) return false;
        file.clear();
        file.seekp(0, std::ios::end);
        const auto pos = file.tellp();
        if (pos < 0) return false;
        out_offset = static_cast<uint64_t>(pos);

        const auto addr_bytes = static_cast<std::streamsize>(addrs.size() * sizeof(uintptr_t));
        const auto cur_bytes = static_cast<std::streamsize>(cur.size());
        const auto prev_bytes = static_cast<std::streamsize>(prev.size());
        if (addr_bytes > 0) file.write(reinterpret_cast<const char*>(addrs.data()), addr_bytes);
        if (cur_bytes > 0) file.write(reinterpret_cast<const char*>(cur.data()), cur_bytes);
        if (prev_bytes > 0) file.write(reinterpret_cast<const char*>(prev.data()), prev_bytes);
        file.flush();
        return file.good();
    }

    bool read_chunk(uint64_t offset, size_t count, size_t value_size, ScanResults::LoadedChunk& out) {
        std::lock_guard lock(io_mutex);
        if (!file.is_open()) return false;
        file.clear();
        file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        out.storage_id = id;
        out.offset = offset;
        out.value_size = value_size;
        out.addresses.resize(count);
        out.current.resize(count * value_size);
        out.previous.resize(count * value_size);
        const auto addr_bytes = static_cast<std::streamsize>(count * sizeof(uintptr_t));
        const auto val_bytes = static_cast<std::streamsize>(count * value_size);
        if (addr_bytes > 0) file.read(reinterpret_cast<char*>(out.addresses.data()), addr_bytes);
        if (val_bytes > 0) file.read(reinterpret_cast<char*>(out.current.data()), val_bytes);
        if (val_bytes > 0) file.read(reinterpret_cast<char*>(out.previous.data()), val_bytes);
        return file.good();
    }
};

void ScanResults::set_ram_limit(size_t max_ram_bytes) {
    m_ram_limit_bytes = max_ram_bytes;
    if (m_ram_limit_bytes != SIZE_MAX && in_memory_bytes_used() > m_ram_limit_bytes) {
        flush_to_disk();
    }
}

bool ScanResults::spill_to_disk() {
    if (m_addresses.empty()) return !m_chunks.empty();
    flush_to_disk();
    return !m_chunks.empty();
}

size_t ScanResults::disk_bytes() const noexcept {
    const size_t stride = sizeof(uintptr_t) + 2 * m_value_size;
    return m_spilled_total * stride;
}

void ScanResults::flush_to_disk() {
    if (m_addresses.empty()) return;
    if (!m_active_storage) {
        m_active_storage = std::make_shared<SpillStorage>();
    }
    uint64_t offset = 0;
    if (!m_active_storage->append_chunk(m_addresses, m_current, m_previous, offset)) {
        return; // keep in memory if spill file cannot be opened/written
    }
    SpillChunkRef ref;
    ref.storage = m_active_storage;
    ref.offset = offset;
    ref.start_index = m_spilled_total;
    ref.count = m_addresses.size();
    m_spilled_total += ref.count;
    m_chunks.push_back(std::move(ref));

    std::vector<uintptr_t>().swap(m_addresses);
    std::vector<uint8_t>().swap(m_current);
    std::vector<uint8_t>().swap(m_previous);
}

const ScanResults::LoadedChunk* ScanResults::fetch_spilled_chunk(size_t index, size_t& out_local) const {
    if (index >= m_spilled_total || m_chunks.empty()) {
        throw std::out_of_range("ScanResults: index out of range");
    }

    auto it = std::upper_bound(m_chunks.begin(), m_chunks.end(), index,
        [](size_t idx, const SpillChunkRef& c) { return idx < c.start_index; });
    if (it == m_chunks.begin()) {
        throw std::out_of_range("ScanResults: spilled chunk lookup failed");
    }
    --it;
    out_local = index - it->start_index;
    if (out_local >= it->count || !it->storage) {
        throw std::out_of_range("ScanResults: chunk offset out of range");
    }

    struct ThreadChunkCache {
        std::array<LoadedChunk, 4> slots{};
        size_t next_slot{0};
    };
    thread_local ThreadChunkCache tl_cache;

    for (auto& slot : tl_cache.slots) {
        if (slot.storage_id == it->storage->id &&
            slot.offset == it->offset &&
            slot.value_size == m_value_size &&
            slot.addresses.size() == it->count) {
            return &slot;
        }
    }

    auto& target = tl_cache.slots[tl_cache.next_slot];
    tl_cache.next_slot = (tl_cache.next_slot + 1) % tl_cache.slots.size();
    if (!it->storage->read_chunk(it->offset, it->count, m_value_size, target)) {
        throw std::runtime_error("ScanResults: failed reading spilled scan chunk from disk");
    }
    return &target;
}

uintptr_t ScanResults::spilled_address(size_t index) const {
    size_t local = 0;
    const auto* chunk = fetch_spilled_chunk(index, local);
    return chunk->addresses[local];
}

const uint8_t* ScanResults::spilled_current_bytes(size_t index) const {
    size_t local = 0;
    const auto* chunk = fetch_spilled_chunk(index, local);
    return chunk->current.data() + local * m_value_size;
}

const uint8_t* ScanResults::spilled_previous_bytes(size_t index) const {
    size_t local = 0;
    const auto* chunk = fetch_spilled_chunk(index, local);
    return chunk->previous.data() + local * m_value_size;
}

void ScanResults::for_each(
    const std::function<void(size_t index, uintptr_t address, const uint8_t* current, const uint8_t* previous)>& fn) const
{
    if (!fn) return;
    LoadedChunk chunk_buf;
    size_t global_idx = 0;
    for (const auto& c : m_chunks) {
        if (!c.storage || !c.storage->read_chunk(c.offset, c.count, m_value_size, chunk_buf)) {
            throw std::runtime_error("ScanResults::for_each: failed reading spilled chunk");
        }
        for (size_t j = 0; j < chunk_buf.addresses.size(); ++j, ++global_idx) {
            fn(global_idx,
               chunk_buf.addresses[j],
               chunk_buf.current.data() + j * m_value_size,
               chunk_buf.previous.data() + j * m_value_size);
        }
    }
    for (size_t j = 0; j < m_addresses.size(); ++j, ++global_idx) {
        fn(global_idx,
           m_addresses[j],
           m_current.data() + j * m_value_size,
           m_previous.data() + j * m_value_size);
    }
}

void ScanResults::sort_by_address() {
    if (count() <= 1) return;

    auto sort_ram_chunk = [&](std::vector<uintptr_t>& addrs,
                              std::vector<uint8_t>& cur,
                              std::vector<uint8_t>& prev) {
        const size_t n = addrs.size();
        if (n <= 1) return;
        std::vector<size_t> order(n);
        for (size_t i = 0; i < n; ++i) order[i] = i;
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return addrs[a] < addrs[b];
        });
        std::vector<uintptr_t> s_addrs(n);
        std::vector<uint8_t> s_cur(n * m_value_size);
        std::vector<uint8_t> s_prev(n * m_value_size);
        for (size_t i = 0; i < n; ++i) {
            const size_t src = order[i];
            s_addrs[i] = addrs[src];
            std::memcpy(s_cur.data() + i * m_value_size, cur.data() + src * m_value_size, m_value_size);
            std::memcpy(s_prev.data() + i * m_value_size, prev.data() + src * m_value_size, m_value_size);
        }
        addrs = std::move(s_addrs);
        cur = std::move(s_cur);
        prev = std::move(s_prev);
    };

    if (m_chunks.empty()) {
        sort_ram_chunk(m_addresses, m_current, m_previous);
        return;
    }

    flush_to_disk();
    if (m_chunks.empty()) return;

    // Pass 1: sort each spilled chunk individually into sorted runs
    struct SortedRun {
        std::vector<SpillChunkRef> chunks;
    };
    auto pass1_storage = std::make_shared<SpillStorage>();
    std::vector<SortedRun> runs;
    runs.reserve(m_chunks.size());

    LoadedChunk loaded;
    for (const auto& c : m_chunks) {
        if (!c.storage || !c.storage->read_chunk(c.offset, c.count, m_value_size, loaded)) {
            throw std::runtime_error("ScanResults::sort_by_address: failed reading spilled chunk");
        }
        sort_ram_chunk(loaded.addresses, loaded.current, loaded.previous);
        uint64_t off = 0;
        if (!pass1_storage->append_chunk(loaded.addresses, loaded.current, loaded.previous, off)) {
            throw std::runtime_error("ScanResults::sort_by_address: failed writing sorted run");
        }
        SortedRun run;
        run.chunks.push_back({pass1_storage, off, 0, loaded.addresses.size()});
        runs.push_back(std::move(run));
    }

    // Multi-pass k-way merge (fan-in 32)
    constexpr size_t kFanIn = 32;
    const size_t stride = sizeof(uintptr_t) + 2 * m_value_size;
    const size_t out_chunk_entries = (m_ram_limit_bytes == SIZE_MAX)
        ? size_t{8192}
        : std::clamp<size_t>(m_ram_limit_bytes / std::max<size_t>(1, stride), 128, 8192);

    while (runs.size() > 1) {
        auto next_storage = std::make_shared<SpillStorage>();
        std::vector<SortedRun> next_runs;
        for (size_t base = 0; base < runs.size(); base += kFanIn) {
            const size_t end = std::min(runs.size(), base + kFanIn);
            struct Cursor {
                const SortedRun* run{nullptr};
                size_t chunk_idx{0};
                size_t item_idx{0};
                LoadedChunk buf;
            };
            std::vector<Cursor> cursors(end - base);
            struct HeapItem {
                uintptr_t addr;
                size_t cursor_idx;
                bool operator>(const HeapItem& o) const noexcept { return addr > o.addr; }
            };
            std::priority_queue<HeapItem, std::vector<HeapItem>, std::greater<HeapItem>> pq;

            for (size_t k = 0; k < cursors.size(); ++k) {
                cursors[k].run = &runs[base + k];
                if (!cursors[k].run->chunks.empty()) {
                    const auto& first = cursors[k].run->chunks[0];
                    if (!first.storage->read_chunk(first.offset, first.count, m_value_size, cursors[k].buf)) {
                        throw std::runtime_error("ScanResults::sort_by_address: merge read failed");
                    }
                    if (!cursors[k].buf.addresses.empty()) {
                        pq.push({cursors[k].buf.addresses[0], k});
                    }
                }
            }

            SortedRun merged_run;
            std::vector<uintptr_t> out_addrs;
            std::vector<uint8_t> out_cur;
            std::vector<uint8_t> out_prev;
            out_addrs.reserve(out_chunk_entries);
            out_cur.reserve(out_chunk_entries * m_value_size);
            out_prev.reserve(out_chunk_entries * m_value_size);

            auto flush_out = [&]() {
                if (out_addrs.empty()) return;
                uint64_t off = 0;
                if (!next_storage->append_chunk(out_addrs, out_cur, out_prev, off)) {
                    throw std::runtime_error("ScanResults::sort_by_address: merge write failed");
                }
                merged_run.chunks.push_back({next_storage, off, 0, out_addrs.size()});
                out_addrs.clear();
                out_cur.clear();
                out_prev.clear();
            };

            while (!pq.empty()) {
                const auto top = pq.top();
                pq.pop();
                auto& cur = cursors[top.cursor_idx];
                const size_t idx = cur.item_idx++;
                out_addrs.push_back(cur.buf.addresses[idx]);
                const uint8_t* cb = cur.buf.current.data() + idx * m_value_size;
                const uint8_t* pb = cur.buf.previous.data() + idx * m_value_size;
                out_cur.insert(out_cur.end(), cb, cb + m_value_size);
                out_prev.insert(out_prev.end(), pb, pb + m_value_size);
                if (out_addrs.size() >= out_chunk_entries) flush_out();

                if (cur.item_idx < cur.buf.addresses.size()) {
                    pq.push({cur.buf.addresses[cur.item_idx], top.cursor_idx});
                } else if (++cur.chunk_idx < cur.run->chunks.size()) {
                    cur.item_idx = 0;
                    const auto& nxt = cur.run->chunks[cur.chunk_idx];
                    if (!nxt.storage->read_chunk(nxt.offset, nxt.count, m_value_size, cur.buf)) {
                        throw std::runtime_error("ScanResults::sort_by_address: merge next-chunk read failed");
                    }
                    if (!cur.buf.addresses.empty()) {
                        pq.push({cur.buf.addresses[0], top.cursor_idx});
                    }
                }
            }
            flush_out();
            next_runs.push_back(std::move(merged_run));
        }
        runs = std::move(next_runs);
        m_active_storage = next_storage;
    }

    m_chunks = std::move(runs[0].chunks);
    size_t total_idx = 0;
    for (auto& c : m_chunks) {
        c.start_index = total_idx;
        total_idx += c.count;
    }
    m_spilled_total = total_idx;
}

size_t MemorySnapshot::candidate_count() const noexcept {
    size_t total = 0;
    for (const auto& b : blocks) {
        for (uint64_t word : b.alive) total += std::popcount(word);
    }
    return total;
}

bool save_results(const std::string& path, uint32_t pid, DataType type, const ScanResults& results) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;

    out << FILE_MAGIC << " " << FILE_VERSION << "\n"
        << "type " << utils::format_data_type(type) << "\n"
        << "pid " << pid << "\n"
        << "count " << results.count() << "\n";

    constexpr char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < results.count(); ++i) {
        out << std::hex << std::uppercase << results.address(i) << std::dec << " ";
        const uint8_t* bytes = results.current_bytes(i);
        for (size_t b = 0; b < results.value_size(); ++b) {
            out << digits[bytes[b] >> 4] << digits[bytes[b] & 0xF];
        }
        out << "\n";
    }

    return static_cast<bool>(out);
}

std::optional<SavedResults> load_results(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;

    std::string magic, key, type_name;
    int version = 0;
    size_t count = 0;
    SavedResults saved;

    if (!(in >> magic >> version) || magic != FILE_MAGIC || version != FILE_VERSION) return std::nullopt;
    if (!(in >> key >> type_name) || key != "type") return std::nullopt;
    if (!(in >> key >> saved.pid) || key != "pid") return std::nullopt;
    if (!(in >> key >> count) || key != "count") return std::nullopt;

    auto type = utils::parse_data_type(type_name);
    if (!type) return std::nullopt;
    saved.type = *type;

    std::string address_hex, value_hex;
    while (in >> address_hex >> value_hex) {
        uintptr_t address = 0;
        auto [ptr, ec] = std::from_chars(address_hex.data(), address_hex.data() + address_hex.size(), address, 16);
        if (ec != std::errc() || ptr != address_hex.data() + address_hex.size()) return std::nullopt;

        auto bytes = parse_hex_bytes(value_hex);
        if (!bytes) return std::nullopt;
        auto value = value_from_bytes(saved.type, bytes->data(), bytes->size());
        if (!value) return std::nullopt;

        // Mixed value sizes within one file (e.g. strings of different lengths) are not a valid results file
        if (!saved.results.empty() && bytes->size() != saved.results.value_size()) return std::nullopt;
        saved.results.add_match(address, *value, *value);
    }

    if (saved.results.count() != count) return std::nullopt;
    return saved;
}

} // namespace nce::scanner

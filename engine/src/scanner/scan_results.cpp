#include "../../include/scanner/scan_results.hpp"
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
    m_addresses.insert(m_addresses.end(), other.m_addresses.begin(), other.m_addresses.end());
    m_current.insert(m_current.end(), other.m_current.begin(), other.m_current.end());
    m_previous.insert(m_previous.end(), other.m_previous.begin(), other.m_previous.end());
}

ScanMatch ScanResults::operator[](size_t index) const {
    return {
        m_addresses[index],
        value_from_bytes(m_type, current_bytes(index), m_value_size).value(),
        value_from_bytes(m_type, previous_bytes(index), m_value_size).value(),
    };
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

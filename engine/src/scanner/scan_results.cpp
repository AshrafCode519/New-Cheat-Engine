#include "../../include/scanner/scan_results.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nce::scanner {

namespace {

constexpr const char* FILE_MAGIC = "NCE-RESULTS";
constexpr int FILE_VERSION = 1;

std::vector<uint8_t> value_bytes(const ScanValue& v) {
    std::vector<uint8_t> bytes;
    const bool numeric = dispatch_numeric(v.type, [&]<typename T>() {
        const T x = std::get<T>(v.value);
        bytes.resize(sizeof(T));
        std::memcpy(bytes.data(), &x, sizeof(T));
    });
    if (numeric) return bytes;

    if (const auto* s = std::get_if<std::string>(&v.value)) return {s->begin(), s->end()};
    if (const auto* b = std::get_if<std::vector<uint8_t>>(&v.value)) return *b;
    return bytes;
}

std::optional<ScanValue> value_from_bytes(DataType type, std::vector<uint8_t> bytes) {
    std::optional<ScanValue> result;
    const bool numeric = dispatch_numeric(type, [&]<typename T>() {
        if (bytes.size() != sizeof(T)) return;
        T x{};
        std::memcpy(&x, bytes.data(), sizeof(T));
        result = ScanValue::of(type, x);
    });
    if (numeric) return result;

    if (type == DataType::String) return ScanValue::of(type, std::string(bytes.begin(), bytes.end()));
    return ScanValue::of(type, std::move(bytes));
}

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

bool save_results(const std::string& path, uint32_t pid, DataType type, const ScanResults& results) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;

    out << FILE_MAGIC << " " << FILE_VERSION << "\n"
        << "type " << utils::format_data_type(type) << "\n"
        << "pid " << pid << "\n"
        << "count " << results.count() << "\n";

    constexpr char digits[] = "0123456789ABCDEF";
    for (const auto& m : results.get_matches()) {
        out << std::hex << std::uppercase << m.address << std::dec << " ";
        for (uint8_t b : value_bytes(m.current_value)) {
            out << digits[b >> 4] << digits[b & 0xF];
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
    saved.results.reserve(count);

    std::string address_hex, value_hex;
    while (in >> address_hex >> value_hex) {
        uintptr_t address = 0;
        auto [ptr, ec] = std::from_chars(address_hex.data(), address_hex.data() + address_hex.size(), address, 16);
        if (ec != std::errc() || ptr != address_hex.data() + address_hex.size()) return std::nullopt;

        auto bytes = parse_hex_bytes(value_hex);
        if (!bytes) return std::nullopt;
        auto value = value_from_bytes(saved.type, std::move(*bytes));
        if (!value) return std::nullopt;

        saved.results.add_match(address, *value, *value);
    }

    if (saved.results.count() != count) return std::nullopt;
    return saved;
}

} // namespace nce::scanner

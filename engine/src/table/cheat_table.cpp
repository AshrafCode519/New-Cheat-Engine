#include "../../include/table/cheat_table.hpp"
#include "../../include/scanner/scan_results.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/utils/text_encoding.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <fstream>
#include <sstream>

namespace nce::table {

namespace {

using json = nlohmann::ordered_json; // keeps keys in the order written

constexpr const char* FORMAT_NAME = "nce-table";
constexpr int FORMAT_VERSION = 1;

std::string to_hex(uint64_t value) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << value;
    return ss.str();
}

template <typename T>
std::optional<T> from_hex(const std::string& text) {
    std::string_view digits(text);
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) digits.remove_prefix(2);
    T value{};
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value, 16);
    if (ec != std::errc() || ptr != digits.data() + digits.size() || digits.empty()) return std::nullopt;
    return value;
}

bool read_pointer(const hal::IProcess& process, uintptr_t address, uintptr_t& out) {
    if (process.pointer_size() == 4) {
        uint32_t value = 0;
        if (!process.read(address, value)) return false;
        out = value;
        return true;
    }
    return process.read(address, out);
}

size_t entry_size(const TableEntry& entry) {
    const size_t numeric = scanner::get_data_type_size(entry.type);
    const bool is_numeric = scanner::dispatch_numeric(entry.type, []<typename T>() {});
    return is_numeric ? numeric : entry.length;
}

} // anonymous namespace

uintptr_t TableEntry::address(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules) const {
    if (!is_absolute()) return location.resolve(process, modules);

    uintptr_t current = location.base_offset;
    for (const auto offset : location.offsets) {
        uintptr_t value = 0;
        if (!read_pointer(process, current, value)) return 0;
        current = value + static_cast<uintptr_t>(offset);
    }
    return current;
}

std::string TableEntry::location_string() const {
    std::ostringstream ss;
    if (is_absolute()) {
        ss << utils::format_address(location.base_offset);
    } else {
        ss << location.module_name << "+" << to_hex(location.base_offset);
    }
    for (const auto offset : location.offsets) {
        ss << " -> " << to_hex(static_cast<uint64_t>(offset));
    }
    return ss.str();
}

TableEntry make_entry(uintptr_t address, scanner::DataType type, const std::vector<hal::ModuleInfo>& modules,
                      std::string description, size_t length) {
    TableEntry entry;
    entry.description = std::move(description);
    entry.type = type;
    entry.length = scanner::dispatch_numeric(type, []<typename T>() {}) ? 0 : length; // numbers know their size
    entry.location.base_offset = address;

    for (const auto& mod : modules) {
        if (address >= mod.base_address && address < mod.base_address + mod.size) {
            entry.location.module_name = mod.name;
            entry.location.base_offset = address - mod.base_address;
            break;
        }
    }
    return entry;
}

TableEntry make_entry(const scanner::PointerPath& path, scanner::DataType type, std::string description) {
    TableEntry entry;
    entry.description = std::move(description);
    entry.type = type;
    entry.location = path;
    return entry;
}

std::optional<scanner::ScanValue> read_entry(const TableEntry& entry, const hal::IProcess& process,
                                             const std::vector<hal::ModuleInfo>& modules) {
    const uintptr_t address = entry.address(process, modules);
    const size_t size = entry_size(entry);
    if (address == 0 || size == 0) return std::nullopt;

    std::vector<uint8_t> bytes(size);
    if (!process.read_raw(address, bytes.data(), size)) return std::nullopt;

    // Text entries stop at the first terminator, like the program reading them would
    if (entry.type == scanner::DataType::String) {
        const auto end = std::find(bytes.begin(), bytes.end(), uint8_t{0});
        return scanner::ScanValue::of(entry.type, std::string(bytes.begin(), end));
    }
    if (entry.type == scanner::DataType::String16) {
        size_t units = 0;
        while (units * 2 + 1 < bytes.size() && (bytes[units * 2] | bytes[units * 2 + 1]) != 0) ++units;
        bytes.resize(units * 2);
        return scanner::ScanValue::of(entry.type, std::move(bytes));
    }
    return scanner::value_from_bytes(entry.type, bytes.data(), bytes.size());
}

bool write_entry(const TableEntry& entry, const std::string& value_text, const hal::IProcess& process,
                 const std::vector<hal::ModuleInfo>& modules) {
    std::vector<uint8_t> bytes;

    if (auto value = utils::parse_scan_value(entry.type, value_text)) {
        bytes = scanner::value_to_bytes(*value);
    } else if (entry.type == scanner::DataType::String) {
        bytes.assign(value_text.begin(), value_text.end());
    } else if (entry.type == scanner::DataType::String16) {
        auto encoded = utils::utf8_to_utf16le(value_text);
        if (!encoded) return false;
        bytes = std::move(*encoded);
    } else {
        return false; // invalid number, or an aob entry
    }

    if (entry.type == scanner::DataType::String || entry.type == scanner::DataType::String16) {
        if (bytes.size() > entry.length) return false;
        // Terminate the shorter text so the old tail isn't read as part of it
        const size_t terminator = (entry.type == scanner::DataType::String16) ? 2 : 1;
        if (bytes.size() + terminator <= entry.length) bytes.resize(bytes.size() + terminator, 0);
    }

    const uintptr_t address = entry.address(process, modules);
    return address != 0 && process.write_raw(address, bytes.data(), bytes.size());
}

std::string to_json(const CheatTable& table) {
    json entries = json::array();
    for (const auto& e : table.entries) {
        json item = {
            {"description", e.description},
            {"type", utils::format_data_type(e.type)},
        };
        if (!e.is_absolute()) item["module"] = e.location.module_name;
        item["offset"] = to_hex(e.location.base_offset);
        if (!e.location.offsets.empty()) {
            json offsets = json::array();
            for (const auto o : e.location.offsets) offsets.push_back(to_hex(static_cast<uint64_t>(o)));
            item["pointer"] = offsets;
        }
        if (e.length > 0) item["length"] = e.length;
        if (e.frozen_value) item["freeze"] = *e.frozen_value;
        entries.push_back(item);
    }

    const json doc = {
        {"format", FORMAT_NAME},
        {"version", FORMAT_VERSION},
        {"process", table.process_name},
        {"entries", entries},
    };
    return doc.dump(2) + "\n";
}

std::optional<CheatTable> from_json(const std::string& text) {
    const json doc = json::parse(text, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) return std::nullopt;
    if (doc.value("format", "") != FORMAT_NAME || doc.value("version", 0) != FORMAT_VERSION) return std::nullopt;

    CheatTable table;
    table.process_name = doc.value("process", "");

    const auto entries = doc.find("entries");
    if (entries == doc.end() || !entries->is_array()) return std::nullopt;

    for (const auto& item : *entries) {
        if (!item.is_object()) return std::nullopt;

        TableEntry e;
        e.description = item.value("description", "");

        auto type = utils::parse_data_type(item.value("type", ""));
        if (!type) return std::nullopt;
        e.type = *type;

        e.location.module_name = item.value("module", "");
        auto offset = from_hex<uintptr_t>(item.value("offset", ""));
        if (!offset) return std::nullopt;
        e.location.base_offset = *offset;

        if (const auto pointer = item.find("pointer"); pointer != item.end()) {
            if (!pointer->is_array()) return std::nullopt;
            for (const auto& o : *pointer) {
                if (!o.is_string()) return std::nullopt;
                auto value = from_hex<int64_t>(o.get<std::string>());
                if (!value) return std::nullopt;
                e.location.offsets.push_back(*value);
            }
        }

        if (const auto length = item.find("length"); length != item.end()) {
            if (!length->is_number_unsigned()) return std::nullopt;
            e.length = length->get<size_t>();
        }
        const bool is_numeric = scanner::dispatch_numeric(e.type, []<typename T>() {});
        if (is_numeric) e.length = 0;                // numbers know their size
        else if (e.length == 0) return std::nullopt; // text / aob entries need one

        if (const auto freeze = item.find("freeze"); freeze != item.end()) {
            if (!freeze->is_string()) return std::nullopt;
            e.frozen_value = freeze->get<std::string>();
        }

        table.entries.push_back(std::move(e));
    }

    return table;
}

bool save_table(const std::string& path, const CheatTable& table) {
    std::ofstream out(path, std::ios::trunc | std::ios::binary);
    if (!out) return false;
    out << to_json(table);
    return static_cast<bool>(out);
}

std::optional<CheatTable> load_table(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return from_json(ss.str());
}

} // namespace nce::table

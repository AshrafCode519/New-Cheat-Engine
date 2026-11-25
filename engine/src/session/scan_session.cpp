#include "../../include/session/scan_session.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/utils/text_encoding.hpp"
#include <sstream>

namespace nce::session {

namespace {

bool is_numeric(scanner::DataType type) {
    return scanner::dispatch_numeric(type, []<typename T>() {});
}

std::string invalid_value(const std::string& text, scanner::DataType type) {
    return "'" + text + "' is not a valid " + utils::format_data_type(type) + " value (not a number, or out of range).";
}

} // anonymous namespace

const std::vector<NextCondition>& ScanSession::next_conditions() {
    using C = scanner::ScanCondition;
    static const std::vector<NextCondition> conditions = {
        {"exact",     "Exact value",  C::ExactValue,  1},
        {"changed",   "Changed",      C::Changed,     0},
        {"unchanged", "Unchanged",    C::Unchanged,   0},
        {"inc",       "Increased",    C::Increased,   0},
        {"dec",       "Decreased",    C::Decreased,   0},
        {"gt",        "Greater than", C::GreaterThan, 1},
        {"lt",        "Less than",    C::LessThan,    1},
        {"between",   "Between",      C::Between,     2},
        {"incby",     "Increased by", C::IncreasedBy, 1},
        {"decby",     "Decreased by", C::DecreasedBy, 1},
    };
    return conditions;
}

std::optional<Outcome> ScanSession::refuse() const {
    if (!m_scanner || !m_process) return Outcome::fail("Attach to a process first.");
    if (!m_process->is_attached()) return Outcome::fail("The target is no longer running; attach again.");
    return std::nullopt;
}

void ScanSession::clear() {
    m_state = {};
    m_history.clear();
}

// Moves the current state into the undo history. Snapshots can be as large as the scanned memory,
// so pushing one drops every older entry: only the newest snapshot is kept.
void ScanSession::push_history() {
    if (m_state.snapshot) m_history.clear();
    m_history.push_back(std::move(m_state));
    if (m_history.size() > MAX_UNDO_STEPS) m_history.erase(m_history.begin());
    m_state = {};
}

bool ScanSession::undo() {
    if (m_history.empty()) return false;
    m_state = std::move(m_history.back());
    m_history.pop_back();
    return true;
}

void ScanSession::replace(scanner::ScanResults results, scanner::DataType type) {
    push_history();
    m_state.results = std::move(results);
    m_state.type = type;
}

std::string ScanSession::describe() const {
    std::ostringstream ss;
    if (m_state.snapshot) {
        ss << m_state.snapshot->candidate_count() << " candidates, snapshot " << format_size(m_state.snapshot->memory_bytes());
    } else {
        ss << m_state.results.count() << " matches";
    }
    return ss.str();
}

Outcome ScanSession::first_scan(const std::string& type_name, const std::string& input, scanner::FloatMatchMode float_mode) {
    if (auto refused = refuse()) return *refused;

    auto type = utils::parse_data_type(type_name);
    if (!type) {
        return Outcome::fail("Unknown type: '" + type_name + "'. Use i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, str, wstr, aob.");
    }

    std::istringstream input_stream(input);
    std::string value_text;
    input_stream >> value_text;

    if (*type == scanner::DataType::AOB) {
        if (!utils::parse_aob_pattern(input)) return Outcome::fail("Invalid AOB pattern. Example: 48 8B ? ? 89");
        push_history();
        m_state.type = *type;
        m_state.results = m_scanner->first_scan_aob(input, 1);
        return Outcome::success();
    }

    if (*type == scanner::DataType::String || *type == scanner::DataType::String16) {
        const bool utf16 = (*type == scanner::DataType::String16);
        if (input.empty()) return Outcome::fail("Type the text to search for.");
        if (utf16 && !utils::utf8_to_utf16le(input)) {
            return Outcome::fail("The text is not valid UTF-8 (non-ASCII input needs a UTF-8 console).");
        }
        push_history();
        m_state.type = *type;
        m_state.results = m_scanner->first_scan_string(input, utf16, 1);
        return Outcome::success();
    }

    const size_t alignment = scanner::get_data_type_size(*type);
    if (value_text == "?" || value_text == "unknown") {
        push_history();
        m_state.type = *type;
        m_state.snapshot = std::make_shared<scanner::MemorySnapshot>(m_scanner->first_scan_unknown(*type, alignment));
        return Outcome::success();
    }

    auto value = utils::parse_scan_value(*type, value_text);
    if (!value) return Outcome::fail(invalid_value(value_text, *type));

    std::string note;
    const auto range = float_exact_range(*type, value_text, float_mode);
    if (range) {
        std::ostringstream ss;
        ss << "matching " << utils::format_data_type(*type) << " values in [" << range->first.to_string() << ", "
           << range->second.to_string() << "] (floatmode " << float_mode_name(float_mode) << ")";
        note = ss.str();
    }

    push_history();
    m_state.type = *type;
    m_state.xor_key.reset();
    m_state.results = range
        ? m_scanner->first_scan(*type, scanner::ScanCondition::Between, range->first, range->second, alignment)
        : m_scanner->first_scan(*type, scanner::ScanCondition::ExactValue, *value, {}, alignment);
    return Outcome::success(note);
}

Outcome ScanSession::first_scan_xor(const std::string& type_name, const std::string& value_text, const std::string& key_text) {
    if (auto refused = refuse()) return *refused;
    auto type = utils::parse_data_type(type_name);
    if (!type || !is_numeric(*type)) {
        return Outcome::fail("XOR scan requires a numeric type (e.g. i32, u32, i64, u64, f32, f64).");
    }
    auto value = utils::parse_scan_value(*type, value_text);
    if (!value) return Outcome::fail(invalid_value(value_text, *type));

    const size_t alignment = scanner::get_data_type_size(*type);
    if (key_text.empty() || key_text == "auto" || key_text == "?") {
        push_history();
        m_state.type = *type;
        m_state.xor_key.reset();
        m_state.results = m_scanner->first_scan_xor_auto(*type, *value, -static_cast<int>(alignment), alignment);
        return Outcome::success("paired XOR auto-discovery (key @ -0x" +
                                std::to_string(alignment) + ")");
    }

    uint64_t key = 0;
    try {
        size_t idx = 0;
        key = std::stoull(key_text, &idx, 0);
        if (idx != key_text.size()) return Outcome::fail("Invalid XOR key: '" + key_text + "'");
    } catch (...) {
        return Outcome::fail("Invalid XOR key: '" + key_text + "'");
    }

    push_history();
    m_state.type = *type;
    m_state.xor_key = key;
    m_state.results = m_scanner->first_scan_xor(*type, key, *value, alignment);
    return Outcome::success("XOR key scanned");
}

Outcome ScanSession::next_scan(const std::string& condition, const std::string& value1, const std::string& value2,
                               scanner::FloatMatchMode float_mode) {
    if (auto refused = refuse()) return *refused;
    if (empty()) return Outcome::fail("No results yet: run a first scan.");

    const NextCondition* spec = nullptr;
    for (const auto& c : next_conditions()) {
        if (condition == c.name) spec = &c;
    }
    if (!spec) return Outcome::fail("Unknown condition: " + condition + ". Use exact/changed/unchanged/inc/dec/gt/lt/between/incby/decby.");

    const scanner::DataType type = m_state.type;
    scanner::ScanCondition cond = spec->condition;
    if (!is_numeric(type) && cond != scanner::ScanCondition::Changed && cond != scanner::ScanCondition::Unchanged) {
        return Outcome::fail("Text and AOB results only support changed and unchanged.");
    }

    scanner::ScanValue val1;
    scanner::ScanValue val2;
    if (spec->value_count >= 1) {
        auto parsed = utils::parse_scan_value(type, value1);
        if (!parsed) return Outcome::fail(invalid_value(value1, type));
        val1 = *parsed;
    }
    if (spec->value_count >= 2) {
        auto parsed = utils::parse_scan_value(type, value2);
        if (!parsed) return Outcome::fail(invalid_value(value2, type));
        val2 = *parsed;
    }

    std::string note;
    if (cond == scanner::ScanCondition::ExactValue) {
        if (auto range = float_exact_range(type, value1, float_mode)) {
            cond = scanner::ScanCondition::Between;
            val1 = range->first;
            val2 = range->second;
            note = "matching values in [" + val1.to_string() + ", " + val2.to_string() + "]";
        }
    }

    push_history();
    filter_into_current(m_history.back(), cond, val1, val2);
    return Outcome::success(note);
}

// A snapshot stays a snapshot until its candidates take less memory as a results list
void ScanSession::filter_into_current(const State& source, scanner::ScanCondition condition,
                                      const scanner::ScanValue& value1, const scanner::ScanValue& value2) {
    m_state.type = source.type;
    m_state.xor_key = source.xor_key;
    if (!source.snapshot) {
        if (source.xor_key && condition == scanner::ScanCondition::ExactValue) {
            scanner::ScanValue enc_val = value1;
            const uint64_t k = *source.xor_key;
            scanner::dispatch_numeric(source.type, [&]<typename T>() {
                T plain = std::get<T>(value1.value);
                if constexpr (sizeof(T) == 1) enc_val.value = static_cast<T>(static_cast<uint8_t>(plain) ^ k);
                else if constexpr (sizeof(T) == 2) {
                    uint16_t b = 0; std::memcpy(&b, &plain, 2); b ^= static_cast<uint16_t>(k);
                    T enc{}; std::memcpy(&enc, &b, 2); enc_val.value = enc;
                } else if constexpr (sizeof(T) == 4) {
                    uint32_t b = 0; std::memcpy(&b, &plain, 4); b ^= static_cast<uint32_t>(k);
                    T enc{}; std::memcpy(&enc, &b, 4); enc_val.value = enc;
                } else if constexpr (sizeof(T) == 8) {
                    uint64_t b = 0; std::memcpy(&b, &plain, 8); b ^= k;
                    T enc{}; std::memcpy(&enc, &b, 8); enc_val.value = enc;
                }
            });
            m_state.results = m_scanner->next_scan(source.results, condition, enc_val, value2);
        } else {
            m_state.results = m_scanner->next_scan(source.results, condition, value1, value2);
        }
        return;
    }

    auto filtered = std::make_shared<scanner::MemorySnapshot>(
        m_scanner->filter_snapshot(*source.snapshot, condition, value1, value2));
    const size_t result_bytes = filtered->candidate_count() *
                                (sizeof(uintptr_t) + 2 * scanner::get_data_type_size(filtered->type));
    if (result_bytes <= filtered->memory_bytes()) {
        m_state.results = scanner::MemoryScanner::snapshot_to_results(*filtered);
    } else {
        m_state.snapshot = std::move(filtered);
    }
}

std::optional<std::pair<scanner::ScanValue, scanner::ScanValue>> float_exact_range(
    scanner::DataType type, const std::string& text, scanner::FloatMatchMode mode) {
    if (type != scanner::DataType::Float && type != scanner::DataType::Double) return std::nullopt;
    auto range = utils::float_match_range(text, mode);
    if (!range) return std::nullopt;
    if (type == scanner::DataType::Float) {
        return std::make_pair(scanner::ScanValue::of(type, static_cast<float>(range->first)),
                              scanner::ScanValue::of(type, static_cast<float>(range->second)));
    }
    return std::make_pair(scanner::ScanValue::of(type, range->first), scanner::ScanValue::of(type, range->second));
}

std::string value_text(const scanner::ScanValue& value) {
    if (value.type == scanner::DataType::String) return std::get<std::string>(value.value);
    if (value.type == scanner::DataType::String16) {
        const auto& bytes = std::get<std::vector<uint8_t>>(value.value);
        return utils::utf16le_to_utf8(bytes.data(), bytes.size());
    }
    return value.to_string();
}

std::string format_size(size_t bytes) {
    std::ostringstream ss;
    if (bytes >= 1024 * 1024) ss << (bytes / (1024 * 1024)) << " MB";
    else ss << (bytes / 1024) << " KB";
    return ss.str();
}

const char* float_mode_name(scanner::FloatMatchMode mode) {
    switch (mode) {
        case scanner::FloatMatchMode::Rounded:   return "rounded";
        case scanner::FloatMatchMode::Truncated: return "truncated";
        case scanner::FloatMatchMode::Exact:     return "exact";
    }
    return "?";
}

} // namespace nce::session

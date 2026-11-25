#include "table/ce_table_format.hpp"
#include "utils/hex_utils.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cctype>

namespace nce::table {

namespace {

std::string trim(const std::string& s) {
    auto start = s.begin();
    while (start != s.end() && std::isspace(static_cast<unsigned char>(*start))) {
        ++start;
    }
    auto end = s.end();
    do {
        --end;
    } while (std::distance(start, end) > 0 && std::isspace(static_cast<unsigned char>(*end)));
    return std::string(start, end + 1);
}

std::string unquote(const std::string& s) {
    std::string str = trim(s);
    if (str.size() >= 2 && str.front() == '"' && str.back() == '"') {
        return str.substr(1, str.size() - 2);
    }
    return str;
}

std::string unescape_xml(const std::string& text) {
    // Check for CDATA
    size_t cdata_start = text.find("<![CDATA[");
    if (cdata_start != std::string::npos) {
        size_t cdata_end = text.find("]]>", cdata_start);
        if (cdata_end != std::string::npos) {
            return text.substr(cdata_start + 9, cdata_end - (cdata_start + 9));
        }
    }

    std::string res;
    res.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '&') {
            if (text.compare(i, 4, "&lt;") == 0) { res += '<'; i += 3; }
            else if (text.compare(i, 4, "&gt;") == 0) { res += '>'; i += 3; }
            else if (text.compare(i, 5, "&amp;") == 0) { res += '&'; i += 4; }
            else if (text.compare(i, 6, "&quot;") == 0) { res += '"'; i += 5; }
            else if (text.compare(i, 6, "&apos;") == 0) { res += '\''; i += 5; }
            else { res += text[i]; }
        } else {
            res += text[i];
        }
    }
    return res;
}

std::string escape_xml(const std::string& text) {
    std::string res;
    res.reserve(text.size() * 11 / 10);
    for (char c : text) {
        switch (c) {
            case '<': res += "&lt;"; break;
            case '>': res += "&gt;"; break;
            case '&': res += "&amp;"; break;
            case '"': res += "&quot;"; break;
            case '\'': res += "&apos;"; break;
            default: res += c; break;
        }
    }
    return res;
}

std::string find_tag(const std::string& xml, const std::string& tag, size_t start_pos = 0, size_t* out_end = nullptr) {
    std::string open_tag = "<" + tag;
    size_t open_pos = xml.find(open_tag, start_pos);
    if (open_pos == std::string::npos) return "";

    size_t tag_body_start = xml.find('>', open_pos);
    if (tag_body_start == std::string::npos) return "";
    tag_body_start += 1;

    std::string close_tag = "</" + tag + ">";
    size_t close_pos = xml.find(close_tag, tag_body_start);
    if (close_pos == std::string::npos) return "";

    if (out_end) *out_end = close_pos + close_tag.size();
    return xml.substr(tag_body_start, close_pos - tag_body_start);
}

std::vector<std::string> find_all_tags(const std::string& xml, const std::string& tag) {
    std::vector<std::string> results;
    size_t pos = 0;
    while (pos < xml.size()) {
        size_t end_pos = 0;
        std::string content = find_tag(xml, tag, pos, &end_pos);
        if (end_pos == 0) break;
        results.push_back(content);
        pos = end_pos;
    }
    return results;
}

} // anonymous namespace

scanner::DataType parse_ce_variable_type(const std::string& type_str) {
    std::string t = trim(type_str);
    if (t == "Byte") return scanner::DataType::Int8;
    if (t == "2 Bytes") return scanner::DataType::Int16;
    if (t == "4 Bytes") return scanner::DataType::Int32;
    if (t == "8 Bytes") return scanner::DataType::Int64;
    if (t == "Float") return scanner::DataType::Float;
    if (t == "Double") return scanner::DataType::Double;
    if (t == "2 Bytes (Big Endian)") return scanner::DataType::Int16BE;
    if (t == "4 Bytes (Big Endian)") return scanner::DataType::Int32BE;
    if (t == "8 Bytes (Big Endian)") return scanner::DataType::Int64BE;
    if (t == "Float (Big Endian)") return scanner::DataType::FloatBE;
    if (t == "Double (Big Endian)") return scanner::DataType::DoubleBE;
    if (t == "String") return scanner::DataType::String;
    if (t == "Unicode") return scanner::DataType::String16;
    if (t == "Array of byte" || t == "AOB") return scanner::DataType::AOB;
    return scanner::DataType::Int32;
}

const char* ce_variable_type_str(scanner::DataType type) {
    switch (type) {
        case scanner::DataType::Int8:
        case scanner::DataType::UInt8:  return "Byte";
        case scanner::DataType::Int16:
        case scanner::DataType::UInt16: return "2 Bytes";
        case scanner::DataType::Int32:
        case scanner::DataType::UInt32: return "4 Bytes";
        case scanner::DataType::Int64:
        case scanner::DataType::UInt64: return "8 Bytes";
        case scanner::DataType::Float:    return "Float";
        case scanner::DataType::Double:   return "Double";
        case scanner::DataType::Int16BE:
        case scanner::DataType::UInt16BE: return "2 Bytes (Big Endian)";
        case scanner::DataType::Int32BE:
        case scanner::DataType::UInt32BE: return "4 Bytes (Big Endian)";
        case scanner::DataType::Int64BE:
        case scanner::DataType::UInt64BE: return "8 Bytes (Big Endian)";
        case scanner::DataType::FloatBE:  return "Float (Big Endian)";
        case scanner::DataType::DoubleBE: return "Double (Big Endian)";
        case scanner::DataType::String:   return "String";
        case scanner::DataType::String16: return "Unicode";
        case scanner::DataType::AOB:    return "Array of byte";
    }
    return "4 Bytes";
}

namespace {

void parse_address_string(const std::string& raw_addr, scanner::PointerPath& out_path) {
    std::string s = unquote(raw_addr);
    size_t plus_pos = s.find('+');
    if (plus_pos != std::string::npos) {
        out_path.module_name = unquote(s.substr(0, plus_pos));
        std::string offset_str = trim(s.substr(plus_pos + 1));
        out_path.base_offset = utils::parse_address(offset_str);
    } else {
        out_path.module_name.clear();
        out_path.base_offset = utils::parse_address(s);
    }
}

} // anonymous namespace

bool parse_ce_table(const std::string& xml_content, CheatTable& out_table, std::string& error_msg) {
    if (xml_content.empty()) {
        error_msg = "XML content is empty.";
        return false;
    }

    if (xml_content.find("<CheatTable") == std::string::npos &&
        xml_content.find("<CheatEntries") == std::string::npos) {
        error_msg = "Not a valid Cheat Engine table (missing <CheatTable> tag).";
        return false;
    }

    auto entries_blocks = find_all_tags(xml_content, "CheatEntry");
    for (const auto& block : entries_blocks) {
        std::string desc = unquote(unescape_xml(find_tag(block, "Description")));
        std::string var_type = trim(unescape_xml(find_tag(block, "VariableType")));

        // Check if it's an Auto Assembler Script
        if (var_type == "Auto Assembler Script") {
            std::string script_body = unescape_xml(find_tag(block, "AssemblerScript"));
            if (desc.empty()) desc = "Script_" + std::to_string(out_table.scripts.size() + 1);

            TableScript script;
            script.name = desc;
            script.body = script_body;
            script.enabled = false;
            out_table.scripts.push_back(std::move(script));
            continue;
        }

        // Regular TableEntry
        TableEntry entry;
        entry.description = desc;
        entry.type = parse_ce_variable_type(var_type);

        std::string addr_str = unescape_xml(find_tag(block, "Address"));
        parse_address_string(addr_str, entry.location);

        // Check for pointer offsets: <Offsets><Offset>18</Offset>...</Offsets>
        std::string offsets_block = find_tag(block, "Offsets");
        if (!offsets_block.empty()) {
            auto offset_tags = find_all_tags(offsets_block, "Offset");
            // Cheat Engine XML writes offsets in reverse (leaf/bottom offset first).
            // NCE follows path from root to leaf: base -> offset[0] -> ... -> leaf.
            // So we reverse the CE offsets list.
            std::vector<int64_t> offs;
            for (const auto& o_tag : offset_tags) {
                std::string trimmed_o = trim(unescape_xml(o_tag));
                if (!trimmed_o.empty() && trimmed_o.front() == '-') {
                    uintptr_t mag = utils::parse_address(trim(trimmed_o.substr(1)));
                    offs.push_back(-static_cast<int64_t>(mag));
                } else {
                    uintptr_t val = utils::parse_address(trimmed_o);
                    offs.push_back(static_cast<int64_t>(val));
                }
            }
            std::reverse(offs.begin(), offs.end());
            entry.location.offsets = std::move(offs);
        }

        // String length if specified
        std::string length_str = find_tag(block, "Length");
        if (!length_str.empty()) {
            try {
                entry.length = std::stoull(length_str);
            } catch (...) {}
        }

        std::string group_str = trim(unescape_xml(find_tag(block, "GroupName")));
        if (!group_str.empty()) entry.group = std::move(group_str);

        std::string dd_block = unescape_xml(find_tag(block, "DropDownList"));
        if (!dd_block.empty()) {
            std::istringstream dss(dd_block);
            std::string dline;
            while (std::getline(dss, dline)) {
                dline = trim(dline);
                if (const size_t col = dline.find(':'); col != std::string::npos && col > 0) {
                    std::string k = trim(dline.substr(0, col));
                    std::string v = trim(dline.substr(col + 1));
                    if (!k.empty()) entry.dropdown[k] = v;
                }
            }
        }

        out_table.entries.push_back(std::move(entry));
    }

    std::string lua_script = unescape_xml(find_tag(xml_content, "LuaScript"));
    if (!lua_script.empty()) {
        out_table.lua_script = std::move(lua_script);
    }

    return true;
}

std::string serialize_ce_table(const CheatTable& table) {
    std::ostringstream ss;
    ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ss << "<CheatTable CheatEngineTableVersion=\"42\">\n";
    ss << "  <CheatEntries>\n";

    int id = 0;

    // Output Table Entries
    for (const auto& e : table.entries) {
        ss << "    <CheatEntry>\n";
        ss << "      <ID>" << id++ << "</ID>\n";
        ss << "      <Description>\"" << escape_xml(e.description.empty() ? "No Description" : e.description) << "\"</Description>\n";
        ss << "      <VariableType>" << ce_variable_type_str(e.type) << "</VariableType>\n";

        if (e.type == scanner::DataType::String || e.type == scanner::DataType::String16) {
            if (e.length > 0) {
                ss << "      <Length>" << e.length << "</Length>\n";
            }
        }

        // Address
        std::ostringstream addr_ss;
        if (e.is_absolute()) {
            addr_ss << utils::format_address(e.location.base_offset);
        } else {
            addr_ss << "\"" << e.location.module_name << "\"+" << std::hex << e.location.base_offset << std::dec;
        }
        ss << "      <Address>" << escape_xml(addr_ss.str()) << "</Address>\n";

        // Offsets (in reverse order for CE)
        if (!e.location.offsets.empty()) {
            ss << "      <Offsets>\n";
            for (auto it = e.location.offsets.rbegin(); it != e.location.offsets.rend(); ++it) {
                ss << "        <Offset>";
                if (*it < 0) ss << "-" << std::hex << static_cast<uint64_t>(-*it);
                else ss << std::hex << static_cast<uint64_t>(*it);
                ss << std::dec << "</Offset>\n";
            }
            ss << "      </Offsets>\n";
        }
        if (!e.group.empty()) {
            ss << "      <GroupName>" << escape_xml(e.group) << "</GroupName>\n";
        }
        if (!e.dropdown.empty()) {
            ss << "      <DropDownList>";
            bool first_dd = true;
            for (const auto& [k, v] : e.dropdown) {
                if (!first_dd) ss << "\n";
                ss << escape_xml(k) << ":" << escape_xml(v);
                first_dd = false;
            }
            ss << "</DropDownList>\n";
        }

        ss << "    </CheatEntry>\n";
    }

    // Output Auto-Assembler Scripts
    for (const auto& s : table.scripts) {
        ss << "    <CheatEntry>\n";
        ss << "      <ID>" << id++ << "</ID>\n";
        ss << "      <Description>\"" << escape_xml(s.name.empty() ? "Script" : s.name) << "\"</Description>\n";
        ss << "      <VariableType>Auto Assembler Script</VariableType>\n";
        ss << "      <AssemblerScript><![CDATA[" << s.body << "]]></AssemblerScript>\n";
        ss << "    </CheatEntry>\n";
    }

    ss << "  </CheatEntries>\n";
    if (!table.lua_script.empty()) {
        ss << "  <LuaScript>" << escape_xml(table.lua_script) << "</LuaScript>\n";
    }
    ss << "</CheatTable>\n";

    return ss.str();
}

bool load_ce_table_file(const std::string& file_path, CheatTable& out_table, std::string& error_msg) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        error_msg = "Could not open file: " + file_path;
        return false;
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return parse_ce_table(ss.str(), out_table, error_msg);
}

bool save_ce_table_file(const std::string& file_path, const CheatTable& table, std::string& error_msg) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        error_msg = "Could not open file for writing: " + file_path;
        return false;
    }
    std::string xml = serialize_ce_table(table);
    file.write(xml.data(), static_cast<std::streamsize>(xml.size()));
    if (!file.good()) {
        error_msg = "Failed writing to file: " + file_path;
        return false;
    }
    return true;
}

} // namespace nce::table

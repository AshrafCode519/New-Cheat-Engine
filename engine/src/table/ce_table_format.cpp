#include "table/ce_table_format.hpp"
#include "hal/hotkeys.hpp"
#include "utils/hex_utils.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <sstream>

namespace nce::table {

namespace {

std::string trim(const std::string& s) {
    const size_t first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

std::string unquote(const std::string& s) {
    std::string str = trim(s);
    if (str.size() >= 2 && str.front() == '"' && str.back() == '"') {
        return str.substr(1, str.size() - 2);
    }
    return str;
}

std::string unescape_xml(const std::string& text) {
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

bool is_tag_char_boundary(char c) {
    return c == '>' || std::isspace(static_cast<unsigned char>(c)) || c == '/';
}

// Balanced tag extraction that properly handles nested identical tags (e.g. nested <CheatEntry>) and CDATA.
std::string find_tag(const std::string& xml, const std::string& tag, size_t start_pos = 0, size_t* out_end = nullptr) {
    const std::string open_prefix = "<" + tag;
    const std::string close_tag = "</" + tag + ">";

    size_t search = start_pos;
    size_t open_pos = std::string::npos;
    size_t body_start = std::string::npos;
    while (search < xml.size()) {
        size_t cdata = xml.find("<![CDATA[", search);
        size_t cand = xml.find(open_prefix, search);
        if (cand == std::string::npos) return "";
        if (cdata != std::string::npos && cdata < cand) {
            size_t cend = xml.find("]]>", cdata + 9);
            if (cend == std::string::npos) return "";
            search = cend + 3;
            continue;
        }
        if (cand + open_prefix.size() < xml.size() && !is_tag_char_boundary(xml[cand + open_prefix.size()])) {
            search = cand + open_prefix.size();
            continue;
        }
        size_t gt = xml.find('>', cand + open_prefix.size());
        if (gt == std::string::npos) return "";
        if (gt > cand && xml[gt - 1] == '/') {
            if (out_end) *out_end = gt + 1;
            return "";
        }
        open_pos = cand;
        body_start = gt + 1;
        break;
    }
    if (open_pos == std::string::npos) return "";

    int depth = 1;
    size_t cur = body_start;
    while (cur < xml.size()) {
        size_t cdata = xml.find("<![CDATA[", cur);
        size_t next_open = xml.find(open_prefix, cur);
        size_t next_close = xml.find(close_tag, cur);
        if (next_close == std::string::npos) return "";

        if (cdata != std::string::npos && cdata < next_close && (next_open == std::string::npos || cdata < next_open)) {
            size_t cend = xml.find("]]>", cdata + 9);
            if (cend == std::string::npos) return "";
            cur = cend + 3;
            continue;
        }
        if (next_open != std::string::npos && next_open < next_close) {
            if (next_open + open_prefix.size() < xml.size() && is_tag_char_boundary(xml[next_open + open_prefix.size()])) {
                size_t gt = xml.find('>', next_open + open_prefix.size());
                if (gt == std::string::npos) return "";
                if (xml[gt - 1] != '/') ++depth;
                cur = gt + 1;
            } else {
                cur = next_open + open_prefix.size();
            }
            continue;
        }

        --depth;
        if (depth == 0) {
            if (out_end) *out_end = next_close + close_tag.size();
            return xml.substr(body_start, next_close - body_start);
        }
        cur = next_close + close_tag.size();
    }
    return "";
}

std::vector<std::string> find_all_tags(const std::string& xml, const std::string& tag) {
    std::vector<std::string> results;
    size_t pos = 0;
    while (pos < xml.size()) {
        size_t end_pos = 0;
        std::string content = find_tag(xml, tag, pos, &end_pos);
        if (end_pos == 0) break;
        results.push_back(std::move(content));
        pos = end_pos;
    }
    return results;
}

scanner::DataType make_unsigned(scanner::DataType t) {
    switch (t) {
        case scanner::DataType::Int8:    return scanner::DataType::UInt8;
        case scanner::DataType::Int16:   return scanner::DataType::UInt16;
        case scanner::DataType::Int32:   return scanner::DataType::UInt32;
        case scanner::DataType::Int64:   return scanner::DataType::UInt64;
        case scanner::DataType::Int16BE: return scanner::DataType::UInt16BE;
        case scanner::DataType::Int32BE: return scanner::DataType::UInt32BE;
        case scanner::DataType::Int64BE: return scanner::DataType::UInt64BE;
        default: return t;
    }
}

bool is_unsigned_type(scanner::DataType t) {
    switch (t) {
        case scanner::DataType::UInt8:
        case scanner::DataType::UInt16:
        case scanner::DataType::UInt32:
        case scanner::DataType::UInt64:
        case scanner::DataType::UInt16BE:
        case scanner::DataType::UInt32BE:
        case scanner::DataType::UInt64BE:
            return true;
        default:
            return false;
    }
}

std::string ce_vk_to_key_name(int vk) {
    if (vk >= 112 && vk <= 135) return "F" + std::to_string(vk - 111);
    if (vk >= 'A' && vk <= 'Z') return std::string(1, static_cast<char>(vk));
    if (vk >= '0' && vk <= '9') return std::string(1, static_cast<char>(vk));
    if (vk >= 96 && vk <= 105) return "Num" + std::to_string(vk - 96);
    switch (vk) {
        case 106: return "Num*";
        case 107: return "Num+";
        case 109: return "Num-";
        case 110: return "Num.";
        case 111: return "Num/";
        case 19:  return "Pause";
        case 32:  return "Space";
        case 33:  return "PageUp";
        case 34:  return "PageDown";
        case 35:  return "End";
        case 36:  return "Home";
        case 37:  return "Left";
        case 38:  return "Up";
        case 39:  return "Right";
        case 40:  return "Down";
        case 45:  return "Insert";
        case 46:  return "Delete";
        default:  return "";
    }
}

std::vector<int> key_combo_to_ce_vks(const hal::KeyCombo& c) {
    std::vector<int> vks;
    if (c.ctrl)  vks.push_back(17); // VK_CONTROL
    if (c.alt)   vks.push_back(18); // VK_MENU
    if (c.shift) vks.push_back(16); // VK_SHIFT
    if (c.win)   vks.push_back(91); // VK_LWIN
    if (c.key.size() == 1 && c.key[0] >= 'A' && c.key[0] <= 'Z') { vks.push_back(c.key[0]); return vks; }
    if (c.key.size() == 1 && c.key[0] >= '0' && c.key[0] <= '9') { vks.push_back(c.key[0]); return vks; }
    if (c.key.size() >= 2 && c.key[0] == 'F') {
        try {
            int f = std::stoi(c.key.substr(1));
            if (f >= 1 && f <= 24) { vks.push_back(111 + f); return vks; }
        } catch (...) {}
    }
    if (c.key.rfind("Num", 0) == 0 && c.key.size() == 4) {
        char d = c.key[3];
        if (d >= '0' && d <= '9') { vks.push_back(96 + (d - '0')); return vks; }
        if (d == '*') { vks.push_back(106); return vks; }
        if (d == '+') { vks.push_back(107); return vks; }
        if (d == '-') { vks.push_back(109); return vks; }
        if (d == '.') { vks.push_back(110); return vks; }
        if (d == '/') { vks.push_back(111); return vks; }
    }
    static const std::pair<const char*, int> kNamed[] = {
        {"Pause", 19}, {"Space", 32}, {"PageUp", 33}, {"PageDown", 34},
        {"End", 35}, {"Home", 36}, {"Left", 37}, {"Up", 38},
        {"Right", 39}, {"Down", 40}, {"Insert", 45}, {"Delete", 46}
    };
    for (const auto& [name, code] : kNamed) {
        if (c.key == name) { vks.push_back(code); break; }
    }
    return vks;
}

std::optional<Hotkey> parse_ce_hotkey_tag(const std::string& hk_xml) {
    const std::string keys_blk = find_tag(hk_xml, "Keys");
    if (keys_blk.empty()) return std::nullopt;
    bool ctrl = false, alt = false, shift = false, win = false;
    std::string main_key;
    for (const auto& k : find_all_tags(keys_blk, "Key")) {
        int vk = 0;
        try { vk = std::stoi(trim(k)); } catch (...) { continue; }
        if (vk == 17 || vk == 162 || vk == 163) ctrl = true;
        else if (vk == 18 || vk == 164 || vk == 165) alt = true;
        else if (vk == 16 || vk == 160 || vk == 161) shift = true;
        else if (vk == 91 || vk == 92) win = true;
        else main_key = ce_vk_to_key_name(vk);
    }
    if (main_key.empty()) return std::nullopt;
    std::string combo_text;
    if (ctrl)  combo_text += "Ctrl+";
    if (alt)   combo_text += "Alt+";
    if (shift) combo_text += "Shift+";
    if (win)   combo_text += "Win+";
    combo_text += main_key;
    auto parsed = hal::parse_hotkey(combo_text);
    if (!parsed) return std::nullopt;

    Hotkey hk;
    hk.keys = hal::format_hotkey(*parsed);
    const std::string action = trim(unescape_xml(find_tag(hk_xml, "Action")));
    std::string val = trim(unescape_xml(find_tag(hk_xml, "Value")));
    if (action == "Set Value") {
        hk.action = Hotkey::Action::Set;
        hk.value = val;
    } else if (action == "Increase Value") {
        hk.action = Hotkey::Action::Add;
        hk.value = val.empty() ? "1" : val;
    } else if (action == "Decrease Value") {
        hk.action = Hotkey::Action::Add;
        if (val.empty()) hk.value = "-1";
        else if (val.front() == '-') hk.value = val.substr(1);
        else hk.value = "-" + val;
    } else {
        hk.action = Hotkey::Action::ToggleFreeze;
    }
    return hk;
}

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

void parse_entries_list(const std::string& entries_xml, const std::string& parent_group, CheatTable& out_table) {
    for (const auto& block : find_all_tags(entries_xml, "CheatEntry")) {
        // Extract children block first so nested child tags don't shadow this entry's fields
        size_t nested_end = 0;
        const std::string nested_entries = find_tag(block, "CheatEntries", 0, &nested_end);
        std::string own_xml = block;
        if (nested_end > 0) {
            const size_t open_child = block.find("<CheatEntries");
            if (open_child != std::string::npos && nested_end > open_child) {
                own_xml.erase(open_child, nested_end - open_child);
            }
        }

        const std::string desc = unquote(unescape_xml(find_tag(own_xml, "Description")));
        const std::string var_type = trim(unescape_xml(find_tag(own_xml, "VariableType")));
        const std::string group_hdr = trim(find_tag(own_xml, "GroupHeader"));
        const std::string addr_str = trim(unescape_xml(find_tag(own_xml, "Address")));

        const std::string explicit_group = trim(unescape_xml(find_tag(own_xml, "GroupName")));
        std::string child_group = parent_group;
        if (group_hdr == "1" || (addr_str.empty() && var_type.empty() && !nested_entries.empty())) {
            if (!desc.empty()) {
                child_group = parent_group.empty() ? desc : (parent_group + " / " + desc);
            }
            if (!nested_entries.empty()) {
                parse_entries_list(nested_entries, child_group, out_table);
            }
            continue;
        }

        if (var_type == "Auto Assembler Script") {
            std::string script_body = unescape_xml(find_tag(own_xml, "AssemblerScript"));
            std::string script_name = desc.empty() ? ("Script_" + std::to_string(out_table.scripts.size() + 1)) : desc;
            TableScript script;
            script.name = std::move(script_name);
            script.body = std::move(script_body);
            script.enabled = false;
            out_table.scripts.push_back(std::move(script));
            if (!nested_entries.empty()) parse_entries_list(nested_entries, parent_group, out_table);
            continue;
        }

        TableEntry entry;
        entry.description = desc;
        entry.type = parse_ce_variable_type(var_type);
        if (trim(find_tag(own_xml, "ShowAsSigned")) == "0") {
            entry.type = make_unsigned(entry.type);
        }
        if (!addr_str.empty()) parse_address_string(addr_str, entry.location);

        const std::string offsets_block = find_tag(own_xml, "Offsets");
        if (!offsets_block.empty()) {
            std::vector<int64_t> offs;
            for (const auto& o_tag : find_all_tags(offsets_block, "Offset")) {
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

        const std::string length_str = find_tag(own_xml, "Length");
        if (!length_str.empty()) {
            try { entry.length = std::stoull(length_str); } catch (...) {}
        }

        entry.group = !explicit_group.empty() ? explicit_group : parent_group;

        const std::string dd_block = unescape_xml(find_tag(own_xml, "DropDownList"));
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

        const std::string hk_block = find_tag(own_xml, "Hotkeys");
        if (!hk_block.empty()) {
            for (const auto& hk_tag : find_all_tags(hk_block, "Hotkey")) {
                if (auto hk = parse_ce_hotkey_tag(hk_tag)) {
                    entry.hotkeys.push_back(std::move(*hk));
                }
            }
        }

        const std::string sa_block = find_tag(own_xml, "SignatureAnchor");
        if (!sa_block.empty()) {
            SignatureAnchor sa;
            sa.module_name = unescape_xml(find_tag(sa_block, "Module"));
            sa.aob_pattern = trim(unescape_xml(find_tag(sa_block, "AOB")));
            try { sa.code_offset_hint = std::stoll(trim(find_tag(sa_block, "CodeOffsetHint"))); } catch (...) {}
            try { sa.disp_offset = std::stoull(trim(find_tag(sa_block, "DispOffset"))); } catch (...) {}
            try { sa.insn_length = std::stoull(trim(find_tag(sa_block, "InsnLength"))); } catch (...) {}
            sa.is_rip_relative = (trim(find_tag(sa_block, "RipRelative")) == "1");
            try { sa.struct_offset = std::stoll(trim(find_tag(sa_block, "StructOffset"))); } catch (...) {}
            if (!sa.aob_pattern.empty()) {
                entry.signature_anchor = std::move(sa);
            }
        }

        out_table.entries.push_back(std::move(entry));

        if (!nested_entries.empty()) {
            std::string sub_group = desc.empty() ? parent_group : (parent_group.empty() ? desc : (parent_group + " / " + desc));
            parse_entries_list(nested_entries, sub_group, out_table);
        }
    }
}

void write_ce_entry(std::ostringstream& ss, const TableEntry& e, int& next_id, const std::string& indent) {
    ss << indent << "<CheatEntry>\n";
    ss << indent << "  <ID>" << next_id++ << "</ID>\n";
    ss << indent << "  <Description>\"" << escape_xml(e.description.empty() ? "No Description" : e.description) << "\"</Description>\n";
    ss << indent << "  <VariableType>" << ce_variable_type_str(e.type) << "</VariableType>\n";
    if (is_unsigned_type(e.type)) {
        ss << indent << "  <ShowAsSigned>0</ShowAsSigned>\n";
    }
    if (e.type == scanner::DataType::String || e.type == scanner::DataType::String16) {
        if (e.length > 0) ss << indent << "  <Length>" << e.length << "</Length>\n";
    }

    std::ostringstream addr_ss;
    if (e.is_absolute()) {
        addr_ss << utils::format_address(e.location.base_offset);
    } else {
        addr_ss << "\"" << e.location.module_name << "\"+" << std::hex << e.location.base_offset << std::dec;
    }
    ss << indent << "  <Address>" << escape_xml(addr_ss.str()) << "</Address>\n";

    if (!e.location.offsets.empty()) {
        ss << indent << "  <Offsets>\n";
        for (auto it = e.location.offsets.rbegin(); it != e.location.offsets.rend(); ++it) {
            ss << indent << "    <Offset>";
            if (*it < 0) ss << "-" << std::hex << static_cast<uint64_t>(-*it);
            else ss << std::hex << static_cast<uint64_t>(*it);
            ss << std::dec << "</Offset>\n";
        }
        ss << indent << "  </Offsets>\n";
    }
    if (!e.group.empty()) {
        ss << indent << "  <GroupName>" << escape_xml(e.group) << "</GroupName>\n";
    }
    if (!e.dropdown.empty()) {
        ss << indent << "  <DropDownList>";
        bool first_dd = true;
        for (const auto& [k, v] : e.dropdown) {
            if (!first_dd) ss << "\n";
            ss << escape_xml(k) << ":" << escape_xml(v);
            first_dd = false;
        }
        ss << "</DropDownList>\n";
    }
    if (!e.hotkeys.empty()) {
        ss << indent << "  <Hotkeys>\n";
        for (const auto& h : e.hotkeys) {
            auto parsed = hal::parse_hotkey(h.keys);
            if (!parsed) continue;
            const auto vks = key_combo_to_ce_vks(*parsed);
            if (vks.empty()) continue;
            ss << indent << "    <Hotkey>\n";
            if (h.action == Hotkey::Action::Set) {
                ss << indent << "      <Action>Set Value</Action>\n";
                ss << indent << "      <Value>" << escape_xml(h.value) << "</Value>\n";
            } else if (h.action == Hotkey::Action::Add) {
                ss << indent << "      <Action>Increase Value</Action>\n";
                ss << indent << "      <Value>" << escape_xml(h.value) << "</Value>\n";
            } else {
                ss << indent << "      <Action>Toggle Activation</Action>\n";
            }
            ss << indent << "      <Keys>\n";
            for (int vk : vks) ss << indent << "        <Key>" << vk << "</Key>\n";
            ss << indent << "      </Keys>\n";
            ss << indent << "    </Hotkey>\n";
        }
        ss << indent << "  </Hotkeys>\n";
    }
    if (e.signature_anchor) {
        const auto& sa = *e.signature_anchor;
        ss << indent << "  <SignatureAnchor>\n";
        ss << indent << "    <Module>" << escape_xml(sa.module_name) << "</Module>\n";
        ss << indent << "    <AOB>" << escape_xml(sa.aob_pattern) << "</AOB>\n";
        ss << indent << "    <CodeOffsetHint>" << sa.code_offset_hint << "</CodeOffsetHint>\n";
        ss << indent << "    <DispOffset>" << sa.disp_offset << "</DispOffset>\n";
        ss << indent << "    <InsnLength>" << sa.insn_length << "</InsnLength>\n";
        ss << indent << "    <RipRelative>" << (sa.is_rip_relative ? 1 : 0) << "</RipRelative>\n";
        ss << indent << "    <StructOffset>" << sa.struct_offset << "</StructOffset>\n";
        ss << indent << "  </SignatureAnchor>\n";
    }
    ss << indent << "</CheatEntry>\n";
}

} // anonymous namespace

scanner::DataType parse_ce_variable_type(const std::string& type_str) {
    std::string t = trim(type_str);
    if (t == "Binary" || t == "Byte") return scanner::DataType::Int8;
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
    if (t == "Unicode" || t == "Unicode String" || t == "Wide String") return scanner::DataType::String16;
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

    const std::string root_entries = find_tag(xml_content, "CheatEntries");
    parse_entries_list(root_entries.empty() ? xml_content : root_entries, "", out_table);

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
    std::vector<const TableEntry*> ungrouped;
    std::vector<std::string> group_order;
    std::map<std::string, std::vector<const TableEntry*>> grouped;
    for (const auto& e : table.entries) {
        if (e.group.empty()) {
            ungrouped.push_back(&e);
        } else {
            if (!grouped.count(e.group)) group_order.push_back(e.group);
            grouped[e.group].push_back(&e);
        }
    }

    for (const auto* e : ungrouped) write_ce_entry(ss, *e, id, "    ");
    for (const auto& gname : group_order) {
        ss << "    <CheatEntry>\n";
        ss << "      <ID>" << id++ << "</ID>\n";
        ss << "      <Description>\"" << escape_xml(gname) << "\"</Description>\n";
        ss << "      <GroupHeader>1</GroupHeader>\n";
        ss << "      <CheatEntries>\n";
        for (const auto* e : grouped[gname]) write_ce_entry(ss, *e, id, "        ");
        ss << "      </CheatEntries>\n";
        ss << "    </CheatEntry>\n";
    }

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

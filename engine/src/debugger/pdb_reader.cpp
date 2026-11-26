#include "../../include/debugger/pdb_reader.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace nce::debugger {

namespace {

constexpr char kMsf7Magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";

uint32_t rd32(const uint8_t* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

uint16_t rd16(const uint8_t* p) {
    uint16_t v = 0;
    std::memcpy(&v, p, 2);
    return v;
}

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string read_cstr_bounded(const uint8_t* p, size_t max_len) {
    size_t len = 0;
    while (len < max_len && p[len] != '\0') ++len;
    return std::string(reinterpret_cast<const char*>(p), len);
}

} // namespace

bool PDBReader::load_file(const std::string& pdb_path) {
    std::ifstream in(pdb_path, std::ios::binary | std::ios::ate);
    if (!in) {
        m_last_error = "Could not open PDB file: " + pdb_path;
        m_loaded = false;
        return false;
    }
    const std::streamsize sz = in.tellg();
    if (sz <= 64 || sz > 512LL * 1024LL * 1024LL) {
        m_last_error = "Invalid PDB file size";
        m_loaded = false;
        return false;
    }
    in.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (!in.read(reinterpret_cast<char*>(buf.data()), sz)) {
        m_last_error = "Failed reading PDB file";
        m_loaded = false;
        return false;
    }
    return load_bytes(buf);
}

bool PDBReader::load_bytes(const std::vector<uint8_t>& file_bytes) {
    m_loaded = false;
    m_symbols.clear();
    m_last_error.clear();

    if (file_bytes.size() < 56 || std::memcmp(file_bytes.data(), kMsf7Magic, 32) != 0) {
        m_last_error = "Not a valid MSF 7.00 PDB file";
        return false;
    }

    const uint32_t block_size = rd32(file_bytes.data() + 32);
    const uint32_t num_blocks = rd32(file_bytes.data() + 40);
    const uint32_t dir_bytes  = rd32(file_bytes.data() + 44);
    const uint32_t dir_map_blk = rd32(file_bytes.data() + 52);

    if (block_size < 512 || (block_size & (block_size - 1)) != 0 ||
        static_cast<uint64_t>(num_blocks) * block_size > file_bytes.size() ||
        dir_bytes == 0 || dir_bytes > 32u * 1024u * 1024u) {
        m_last_error = "Corrupt MSF superblock dimensions";
        return false;
    }

    auto read_block_span = [&](const std::vector<uint32_t>& blocks, uint32_t byte_len, std::vector<uint8_t>& out) -> bool {
        out.clear();
        out.reserve(byte_len);
        size_t rem = byte_len;
        for (uint32_t b : blocks) {
            if (rem == 0) break;
            if (b >= num_blocks) return false;
            const size_t off = static_cast<size_t>(b) * block_size;
            const size_t take = std::min<size_t>(block_size, rem);
            if (off + take > file_bytes.size()) return false;
            out.insert(out.end(), file_bytes.data() + off, file_bytes.data() + off + take);
            rem -= take;
        }
        return rem == 0;
    };

    const uint32_t num_dir_blocks = (dir_bytes + block_size - 1) / block_size;
    if (static_cast<uint64_t>(dir_map_blk) * block_size + num_dir_blocks * 4ULL > file_bytes.size()) {
        m_last_error = "Invalid MSF directory map block";
        return false;
    }

    std::vector<uint32_t> dir_blocks;
    dir_blocks.reserve(num_dir_blocks);
    const uint8_t* map_ptr = file_bytes.data() + static_cast<size_t>(dir_map_blk) * block_size;
    for (uint32_t i = 0; i < num_dir_blocks; ++i) {
        dir_blocks.push_back(rd32(map_ptr + static_cast<size_t>(i) * 4));
    }

    std::vector<uint8_t> dir;
    if (!read_block_span(dir_blocks, dir_bytes, dir) || dir.size() < 4) {
        m_last_error = "Failed assembling MSF stream directory";
        return false;
    }

    const uint32_t num_streams = rd32(dir.data());
    if (num_streams > 4096 || 4 + static_cast<size_t>(num_streams) * 4 > dir.size()) {
        m_last_error = "Invalid MSF stream count";
        return false;
    }

    std::vector<uint32_t> stream_sizes(num_streams);
    size_t pos = 4;
    for (uint32_t s = 0; s < num_streams; ++s) {
        stream_sizes[s] = rd32(dir.data() + pos);
        pos += 4;
    }

    std::vector<std::vector<uint32_t>> stream_blocks(num_streams);
    for (uint32_t s = 0; s < num_streams; ++s) {
        const uint32_t sz = stream_sizes[s];
        if (sz == 0xFFFFFFFFu || sz == 0) continue;
        const uint32_t blks = (sz + block_size - 1) / block_size;
        if (pos + static_cast<size_t>(blks) * 4 > dir.size()) {
            m_last_error = "Truncated stream directory blocks";
            return false;
        }
        stream_blocks[s].reserve(blks);
        for (uint32_t b = 0; b < blks; ++b) {
            stream_blocks[s].push_back(rd32(dir.data() + pos));
            pos += 4;
        }
    }

    auto get_stream = [&](uint32_t idx, std::vector<uint8_t>& out) -> bool {
        if (idx >= num_streams) return false;
        const uint32_t sz = stream_sizes[idx];
        if (sz == 0xFFFFFFFFu || sz == 0) return false;
        return read_block_span(stream_blocks[idx], sz, out);
    };

    // Stream 3 = DBI Stream (contains symRecordStream + OptionalDbgHeader -> SectionHeaders)
    std::vector<uint8_t> dbi;
    if (!get_stream(3, dbi) || dbi.size() < 64) {
        m_last_error = "Missing DBI stream (stream 3)";
        return false;
    }

    const uint16_t sym_rec_stream = rd16(dbi.data() + 20);
    const uint32_t cb_mod_info    = rd32(dbi.data() + 24);
    const uint32_t cb_sec_con     = rd32(dbi.data() + 28);
    const uint32_t cb_sec_map     = rd32(dbi.data() + 32);
    const uint32_t cb_src_info    = rd32(dbi.data() + 36);
    const uint32_t cb_ts_map      = rd32(dbi.data() + 40);
    // +44 is MFCTypeServerIndex; OptionalDbgHeaderSize is +48, ECSubstreamSize is +52
    const uint32_t cb_opt_dbg     = rd32(dbi.data() + 48);
    const uint32_t cb_ec_info     = rd32(dbi.data() + 52);

    std::vector<uint32_t> section_rvas;
    const size_t opt_dbg_off = 64ULL + cb_mod_info + cb_sec_con + cb_sec_map + cb_src_info + cb_ts_map + cb_ec_info;
    if (cb_opt_dbg >= 12 && opt_dbg_off + 12 <= dbi.size()) {
        const uint16_t sec_hdr_stream = rd16(dbi.data() + opt_dbg_off + 10); // index 5 = DbgStreamType::SectionHdr
        std::vector<uint8_t> sec_bytes;
        if (sec_hdr_stream != 0xFFFF && get_stream(sec_hdr_stream, sec_bytes)) {
            for (size_t off = 0; off + 40 <= sec_bytes.size(); off += 40) {
                // IMAGE_SECTION_HEADER::VirtualAddress at offset +12
                section_rvas.push_back(rd32(sec_bytes.data() + off + 12));
            }
        }
    }

    std::vector<uint8_t> sym_bytes;
    if (!get_stream(sym_rec_stream, sym_bytes)) {
        m_last_error = "Missing CodeView symbol record stream";
        return false;
    }

    auto resolve_rva = [&](uint16_t seg, uint32_t off) -> uint32_t {
        if (seg >= 1 && static_cast<size_t>(seg - 1) < section_rvas.size()) {
            return section_rvas[static_cast<size_t>(seg - 1)] + off;
        }
        return off;
    };

    size_t sp = 0;
    while (sp + 4 <= sym_bytes.size()) {
        const uint16_t rec_len = rd16(sym_bytes.data() + sp);
        if (rec_len < 2 || sp + 2 + rec_len > sym_bytes.size()) break;
        const uint16_t rec_kind = rd16(sym_bytes.data() + sp + 2);
        const uint8_t* rec_body = sym_bytes.data() + sp + 4;
        const size_t body_len = rec_len - 2;

        if (rec_kind == 0x110E && body_len >= 11) { // S_PUB32
            PDBSymbol sym;
            sym.flags = rd32(rec_body + 0);
            sym.section_offset = rd32(rec_body + 4);
            sym.section = rd16(rec_body + 8);
            sym.rva = resolve_rva(sym.section, sym.section_offset);
            sym.name = read_cstr_bounded(rec_body + 10, body_len - 10);
            if (!sym.name.empty()) m_symbols.push_back(std::move(sym));
        } else if ((rec_kind == 0x1110 || rec_kind == 0x110F) && body_len >= 36) { // S_GPROC32 / S_LPROC32
            PDBSymbol sym;
            sym.section_offset = rd32(rec_body + 28);
            sym.section = rd16(rec_body + 32);
            sym.flags = rec_body[34];
            sym.rva = resolve_rva(sym.section, sym.section_offset);
            sym.name = read_cstr_bounded(rec_body + 35, body_len - 35);
            if (!sym.name.empty()) m_symbols.push_back(std::move(sym));
        }

        const size_t next = sp + 2 + rec_len;
        // CodeView records in PDB symbol stream are 4-byte aligned (if aligned) or sequential
        sp = next;
    }

    std::sort(m_symbols.begin(), m_symbols.end(), [](const PDBSymbol& a, const PDBSymbol& b) {
        return a.rva < b.rva;
    });
    m_loaded = true;
    return true;
}

std::optional<std::pair<PDBSymbol, uint32_t>> PDBReader::find_by_rva(uint32_t rva, uint32_t max_displacement) const {
    if (!m_loaded || m_symbols.empty()) return std::nullopt;
    auto it = std::upper_bound(m_symbols.begin(), m_symbols.end(), rva, [](uint32_t target, const PDBSymbol& sym) {
        return target < sym.rva;
    });
    if (it == m_symbols.begin()) return std::nullopt;
    --it;
    if (rva < it->rva) return std::nullopt;
    const uint32_t disp = rva - it->rva;
    if (disp > max_displacement) return std::nullopt;
    return std::make_pair(*it, disp);
}

std::vector<PDBSymbol> PDBReader::find_by_name(const std::string& query, size_t max_results) const {
    std::vector<PDBSymbol> out;
    if (!m_loaded || query.empty()) return out;
    const std::string q = lower_copy(query);
    for (const auto& s : m_symbols) {
        if (lower_copy(s.name).find(q) != std::string::npos) {
            out.push_back(s);
            if (out.size() >= max_results) break;
        }
    }
    return out;
}

std::string PDBReader::locate_companion_pdb(const std::string& module_path) {
    if (module_path.empty()) return {};
    std::error_code ec;
    std::filesystem::path p(module_path);
    std::filesystem::path pdb = p;
    pdb.replace_extension(".pdb");
    if (std::filesystem::exists(pdb, ec)) return pdb.string();
    return {};
}

} // namespace nce::debugger

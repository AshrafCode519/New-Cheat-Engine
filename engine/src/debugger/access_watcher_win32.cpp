#include "../../include/debugger/access_watcher.hpp"
#include "../../include/debugger/debug_coordinator.hpp"
#include "../../include/debugger/disassembler.hpp"
#include "../../include/utils/hex_utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace nce::debugger {

namespace {

void find_base(const DecodedInstruction& insn, std::string& base_reg, int64_t& base_off) {
    const std::string& ops = insn.operands;
    const size_t open = ops.find('[');
    const size_t close = ops.find(']', open);
    if (open == std::string::npos || close == std::string::npos) return;
    std::string inside = ops.substr(open + 1, close - open - 1);
    if (inside.find('*') != std::string::npos) return;

    std::string reg;
    size_t i = 0;
    while (i < inside.size() && std::isalnum(static_cast<unsigned char>(inside[i]))) reg += inside[i++];
    if (reg.empty() || !(reg[0] == 'r' || reg[0] == 'e')) return;
    base_reg = reg;
    base_off = 0;
    while (i < inside.size() && inside[i] == ' ') ++i;
    if (i < inside.size() && (inside[i] == '+' || inside[i] == '-')) {
        const int sign = inside[i] == '-' ? -1 : 1;
        ++i;
        std::string num = inside.substr(i);
        base_off = sign * static_cast<int64_t>(std::strtoll(num.c_str(), nullptr, 0));
    }
}

DecodedInstruction writer_before(const hal::IProcess& process, uintptr_t rip, bool is_64bit, uintptr_t& start_address) {
    constexpr size_t window = 15;
    if (rip <= window) return {};
    uint8_t buf[window] = {0};
    if (!process.read_raw(rip - window, buf, window)) return {};

    for (size_t back = window; back >= 1; --back) {
        const uintptr_t anchor = rip - back;
        uintptr_t cur = anchor;
        DecodedInstruction last;
        bool clean = true;
        for (int guard = 0; cur < rip && guard < 16; ++guard) {
            const size_t offset = cur - (rip - window);
            auto d = Disassembler::decode(buf + offset, window - offset, cur, is_64bit);
            if (d.length == 0 || d.mnemonic == "db") { clean = false; break; }
            last = d;
            cur += d.length;
        }
        if (clean && cur == rip && last.length > 0) {
            start_address = rip - last.length;
            return last;
        }
    }
    return {};
}

std::string locate(uintptr_t address, const std::vector<hal::ModuleInfo>& modules) {
    for (const auto& m : modules) {
        if (address >= m.base_address && address - m.base_address < m.size) {
            std::ostringstream ss;
            ss << m.name << "+0x" << std::uppercase << std::hex << (address - m.base_address);
            return ss.str();
        }
    }
    return utils::format_address(address);
}

} // anonymous namespace

uint64_t Registers::by_name(const std::string& name) const {
    static const std::vector<std::pair<const char*, uint64_t Registers::*>> table = {
        {"rax", &Registers::rax}, {"rbx", &Registers::rbx}, {"rcx", &Registers::rcx}, {"rdx", &Registers::rdx},
        {"rsi", &Registers::rsi}, {"rdi", &Registers::rdi}, {"rbp", &Registers::rbp}, {"rsp", &Registers::rsp},
        {"rip", &Registers::rip}, {"r8", &Registers::r8}, {"r9", &Registers::r9}, {"r10", &Registers::r10},
        {"r11", &Registers::r11}, {"r12", &Registers::r12}, {"r13", &Registers::r13}, {"r14", &Registers::r14},
        {"r15", &Registers::r15},
    };
    std::string key = name;
    if (!key.empty() && key[0] == 'e') key = "r" + key.substr(1);
    for (const auto& [n, member] : table) {
        if (key == n) return this->*member;
    }
    return 0;
}

uintptr_t AccessHit::base_pointer() const {
    return base_register.empty() ? 0 : static_cast<uintptr_t>(registers.by_name(base_register));
}

AccessWatcher::~AccessWatcher() { stop(); }

void AccessWatcher::set_coordinator(std::shared_ptr<DebugCoordinator> coordinator) {
    stop();
    m_shared_coordinator = std::move(coordinator);
}

bool AccessWatcher::start(std::shared_ptr<hal::IProcess> process, uintptr_t address, size_t size, WatchKind kind) {
    if (!process || !process->is_attached() || address == 0) return false;
    if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;

    m_process = std::move(process);
    m_modules = m_process->get_modules();
    m_address = address;
    m_size = size;
    m_kind = kind;

    std::shared_ptr<DebugCoordinator> coord = m_shared_coordinator;
    if (!coord) {
        if (!m_owned_coordinator) {
            m_owned_coordinator = std::make_shared<DebugCoordinator>(m_process);
        }
        coord = m_owned_coordinator;
    }

    if (!coord->is_attached()) {
        if (!coord->attach(coord->backend())) {
            return false;
        }
    }

    int slot = coord->add_hw_watch(address, size, kind, [this](uint32_t tid, uintptr_t rip, const Registers& regs) {
        on_hw_hit(tid, rip, regs);
    });
    if (slot < 0) return false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (std::find(m_watched_addresses.begin(), m_watched_addresses.end(), address) == m_watched_addresses.end()) {
            m_watched_addresses.push_back(address);
        }
        if (m_watched_addresses.size() == 1) {
            m_hits.clear();
        }
    }
    m_active = true;
    return true;
}

void AccessWatcher::stop_address(uintptr_t address) {
    auto coord = m_shared_coordinator ? m_shared_coordinator : m_owned_coordinator;
    if (coord) {
        coord->remove_hw_watch(address);
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_watched_addresses.erase(
        std::remove(m_watched_addresses.begin(), m_watched_addresses.end(), address),
        m_watched_addresses.end()
    );
    if (m_watched_addresses.empty()) {
        m_active = false;
        m_address = 0;
    } else {
        m_address = m_watched_addresses.back();
    }
}

void AccessWatcher::stop() {
    auto coord = m_shared_coordinator ? m_shared_coordinator : m_owned_coordinator;
    if (coord) {
        std::vector<uintptr_t> to_remove;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            to_remove = m_watched_addresses;
        }
        for (uintptr_t a : to_remove) {
            coord->remove_hw_watch(a);
        }
    }
    if (m_owned_coordinator) {
        m_owned_coordinator->detach();
        m_owned_coordinator.reset();
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_watched_addresses.clear();
    m_active = false;
    m_address = 0;
}

std::vector<uintptr_t> AccessWatcher::watched_addresses() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_watched_addresses;
}

void AccessWatcher::on_hw_hit(uint32_t, uintptr_t rip, const Registers& regs) {
    if (!m_process) return;

    const bool is_64 = (m_process->pointer_size() != 4);
    uintptr_t writer_addr = rip;
    DecodedInstruction decoded;
    if (m_kind == WatchKind::Execute) {
        uint8_t code[16] = {0};
        m_process->read_raw(rip, code, sizeof code);
        decoded = Disassembler::decode(code, sizeof code, rip, is_64);
        writer_addr = rip;
    } else {
        decoded = writer_before(*m_process, rip, is_64, writer_addr);
        if (decoded.length == 0) {
            uint8_t code[16] = {0};
            m_process->read_raw(rip, code, sizeof code);
            decoded = Disassembler::decode(code, sizeof code, rip, is_64);
            writer_addr = rip;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::find_if(m_hits.begin(), m_hits.end(), [&](const AccessHit& h) { return h.instruction == writer_addr; });
    if (it != m_hits.end()) {
        ++it->count;
        it->registers = regs;
    } else {
        AccessHit hit;
        hit.instruction = writer_addr;
        hit.location = locate(writer_addr, m_modules);
        hit.disassembly = decoded.mnemonic + (decoded.operands.empty() ? "" : " " + decoded.operands);
        hit.bytes = decoded.bytes;
        hit.registers = regs;
        hit.count = 1;
        find_base(decoded, hit.base_register, hit.base_offset);
        m_hits.push_back(std::move(hit));
    }
}

std::vector<AccessHit> AccessWatcher::hits() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AccessHit> out = m_hits;
    std::sort(out.begin(), out.end(), [](const AccessHit& a, const AccessHit& b) { return a.count > b.count; });
    return out;
}

void AccessWatcher::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hits.clear();
}

} // namespace nce::debugger

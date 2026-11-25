#include "../../include/debugger/causality_timeline.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>

namespace nce::debugger {

namespace {

uint64_t now_micros() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace

void CausalityTimeline::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
    m_cursor = 0;
    m_next_seq = 1;
}

void CausalityTimeline::set_max_events(size_t cap) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_max_events = std::max<size_t>(1, cap);
    if (m_events.size() > m_max_events) {
        const size_t drop = m_events.size() - m_max_events;
        m_events.erase(m_events.begin(), m_events.begin() + static_cast<std::ptrdiff_t>(drop));
        if (m_cursor >= m_events.size()) m_cursor = m_events.empty() ? 0 : m_events.size() - 1;
    }
}

std::vector<RegisterDelta> CausalityTimeline::compute_reg_deltas(const Registers& a, const Registers& b) {
    struct Slot { const char* name; uint64_t va; uint64_t vb; };
    const Slot slots[] = {
        {"rax", a.rax, b.rax}, {"rbx", a.rbx, b.rbx}, {"rcx", a.rcx, b.rcx}, {"rdx", a.rdx, b.rdx},
        {"rsi", a.rsi, b.rsi}, {"rdi", a.rdi, b.rdi}, {"rbp", a.rbp, b.rbp}, {"rsp", a.rsp, b.rsp},
        {"rip", a.rip, b.rip}, {"r8",  a.r8,  b.r8},  {"r9",  a.r9,  b.r9},  {"r10", a.r10, b.r10},
        {"r11", a.r11, b.r11}, {"r12", a.r12, b.r12}, {"r13", a.r13, b.r13}, {"r14", a.r14, b.r14},
        {"r15", a.r15, b.r15}, {"eflags", a.eflags, b.eflags}
    };
    std::vector<RegisterDelta> out;
    for (const auto& s : slots) {
        if (s.va != s.vb) out.push_back({s.name, s.va, s.vb});
    }
    return out;
}

std::vector<MemoryDeltaByte> CausalityTimeline::compute_mem_deltas(
    uintptr_t addr_a, const std::vector<uint8_t>& mem_a,
    uintptr_t addr_b, const std::vector<uint8_t>& mem_b)
{
    std::vector<MemoryDeltaByte> out;
    if (addr_a == 0 || addr_a != addr_b || mem_a.empty() || mem_b.empty()) return out;
    const size_t n = std::min(mem_a.size(), mem_b.size());
    for (size_t i = 0; i < n; ++i) {
        if (mem_a[i] != mem_b[i]) {
            out.push_back({addr_a + i, mem_a[i], mem_b[i]});
        }
    }
    return out;
}

void CausalityTimeline::push_event(
    uintptr_t instruction_address,
    std::string symbol,
    std::string disassembly,
    const Registers& regs,
    uint32_t thread_id,
    uintptr_t watch_address,
    std::vector<uint8_t> watch_bytes)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_events.size() >= m_max_events) {
        m_events.erase(m_events.begin());
    }

    CausalityEvent ev;
    ev.sequence = static_cast<size_t>(m_next_seq++);
    ev.timestamp_us = now_micros();
    ev.thread_id = thread_id;
    ev.instruction_address = instruction_address;
    ev.symbol = std::move(symbol);
    ev.disassembly = std::move(disassembly);
    ev.registers = regs;
    ev.watched_address = watch_address;
    ev.watched_bytes = std::move(watch_bytes);

    if (!m_events.empty()) {
        const auto& prev = m_events.back();
        ev.reg_deltas = compute_reg_deltas(prev.registers, ev.registers);
        ev.memory_deltas = compute_mem_deltas(
            prev.watched_address, prev.watched_bytes, ev.watched_address, ev.watched_bytes);
    }

    std::ostringstream ss;
    ss << "[#" << ev.sequence << "] ";
    if (!ev.symbol.empty()) ss << ev.symbol;
    else ss << "0x" << std::hex << ev.instruction_address << std::dec;
    if (!ev.disassembly.empty()) ss << "  " << ev.disassembly;
    if (!ev.reg_deltas.empty()) {
        ss << " | dRegs=" << ev.reg_deltas.size();
    }
    if (!ev.memory_deltas.empty()) {
        ss << " | dMem=" << ev.memory_deltas.size() << "B";
    }
    ev.summary = ss.str();

    m_events.push_back(std::move(ev));
    m_cursor = m_events.size() - 1;
}

void CausalityTimeline::record_trace(
    const std::vector<TraceEntry>& trace_entries,
    const hal::IProcess* process,
    uintptr_t watch_address,
    size_t watch_bytes_len)
{
    for (const auto& t : trace_entries) {
        std::vector<uint8_t> mem;
        if (process && watch_address != 0 && watch_bytes_len > 0) {
            mem.resize(watch_bytes_len);
            if (!process->read_raw(watch_address, mem.data(), mem.size())) mem.clear();
        }
        push_event(t.address, t.symbol, t.disassembly, t.registers, t.thread_id, watch_address, std::move(mem));
    }
}

void CausalityTimeline::record_hits(
    const std::vector<AccessHit>& hits,
    const hal::IProcess* process,
    uintptr_t watch_address,
    size_t watch_bytes_len)
{
    for (const auto& h : hits) {
        std::vector<uint8_t> mem;
        if (process && watch_address != 0 && watch_bytes_len > 0) {
            mem.resize(watch_bytes_len);
            if (!process->read_raw(watch_address, mem.data(), mem.size())) mem.clear();
        }
        push_event(h.instruction, h.location, h.disassembly, h.registers, 0, watch_address, std::move(mem));
    }
}

size_t CausalityTimeline::count() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events.size();
}

bool CausalityTimeline::empty() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events.empty();
}

size_t CausalityTimeline::cursor() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cursor;
}

bool CausalityTimeline::seek(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (index >= m_events.size()) return false;
    m_cursor = index;
    return true;
}

bool CausalityTimeline::step_backward() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_events.empty() || m_cursor == 0) return false;
    --m_cursor;
    return true;
}

bool CausalityTimeline::step_forward() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_events.empty() || m_cursor + 1 >= m_events.size()) return false;
    ++m_cursor;
    return true;
}

std::optional<CausalityEvent> CausalityTimeline::current() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_events.empty() || m_cursor >= m_events.size()) return std::nullopt;
    return m_events[m_cursor];
}

std::optional<CausalityEvent> CausalityTimeline::at(size_t index) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (index >= m_events.size()) return std::nullopt;
    return m_events[index];
}

std::vector<CausalityEvent> CausalityTimeline::events() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events;
}

TimelineDiff CausalityTimeline::diff_between(size_t from_idx, size_t to_idx) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    TimelineDiff d;
    if (from_idx >= m_events.size() || to_idx >= m_events.size()) return d;
    const auto& a = m_events[from_idx];
    const auto& b = m_events[to_idx];
    d.reg_deltas = compute_reg_deltas(a.registers, b.registers);
    d.memory_deltas = compute_mem_deltas(a.watched_address, a.watched_bytes, b.watched_address, b.watched_bytes);
    return d;
}

std::vector<size_t> CausalityTimeline::find_memory_mutations() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<size_t> indices;
    for (size_t i = 0; i < m_events.size(); ++i) {
        if (!m_events[i].memory_deltas.empty()) indices.push_back(i);
    }
    return indices;
}

std::string CausalityTimeline::format_report(size_t from_idx, size_t max_count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (from_idx >= m_events.size()) return "(no causality events)\n";
    const size_t end = std::min(m_events.size(), from_idx + max_count);
    std::ostringstream ss;
    for (size_t i = from_idx; i < end; ++i) {
        ss << (i == m_cursor ? "=> " : "   ") << m_events[i].summary << "\n";
    }
    return ss.str();
}

} // namespace nce::debugger

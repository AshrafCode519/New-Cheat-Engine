#include "../../include/debugger/step_debugger.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <sstream>

namespace nce::debugger {

namespace {

std::string format_symbol(uintptr_t addr, const std::vector<hal::ModuleInfo>& modules) {
    for (const auto& mod : modules) {
        if (addr >= mod.base_address && addr < mod.base_address + mod.size) {
            uintptr_t off = addr - mod.base_address;
            std::ostringstream ss;
            ss << mod.name << "+0x" << std::hex << std::uppercase << off;
            return ss.str();
        }
    }
    return utils::format_address(addr);
}

} // anonymous namespace

StepDebugger::StepDebugger(std::shared_ptr<hal::IProcess> process, std::shared_ptr<DebugCoordinator> coordinator)
    : m_process(std::move(process))
    , m_coord(std::move(coordinator))
{
    if (!m_coord) {
        m_coord = std::make_shared<DebugCoordinator>(m_process);
        m_owns_coord = true;
    }
}

StepDebugger::~StepDebugger() {
    if (m_owns_coord && m_coord) {
        m_coord->detach();
    }
}

void StepDebugger::set_coordinator(std::shared_ptr<DebugCoordinator> coordinator) {
    if (m_owns_coord && m_coord) {
        m_coord->detach();
    }
    m_coord = std::move(coordinator);
    m_owns_coord = (m_coord == nullptr);
    if (!m_coord) {
        m_coord = std::make_shared<DebugCoordinator>(m_process);
    }
}

bool StepDebugger::is_call_instruction(const DecodedInstruction& insn) {
    if (insn.mnemonic == "call") return true;
    if (!insn.bytes.empty()) {
        if (insn.bytes[0] == 0xE8) return true;
        if (insn.bytes[0] == 0xFF && insn.bytes.size() >= 2) {
            uint8_t modrm = insn.bytes[1];
            uint8_t reg = (modrm >> 3) & 0x07;
            if (reg == 2) return true;
        }
    }
    return false;
}

std::vector<StackFrame> StepDebugger::walk_stack(const hal::IProcess& proc,
                                                 uintptr_t rbp,
                                                 uintptr_t rsp,
                                                 const std::vector<hal::ModuleInfo>& modules,
                                                 size_t max_frames) {
    std::vector<StackFrame> frames;
    uintptr_t cur_rbp = rbp;

    uintptr_t top_ret = 0;
    if (rsp != 0 && proc.read_raw(rsp, &top_ret, sizeof(top_ret)) && top_ret > 0x10000) {
        StackFrame frame;
        frame.rbp = rbp;
        frame.return_address = top_ret;
        frame.symbol_name = format_symbol(top_ret, modules);
        for (const auto& mod : modules) {
            if (top_ret >= mod.base_address && top_ret < mod.base_address + mod.size) {
                frame.module_name = mod.name;
                frame.module_offset = top_ret - mod.base_address;
                break;
            }
        }
        frames.push_back(std::move(frame));
    }

    for (size_t i = 0; i < max_frames && cur_rbp != 0; ++i) {
        uintptr_t next_rbp = 0;
        uintptr_t ret_addr = 0;

        if (!proc.read_raw(cur_rbp, &next_rbp, sizeof(next_rbp))) break;
        if (!proc.read_raw(cur_rbp + sizeof(uintptr_t), &ret_addr, sizeof(ret_addr))) break;
        if (ret_addr <= 0x10000) break;

        StackFrame frame;
        frame.rbp = cur_rbp;
        frame.return_address = ret_addr;
        frame.symbol_name = format_symbol(ret_addr, modules);

        for (const auto& mod : modules) {
            if (ret_addr >= mod.base_address && ret_addr < mod.base_address + mod.size) {
                frame.module_name = mod.name;
                frame.module_offset = ret_addr - mod.base_address;
                break;
            }
        }

        frames.push_back(std::move(frame));
        if (next_rbp <= cur_rbp) break;
        cur_rbp = next_rbp;
    }

    return frames;
}

bool StepDebugger::attach(DebugBackend backend) {
    m_preferred_backend = backend;
    return m_coord ? m_coord->attach(backend) : false;
}

void StepDebugger::detach() {
    if (m_coord) m_coord->detach();
}

DebugBackend StepDebugger::backend() const noexcept {
    return m_coord ? m_coord->backend() : m_preferred_backend;
}

bool StepDebugger::set_breakpoint(uintptr_t address, const std::string& note, bool temporary,
                                  const std::string& condition, bool is_tracepoint) {
    return m_coord ? m_coord->set_breakpoint(address, note, temporary, condition, is_tracepoint) : false;
}

bool StepDebugger::remove_breakpoint(uintptr_t address) {
    return m_coord ? m_coord->remove_breakpoint(address) : false;
}

bool StepDebugger::enable_breakpoint(uintptr_t address, bool enable) {
    return m_coord ? m_coord->enable_breakpoint(address, enable) : false;
}

bool StepDebugger::has_breakpoint(uintptr_t address) const {
    return m_coord ? m_coord->has_breakpoint(address) : false;
}

std::vector<Breakpoint> StepDebugger::get_breakpoints() const {
    return m_coord ? m_coord->get_breakpoints() : std::vector<Breakpoint>{};
}

bool StepDebugger::resume() {
    return m_coord ? m_coord->resume() : false;
}

bool StepDebugger::pause() {
    return m_coord ? m_coord->pause() : false;
}

bool StepDebugger::step_into() {
    return m_coord ? m_coord->step_into() : false;
}

bool StepDebugger::step_over() {
    return m_coord ? m_coord->step_over() : false;
}

bool StepDebugger::step_out() {
    return m_coord ? m_coord->step_out() : false;
}

DebuggerState StepDebugger::state() const noexcept {
    return m_coord ? m_coord->state() : DebuggerState::Detached;
}

bool StepDebugger::is_attached() const noexcept {
    return m_coord ? m_coord->is_attached() : false;
}

bool StepDebugger::is_paused() const noexcept {
    return m_coord ? m_coord->is_paused() : false;
}

uintptr_t StepDebugger::current_rip() const noexcept {
    return m_coord ? m_coord->current_rip() : 0;
}

const Registers& StepDebugger::registers() const noexcept {
    static const Registers kEmpty{};
    return m_coord ? m_coord->registers() : kEmpty;
}

uint32_t StepDebugger::active_thread_id() const noexcept {
    return m_coord ? m_coord->active_thread_id() : 0;
}

const std::string& StepDebugger::last_error() const noexcept {
    static const std::string kEmpty{};
    return m_coord ? m_coord->last_error() : kEmpty;
}

std::vector<StackFrame> StepDebugger::get_call_stack(size_t max_frames) const {
    return m_coord ? m_coord->get_call_stack(max_frames) : std::vector<StackFrame>{};
}

std::vector<DecodedInstruction> StepDebugger::get_disassembly_around_rip(size_t count) const {
    return m_coord ? m_coord->get_disassembly_around_rip(count) : std::vector<DecodedInstruction>{};
}

std::vector<TraceEntry> StepDebugger::get_trace_log() const {
    return m_coord ? m_coord->get_trace_log() : std::vector<TraceEntry>{};
}

void StepDebugger::clear_trace_log() {
    if (m_coord) m_coord->clear_trace_log();
}

void StepDebugger::set_breakpoint_callback(DebugCoordinator::BreakpointCallback cb) {
    if (m_coord) m_coord->set_breakpoint_callback(std::move(cb));
}

} // namespace nce::debugger

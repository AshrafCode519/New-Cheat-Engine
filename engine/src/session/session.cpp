#include "../../include/session/session.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>

namespace nce::session {

namespace {

bool equals_ignore_case(const std::string& a, const std::string& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

std::string no_entry(size_t index, size_t size) {
    return "No table entry #" + std::to_string(index) + " (there are " + std::to_string(size) + ").";
}

} // anonymous namespace

// ---- TableKeeper ---------------------------------------------------------------------------------

TableKeeper::TableKeeper(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
    , m_freeze_thread([this] { freeze_loop(); })
{}

TableKeeper::~TableKeeper() {
    m_running = false;
    if (m_freeze_thread.joinable()) m_freeze_thread.join();
}

void TableKeeper::freeze_loop() {
    while (m_running) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_process->is_attached() && m_process->can_write()) {
                for (const auto& e : m_table.entries) {
                    if (e.frozen_value) table::write_entry(e, *e.frozen_value, *m_process, m_modules);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

size_t TableKeeper::attach(uint32_t pid, bool& attached) {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Absolute addresses belong to the old process; module-relative entries only resolve if the new one
    // has the same module, so they stay frozen
    size_t unfrozen = 0;
    for (auto& e : m_table.entries) {
        if (e.is_absolute() && e.frozen_value) {
            e.frozen_value.reset();
            ++unfrozen;
        }
    }
    attached = m_process->attach(pid);
    m_modules = attached ? m_process->get_modules() : std::vector<hal::ModuleInfo>{};
    return unfrozen;
}

void TableKeeper::detach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_process->detach();
    m_modules.clear();
}

std::vector<TableKeeper::ReconcileLine> TableKeeper::reconcile() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ReconcileLine> lines;
    if (!m_process->is_attached()) return lines;
    for (size_t i = 0; i < m_table.entries.size(); ++i) {
        auto& e = m_table.entries[i];
        if (e.alternatives.empty()) continue;
        lines.push_back({i, e.description.empty() ? e.location_string() : e.description,
                         table::reconcile(e, *m_process, m_modules)});
    }
    return lines;
}

Outcome TableKeeper::add_result(const scanner::ScanResults& results, size_t index, std::string description) {
    if (index >= results.count()) {
        return Outcome::fail("No result #" + std::to_string(index) + " (there are " + std::to_string(results.count()) + ").");
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.entries.push_back(table::make_entry(results.address(index), results.type(), m_modules,
                                                std::move(description), results.value_size()));
    const auto& e = m_table.entries.back();
    return Outcome::success("Added #" + std::to_string(m_table.entries.size() - 1) + ": " + e.location_string() +
                            (e.is_absolute() ? "  (heap address: only valid until the target restarts)" : ""));
}

Outcome TableKeeper::add_address(uintptr_t address, scanner::DataType type, std::string description) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.entries.push_back(table::make_entry(address, type, m_modules, std::move(description)));
    const auto& e = m_table.entries.back();
    return Outcome::success("Added #" + std::to_string(m_table.entries.size() - 1) + ": " + e.location_string() +
                            (e.is_absolute() ? "  (heap address: only valid until the target restarts)" : ""));
}

Outcome TableKeeper::add_pointer(const scanner::PointerPath& path, scanner::DataType type, std::string description) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.entries.push_back(table::make_entry(path, type, std::move(description)));
    return Outcome::success("Added #" + std::to_string(m_table.entries.size() - 1) + ": " +
                            m_table.entries.back().location_string());
}

Outcome TableKeeper::set_value(size_t index, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    auto& e = m_table.entries[index];
    if (!m_process->is_attached() || !table::write_entry(e, value, *m_process, m_modules)) {
        return Outcome::fail("Could not write '" + value + "' to #" + std::to_string(index) +
                             " (invalid value, text too long, aob entry, or address not resolvable).");
    }
    if (e.frozen_value) e.frozen_value = value; // keep a frozen entry at the new value
    return Outcome::success("#" + std::to_string(index) + " set to " + value);
}

Outcome TableKeeper::freeze(size_t index, std::optional<std::string> value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    auto& e = m_table.entries[index];
    if (!value) {
        auto current = m_process->is_attached() ? table::read_entry(e, *m_process, m_modules) : std::nullopt;
        if (!current) return Outcome::fail("Can't read #" + std::to_string(index) + " to freeze it; give a value.");
        value = value_text(*current);
    }
    e.frozen_value = *value;
    return Outcome::success("#" + std::to_string(index) + " frozen at " + *value);
}

Outcome TableKeeper::unfreeze(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    m_table.entries[index].frozen_value.reset();
    return Outcome::success("#" + std::to_string(index) + " unfrozen.");
}

size_t TableKeeper::unfreeze_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;
    for (auto& e : m_table.entries) {
        if (e.frozen_value) {
            e.frozen_value.reset();
            ++count;
        }
    }
    return count;
}

Outcome TableKeeper::remove(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    m_table.entries.erase(m_table.entries.begin() + static_cast<std::ptrdiff_t>(index));
    return Outcome::success("Removed #" + std::to_string(index) + ".");
}

Outcome TableKeeper::save(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_table.process_name.empty() && !m_modules.empty()) m_table.process_name = m_modules.front().name;
    if (!table::save_table(path, m_table)) return Outcome::fail("Could not write " + path + ".");
    return Outcome::success("Saved " + std::to_string(m_table.entries.size()) + " entries to " + path + ".");
}

Outcome TableKeeper::load(const std::string& path) {
    auto loaded = table::load_table(path);
    if (!loaded) return Outcome::fail("Could not read a table from " + path + ".");
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table = std::move(*loaded);
    size_t frozen = 0;
    for (const auto& e : m_table.entries) frozen += e.frozen_value ? 1 : 0;
    return Outcome::success("Loaded " + std::to_string(m_table.entries.size()) + " entries for '" + m_table.process_name +
                            "'" + (frozen ? " (" + std::to_string(frozen) + " frozen)" : std::string()) + ".");
}

std::optional<table::TableEntry> TableKeeper::entry(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return std::nullopt;
    return m_table.entries[index];
}

Outcome TableKeeper::make_permanent(size_t index, const table::TableEntry& scanned,
                                    const std::vector<scanner::PointerPath>& paths) {
    if (paths.empty()) {
        return Outcome::fail("No static pointer path leads to it; it stays valid only until the target restarts.");
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail("The table changed during the search; try again.");
    auto& e = m_table.entries[index];
    const bool same = e.location.module_name == scanned.location.module_name &&
                      e.location.base_offset == scanned.location.base_offset &&
                      e.location.offsets == scanned.location.offsets;
    if (!same) return Outcome::fail("The table changed during the search; try again.");

    table::make_permanent(e, paths, *m_process, m_modules);
    return Outcome::success("#" + std::to_string(index) + " is permanent: " + e.location_string() + " (+" +
                            std::to_string(e.alternatives.size()) + " other paths that find it after a restart).");
}

size_t TableKeeper::size() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_table.entries.size();
}

std::vector<hal::ModuleInfo> TableKeeper::modules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_modules;
}

void TableKeeper::refresh_modules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_process->is_attached()) m_modules = m_process->get_modules();
}

std::string describe_reconcile(const table::ReconcileResult& r) {
    std::string text;
    if (r.resolved == 0) {
        return "none of its " + std::to_string(r.paths) + " paths resolve here (another program?)";
    }
    if (r.ambiguous) {
        return "close vote (" + std::to_string(r.agreeing) + " of " + std::to_string(r.resolved) + " paths agree on " +
               utils::format_address(r.address) + "): check the value; nothing dropped";
    }
    text = "found at " + utils::format_address(r.address) + " (" + std::to_string(r.agreeing) + " of " +
           std::to_string(r.resolved) + " paths lead there";
    if (r.context_words > 0) {
        text += "; surroundings match " + std::to_string(r.context_matches) + "/" + std::to_string(r.context_words) + " words";
    }
    if (r.value_matches) text += "; same value as when saved";
    if (r.by_context) text += "; chosen by its surroundings over the most-voted address";
    text += ")";
    if (r.changed) text += ", kept those paths";
    return text;
}

// ---- Session -------------------------------------------------------------------------------------

Session::Session(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
    , m_table(std::make_unique<TableKeeper>(m_process))
{}

Session::AttachReport Session::attach(uint32_t pid) {
    AttachReport report;
    report.unfrozen = m_table->attach(pid, report.ok);
    m_scans.clear();
    m_noise.reset();
    if (!report.ok) {
        m_scanner.reset();
        m_scans.set_scanner(nullptr, nullptr);
        return report;
    }

    m_scanner = std::make_shared<scanner::MemoryScanner>(m_process);
    m_scans.set_scanner(m_scanner, m_process);
    report.read_only = !m_process->can_write();
    report.reconciled = m_table->reconcile();
    return report;
}

void Session::detach() {
    m_table->detach();
    m_scans.clear();
    m_scans.set_scanner(nullptr, nullptr);
    m_scanner.reset();
    m_noise.reset();
}

std::optional<hal::ProcessInfo> Session::find_restart() const {
    const std::string name = m_process->name();
    if (name.empty() || m_process->get_pid() == 0) return std::nullopt;
    for (const auto& p : hal::IProcess::list_processes()) {
        if (p.pid != m_process->get_pid() && equals_ignore_case(p.name, name)) return p;
    }
    return std::nullopt;
}

std::shared_ptr<scanner::NoiseMap> Session::learn_noise(const scanner::NoiseOptions& options,
                                                        const std::atomic<bool>* stop) const {
    auto noise = std::make_shared<scanner::NoiseMap>();
    noise->learn(*m_process, options, stop);
    return noise;
}

void Session::set_noise(std::shared_ptr<scanner::NoiseMap> noise) {
    m_noise = std::move(noise);
    if (m_scanner) m_scanner->set_noise_map(m_noise);
}

std::string Session::describe_noise() const {
    if (!m_noise || m_noise->empty()) return "none known";
    std::string text = std::to_string(m_noise->noisy_slots()) + " addresses ignored";
    if (m_noise->skipped_bytes() > 0) text += ", " + format_size(m_noise->skipped_bytes()) + " skipped";
    return text;
}

void Session::refresh(view::MemoryView& view) {
    if (attached()) view.refresh(*m_process, m_table->modules(), m_noise.get());
}

std::unique_ptr<scanner::ValueTracker> Session::new_tracker(std::vector<scanner::DataType> types) const {
    auto tracker = std::make_unique<scanner::ValueTracker>(m_process, std::move(types));
    tracker->set_noise_map(m_noise);
    return tracker;
}

std::vector<scanner::PointerPath> Session::find_permanent_paths(const table::TableEntry& entry) {
    return table::find_permanent_paths(entry, m_process, m_table->modules());
}

} // namespace nce::session

#pragma once

// Internal helper shared by the scanners (not part of the engine's public headers)

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

namespace nce::scanner::detail {

// Runs body(state, i) for every i in [0, count) on up to thread_count threads; each thread gets
// its own state from make_state(). The first exception (e.g. bad_alloc on huge result sets) stops
// the remaining work and is rethrown on the calling thread instead of terminating the process.
template <typename MakeState, typename Body>
void parallel_for(size_t count, size_t thread_count, MakeState&& make_state, Body&& body) {
    std::atomic<size_t> next_index{0};
    std::atomic<bool> failed{false};
    std::mutex error_mutex;
    std::exception_ptr error;

    auto worker = [&]() {
        try {
            auto state = make_state();
            while (!failed) {
                const size_t i = next_index.fetch_add(1);
                if (i >= count) break;
                body(state, i);
            }
        } catch (...) {
            std::lock_guard<std::mutex> lock(error_mutex);
            if (!error) error = std::current_exception();
            failed = true;
        }
    };

    const size_t worker_count = std::clamp<size_t>(thread_count, 1, std::max<size_t>(1, count));
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    if (error) std::rethrow_exception(error);
}

inline size_t default_thread_count() {
    return std::max(1u, std::thread::hardware_concurrency());
}

} // namespace nce::scanner::detail

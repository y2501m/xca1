#pragma once

#include "zipcrypto_input.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

struct GpuRunResult {
    enum class Outcome { Completed, Found, Stopped, Fallback };
    Outcome outcome = Outcome::Fallback;
    std::string password;
    std::string deviceName;
    std::string detail;
};

// This backend implements ONLY legacy ZIP / ZipCrypto header filtering.
// For each GPU-filter match, verifyPassword must fully verify via libzip.
// A Fallback result means CPU must search from the beginning (GPU results
// must never be treated as a successful password without full verification).
GpuRunResult runZipCryptoGpu(
    const ZipCryptoInput& input,
    const std::string& charset,
    int maxPasswordLength,
    std::atomic<bool>& stopRequested,
    std::atomic<std::uint64_t>& triedCount,
    const std::function<bool(const std::string&)>& verifyPassword);

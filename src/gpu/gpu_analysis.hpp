#pragma once

#include "zipcrypto_input.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// GPU reports compact offset batches; the host runs libzip verification.
struct GpuCandidateBatch {
    std::string prefix;
    std::uint64_t startIndex = 0;
    std::uint32_t suffixLength = 0;
    std::vector<std::uint32_t> offsets;
};

struct GpuRunResult {
    enum class Outcome { Completed, Found, Stopped, Fallback };
    Outcome outcome = Outcome::Fallback;
    std::string password;
    std::string deviceName;
    std::string detail;
    bool deflatePrefilterEnabled = false;
    bool storeCrcPrefilterEnabled = false;
    std::uint32_t storeCrcBytes = 0;
    std::uint64_t headerPasses = 0;
    std::uint64_t prefilterPasses = 0;
};

// Covers password lengths 1..16 by combining an up-to-8-character GPU suffix
// with a host-side prefix. Progress is reported as an *absolute* double count,
// avoiding 64-bit overflow and floating-point stagnation from tiny increments.
GpuRunResult runZipCryptoGpu(
    const ZipCryptoInput& input,
    const std::string& charset,
    int maxPasswordLength,
    std::atomic<bool>& stopRequested,
    std::atomic<std::uint64_t>& triedCount,
    const std::function<bool(GpuCandidateBatch&&)>& submitBatch,
    const std::function<bool()>& shouldInterrupt,
    const std::function<void(double)>& reportCompleted);

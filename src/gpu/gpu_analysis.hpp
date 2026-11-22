#pragma once

#include "zipcrypto_input.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct GpuRunResult {
    enum class Outcome { Completed, Found, Stopped, Fallback };
    Outcome outcome = Outcome::Fallback;
    std::string password;
    std::string deviceName;
    std::string detail;
    // Counts are device-side measurements, not CPU libzip verification counts.
    std::uint64_t headerPasses = 0;
    std::uint64_t prefilterPasses = 0;
    bool deflatePrefilterEnabled = false;
    bool storeCrcPrefilterEnabled = false;
    std::uint32_t storeCrcBytes = 0;
};

// GPU returns batches of compact candidate offsets, not millions of strings.
// This keeps the GPU producer light and makes CPU queueing amortized O(1)
// per batch. No candidate is accepted as a password until libzip validates it.
struct GpuCandidateBatch {
    std::string prefix;
    std::uint64_t startIndex = 0;
    std::uint32_t suffixLength = 0;
    std::vector<std::uint32_t> offsets;
};

// submitBatch returns true when the whole batch was safely queued.
// False requests interruption; caller must distinguish Stop, Found or Failure.
// The consumer must eventually verify every submitted candidate on Completed.
GpuRunResult runZipCryptoGpu(
    const ZipCryptoInput& input,
    const std::string& charset,
    int maxPasswordLength,
    std::atomic<bool>& stopRequested,
    std::atomic<std::uint64_t>& triedCount,
    const std::function<bool(GpuCandidateBatch&&)>& submitBatch,
    const std::function<bool()>& shouldInterrupt = {});

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <zip.h>

struct ZipCryptoInput;
struct GpuRunResult;

class Analysis {
public:
    Analysis(std::string filePath, int maxPasswordLen);

    // Returns the recovered password; an empty string means no password was found.
    std::string run();
    void requestStop() noexcept;

    // Read statusMessage() only after the analysis thread has finished.
    const std::string& statusMessage() const noexcept { return statusMessage_; }

    std::atomic<std::uint64_t> triedCount{0};
    std::atomic<std::uint64_t> totalCount{0}; // Saturated to UINT64_MAX when necessary.
    std::atomic<double> totalCountEstimate{0.0}; // UI progress for large search spaces.
    std::atomic<bool> isRunning{false};
    std::atomic<bool> found{false};
    // 0=detecting, 1=CPU, 2=GPU; used for display only.
    std::atomic<int> activeBackend{0};

private:
    struct TargetEntry {
        zip_uint64_t index = 0;
        zip_uint64_t uncompressedSize = 0;
        bool sizeKnown = false;
        zip_uint16_t encryptionMethod = ZIP_EM_NONE;
    };

    bool selectEncryptedEntry(zip_t* archive, TargetEntry& target, bool preferZipCrypto);
    void initializeProgress();
    GpuRunResult runGpuParallel(const ZipCryptoInput& input, const TargetEntry& target);
    void runCpu(const TargetEntry& target);
    void worker(const TargetEntry& target,
                std::atomic<std::size_t>& nextTask,
                std::size_t taskCount);
    bool search(zip_t* archive, const TargetEntry& target,
                std::string& attempt, int remainingDigits);
    bool testPassword(zip_t* archive, const TargetEntry& target,
                      const std::string& password, bool countAttempt = true);
    void saveResult(const std::string& candidate);
    bool shouldStop() const noexcept;

    std::string filePath_;
    int maxPasswordLen_;
    const std::string charset_ =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|";

    std::atomic<bool> stopRequested_{false};
    std::string result_;
    std::string statusMessage_;
    std::string workerError_;
    std::mutex resultMutex_;
    std::mutex workerErrorMutex_;
};

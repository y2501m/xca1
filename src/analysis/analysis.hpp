#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>
#include <zip.h>

struct ZipCryptoInput;
struct GpuRunResult;

class Analysis {
public:
    Analysis(std::string filePath, int maxPasswordLen);

    // Empty result means no CONFIRMED password was found.
    std::string run();
    void requestStop() noexcept;

    // Read only after the analysis thread has finished.
    const std::string& statusMessage() const noexcept { return statusMessage_; }

    // Safe to poll from the UI while the analysis thread is running.
    struct CandidateSnapshot {
        std::uint64_t total = 0;
        std::vector<std::string> passwords; // UI sample only, all candidates are journaled
        std::string journalPath;
    };
    CandidateSnapshot candidateSnapshot() const;

    std::atomic<std::uint64_t> triedCount{0};
    std::atomic<std::uint64_t> totalCount{0};
    std::atomic<double> totalCountEstimate{0.0};
    std::atomic<double> completedCountEstimate{0.0}; // GPU supports >uint64 totals
    std::atomic<bool> isRunning{false};
    std::atomic<bool> found{false};
    // 0=detecting, 1=CPU, 2=GPU.
    std::atomic<int> activeBackend{0};

private:
    struct TargetEntry {
        zip_uint64_t index = 0;
        zip_uint64_t uncompressedSize = 0;
        bool sizeKnown = false;
        zip_uint16_t encryptionMethod = ZIP_EM_NONE;
    };

    bool selectEncryptedEntry(zip_t* archive, TargetEntry& target, bool preferZipCrypto);
    GpuRunResult runGpuParallel(const ZipCryptoInput& input, const TargetEntry& target);
    void initializeProgress();
    void runCpu(const TargetEntry& target);
    void worker(const TargetEntry& target,
                std::atomic<std::size_t>& nextTask,
                std::size_t taskCount);
    bool search(zip_t* archive, const TargetEntry& target,
                std::string& attempt, int remainingDigits);
    enum class CheckResult { Rejected, Unconfirmed, Confirmed };
    CheckResult checkPassword(zip_t* archive, const TargetEntry& target,
                              const std::string& password, bool countAttempt = true);
    void handleCheckResult(const std::string& password, CheckResult result);
    bool openCandidateJournal();
    void addCpuAttempt();
    void saveResult(const std::string& candidate);
    void recordCandidate(const std::string& password);
    void setFailure(const std::string& error);
    bool shouldStop() const noexcept;

    static constexpr std::size_t kMaxSavedCandidates = 10;

    std::string filePath_;
    int maxPasswordLen_;
    const std::string charset_ =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|";

    std::atomic<bool> stopRequested_{false};
    std::uint64_t candidateCount_ = 0; // Guarded by resultMutex_.
    std::vector<std::string> candidatePasswords_; // Guarded by resultMutex_.
    std::string candidateJournalPath_; // Set before threads are launched.
    std::ofstream candidateJournal_; // All writes under resultMutex_.
    std::string result_;
    std::string statusMessage_;
    std::string workerError_;
    mutable std::mutex resultMutex_;
    std::mutex workerErrorMutex_;
};

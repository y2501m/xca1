#include "analysis.hpp"
#include "../gpu/gpu_detector.hpp"
#include "../gpu/gpu_analysis.hpp"
#include "../gpu/zipcrypto_input.hpp"
#include "../logger/logger.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <thread>
#include <utility>

namespace {
struct ZipDeleter {
    void operator()(zip_t* archive) const noexcept {
        if (archive) zip_discard(archive); // Read-only handle; never write the ZIP file.
    }
};
using ZipHandle = std::unique_ptr<zip_t, ZipDeleter>;

// Only encrypted regular files can independently confirm a ZIP password.
bool isEncryptedRegularEntry(const zip_stat_t& stat) {
    if (!(stat.valid & ZIP_STAT_ENCRYPTION_METHOD) ||
        stat.encryption_method == ZIP_EM_NONE) return false;
    if ((stat.valid & ZIP_STAT_NAME) && stat.name) {
        const std::size_t n = std::strlen(stat.name);
        if (n && stat.name[n - 1] == '/') return false;
    }
    return true;
}

} // namespace

Analysis::Analysis(std::string filePath, int maxPasswordLen)
    : filePath_(std::move(filePath)), maxPasswordLen_(maxPasswordLen) {}

void Analysis::requestStop() noexcept {
    stopRequested_.store(true, std::memory_order_release);
}

bool Analysis::shouldStop() const noexcept {
    return stopRequested_.load(std::memory_order_relaxed) ||
           found.load(std::memory_order_acquire);
}

void Analysis::initializeProgress() {
    triedCount.store(0, std::memory_order_relaxed);
    totalCount.store(0, std::memory_order_relaxed);
    totalCountEstimate.store(0.0, std::memory_order_relaxed);
    completedCountEstimate.store(0.0, std::memory_order_relaxed);

    const std::uint64_t base = static_cast<std::uint64_t>(charset_.size());
    std::uint64_t power = 1;
    std::uint64_t sum = 0;
    double approximatePower = 1.0;
    double approximateSum = 0.0;
    bool overflow = false;

    for (int len = 1; len <= maxPasswordLen_; ++len) {
        approximatePower *= static_cast<double>(base);
        approximateSum += approximatePower;

        if (!overflow) {
            if (power > std::numeric_limits<std::uint64_t>::max() / base) {
                overflow = true;
            } else {
                power *= base;
                if (sum > std::numeric_limits<std::uint64_t>::max() - power) {
                    overflow = true;
                } else {
                    sum += power;
                }
            }
        }
    }

    totalCount.store(overflow ? std::numeric_limits<std::uint64_t>::max() : sum,
                     std::memory_order_release);
    totalCountEstimate.store(approximateSum, std::memory_order_release);
    if (overflow) {
        Logger::getInstance().log(
            LogLevel::Info,
            "Password search space exceeds uint64_t; exact total was capped.");
    }
}

bool Analysis::selectEncryptedEntry(zip_t* archive, TargetEntry& target, bool preferZipCrypto) {
    const zip_int64_t entryCount = zip_get_num_entries(archive, 0);
    if (entryCount <= 0) {
        statusMessage_ = "ZIP archive contains no files.";
        return false;
    }

    bool sawEncrypted = false;
    bool foundSupportedEntry = false;
    zip_uint64_t bestSize = std::numeric_limits<zip_uint64_t>::max();
    bool bestIsZipCrypto = false;

    for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(entryCount); ++i) {
        zip_stat_t stat;
        zip_stat_init(&stat);
        if (zip_stat_index(archive, i, 0, &stat) != 0 ||
            !(stat.valid & ZIP_STAT_ENCRYPTION_METHOD) ||
            stat.encryption_method == ZIP_EM_NONE) {
            continue;
        }

        // Directory entries are not useful verification targets.
        if ((stat.valid & ZIP_STAT_NAME) && stat.name) {
            const std::size_t nameLength = std::strlen(stat.name);
            if (nameLength != 0 && stat.name[nameLength - 1] == '/') continue;
        }

        sawEncrypted = true;
        // libzip argument 1 checks support for decryption (per its documented API).
        if (!zip_encryption_method_supported(
                static_cast<zip_int16_t>(stat.encryption_method), 1)) {
            continue;
        }
        if ((stat.valid & ZIP_STAT_COMP_METHOD) &&
            !zip_compression_method_supported(
                static_cast<zip_int32_t>(stat.comp_method), 1)) {
            continue;
        }

        // A smaller non-empty entry is generally quicker to validate fully.
        // Empty or unknown-size entries are a last resort.
        const bool hasSize = (stat.valid & ZIP_STAT_SIZE) != 0;
        const zip_uint64_t rank = hasSize && stat.size > 0
            ? stat.size : std::numeric_limits<zip_uint64_t>::max();

        const bool isZipCrypto = stat.encryption_method == ZIP_EM_TRAD_PKWARE;
        const bool preferThis = preferZipCrypto && isZipCrypto != bestIsZipCrypto;
        if (!foundSupportedEntry ||
            (preferThis && isZipCrypto) ||
            (!preferThis && rank < bestSize)) {
            bestSize = rank;
            target.index = i;
            target.uncompressedSize = stat.size;
            target.sizeKnown = hasSize;
            target.encryptionMethod = stat.encryption_method;
            bestIsZipCrypto = isZipCrypto;
            foundSupportedEntry = true;
        }
    }

    if (!foundSupportedEntry) {
        statusMessage_ = sawEncrypted
            ? "The encrypted entries use an unsupported encryption or compression method."
            : "No encrypted file was found in the ZIP archive.";
        return false;
    }

    return true;
}

std::string Analysis::run() {
    // The UI only reads statusMessage() after the caller signals completion.
    isRunning.store(true, std::memory_order_release);
    found.store(false, std::memory_order_release);
    activeBackend.store(0, std::memory_order_release);
    // stopRequested_ starts false in the constructor; do not overwrite a shutdown request.
    result_.clear();
    statusMessage_.clear();
    workerError_.clear();
    {
        std::lock_guard<std::mutex> lock(resultMutex_);
        candidateCount_ = 0;
        candidatePasswords_.clear();
        candidateJournalPath_.clear();
    }
    initializeProgress();

    try {
        if (maxPasswordLen_ < 1 || maxPasswordLen_ > 16 || charset_.empty()) {
            statusMessage_ = "Password length must be in the range 1..16.";
        } else {
            int errorCode = 0;
            ZipHandle archive(zip_open(filePath_.c_str(), ZIP_RDONLY, &errorCode));
            if (!archive) {
                statusMessage_ = "Failed to open ZIP archive (error code " +
                                 std::to_string(errorCode) + ").";
            } else {
                const GpuDetection detectedGpu = detectOpenCLGpu();
                TargetEntry target;
                if (selectEncryptedEntry(archive.get(), target, detectedGpu.available)) {
                    Logger::getInstance().log(
                        LogLevel::Info,
                        "Selected encrypted ZIP entry index: " +
                            std::to_string(target.index));

                    // All potentially valid ZipCrypto passwords are journaled when
                    // they cannot be independently confirmed. Do not impose a 10-
                    // candidate cap on the actual results. Failed journal creation
                    // aborts instead of silently discarding candidate passwords.
                    if (target.encryptionMethod == ZIP_EM_TRAD_PKWARE &&
                        !openCandidateJournal()) {
                        statusMessage_ = workerError_;
                        isRunning.store(false, std::memory_order_release);
                        return {};
                    }
                    bool cpuFallback = true;
                    if (detectedGpu.available &&
                        target.encryptionMethod == ZIP_EM_TRAD_PKWARE &&
                        !stopRequested_.load(std::memory_order_relaxed)) {
                        ZipCryptoInput gpuInput;
                        std::string reason;
                        if (prepareZipCryptoInput(filePath_, archive.get(), target.index,
                                                  gpuInput, reason)) {
                            if (!gpuInput.storeCrcPrefilterEnabled &&
                                !gpuInput.storeCrcSkipReason.empty()) {
                                Logger::getInstance().log(
                                    LogLevel::Info, "Store CRC prefilter skipped: " +
                                    gpuInput.storeCrcSkipReason);
                            }
                            Logger::getInstance().log(
                                LogLevel::Info, "Attempting OpenCL GPU analysis: " +
                                detectedGpu.deviceName);
                            activeBackend.store(2, std::memory_order_release);
                            const GpuRunResult gpu = runGpuParallel(gpuInput, target);
                            if (gpu.outcome == GpuRunResult::Outcome::Found) {
                                // runGpuParallel workers already stored the result safely.
                                cpuFallback = false;
                            } else if (gpu.outcome == GpuRunResult::Outcome::Completed ||
                                       gpu.outcome == GpuRunResult::Outcome::Stopped) {
                                cpuFallback = false;
                            } else {
                                reason = gpu.detail;
                            }
                            if (gpu.outcome != GpuRunResult::Outcome::Fallback) {
                                Logger::getInstance().log(
                                    LogLevel::Info, "OpenCL GPU backend used: " +
                                    gpu.deviceName);
                            }
                        }
                        if (cpuFallback) {
                            Logger::getInstance().log(
                                LogLevel::Info, "GPU backend unavailable: " + reason +
                                ". Falling back to CPU from the beginning.");
                        }
                    } else if (detectedGpu.available) {
                        Logger::getInstance().log(
                            LogLevel::Info,
                            "Selected ZIP encryption is not supported by GPU; using CPU.");
                    } else {
                        Logger::getInstance().log(
                            LogLevel::Info, "OpenCL GPU unavailable: " +
                            detectedGpu.reason + ". Using CPU.");
                    }

                    if (cpuFallback && !stopRequested_.load(std::memory_order_relaxed)) {
                        // A failed partial GPU run must restart the entire search on CPU.
                        triedCount.store(0, std::memory_order_release);
                        completedCountEstimate.store(0.0, std::memory_order_release);
                        activeBackend.store(1, std::memory_order_release);
                        archive.reset(); // CPU threads each create a separate zip_t.
                        const auto cpuStarted = std::chrono::steady_clock::now();
                        runCpu(target);
                        const double cpuSeconds = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - cpuStarted).count();
                        const auto cpuAttempts = triedCount.load(std::memory_order_relaxed);
                        std::ostringstream cpuProfile;
                        cpuProfile << std::fixed << std::setprecision(2)
                                   << "CPU profile: attempts=" << cpuAttempts
                                   << ", elapsed_s=" << cpuSeconds
                                   << ", passwords_per_s=" <<
                                      (cpuSeconds > 0.0 ?
                                       static_cast<double>(cpuAttempts) / cpuSeconds : 0.0);
                        Logger::getInstance().log(LogLevel::Info, cpuProfile.str());
                    }

                    if (!workerError_.empty()) {
                        statusMessage_ = workerError_;
                        const auto snapshot = candidateSnapshot();
                        if (!snapshot.journalPath.empty())
                            statusMessage_ += "\nSaved candidate list: " +
                                              snapshot.journalPath;
                    } else if (found.load(std::memory_order_acquire)) {
                        statusMessage_ = "Password found (verified).";
                    } else {
                        const CandidateSnapshot candidates = candidateSnapshot();
                        const bool stopped =
                            stopRequested_.load(std::memory_order_acquire);
                        if (candidates.total != 0) {
                            std::ostringstream message;
                            message << (stopped ? "Analysis stopped. " : "Analysis completed. ")
                                    << "Unconfirmed password candidates: "
                                    << candidates.total
                                    << ". These are NOT guaranteed correct passwords.";
                            if (!candidates.passwords.empty()) {
                                message << "\nFirst " << candidates.passwords.size()
                                        << " candidate(s):";
                                for (const auto& password : candidates.passwords)
                                    message << "\n  " << password;
                            }
                            message << "\nComplete candidate list (plaintext): "
                                    << candidates.journalPath;
                            statusMessage_ = message.str();
                        } else if (stopped) {
                            statusMessage_ = "Analysis stopped. No password candidates found.";
                        } else {
                            statusMessage_ = "Password not found within the selected length.";
                        }
                    }
                }
            }
        }
    } catch (const std::exception& ex) {
        statusMessage_ = std::string("Analysis error: ") + ex.what();
        Logger::getInstance().log(LogLevel::Error, statusMessage_);
    } catch (...) {
        statusMessage_ = "An unknown analysis error occurred.";
        Logger::getInstance().log(LogLevel::Error, statusMessage_);
    }

    isRunning.store(false, std::memory_order_release);
    return found.load(std::memory_order_acquire) ? result_ : std::string{};
}

// Number of verification workers. A 12-worker default suits a 20-thread CPU,
// but the best setting depends on RAM, storage and libzip performance.
// Environment variable ZIPANALYSIS_VERIFY_WORKERS accepts 1..32 for A/B tests.
namespace {
std::size_t gpuVerificationWorkers() {
    const auto hw = std::thread::hardware_concurrency();
    const std::size_t threads = hw ? hw : 8;
    const std::size_t suggested = std::max<std::size_t>(2, (threads * 3 + 4) / 5);
    const std::size_t automatic = std::min<std::size_t>(16, suggested);
    const char* raw = std::getenv("ZIPANALYSIS_VERIFY_WORKERS");
    if (!raw || !*raw) return automatic;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(raw, &end, 10);
    if (end == raw || *end != '\0' || parsed < 1 || parsed > 32)
        return automatic;
    return static_cast<std::size_t>(parsed);
}
}

// GPU produces *compact batches* (offsets into a password range).
// CPU consumers expand passwords directly into a reusable std::string,
// avoiding per-candidate allocation and per-candidate queue locks.
GpuRunResult Analysis::runGpuParallel(const ZipCryptoInput& input,
                                      const TargetEntry& target) {
    using Clock = std::chrono::steady_clock;
    using namespace std::chrono_literals;
    constexpr std::size_t kQueueCandidateCapacity = 16384;
    const std::size_t workerCount = gpuVerificationWorkers();

    std::deque<GpuCandidateBatch> pending;
    std::size_t queuedCandidates = 0; // guarded by queueMutex
    std::mutex queueMutex;
    std::condition_variable queueNotEmpty;
    std::condition_variable queueNotFull;
    std::atomic<bool> workerFailed{false};
    std::atomic<std::uint64_t> verifications{0};
    std::atomic<std::uint64_t> workerNs{0};
    std::atomic<std::uint64_t> producerWaitNs{0};
    std::atomic<std::uint64_t> completedBatches{0};
    std::string failureReason;
    std::size_t peakQueue = 0;
    bool producerFinished = false; // guarded by queueMutex

    const auto interrupted = [&]() noexcept {
        return stopRequested_.load(std::memory_order_relaxed) ||
               found.load(std::memory_order_acquire) ||
               workerFailed.load(std::memory_order_acquire);
    };
    const auto wakeAll = [&]() {
        queueNotEmpty.notify_all();
        queueNotFull.notify_all();
    };
    const auto fail = [&](const std::string& message) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (failureReason.empty()) failureReason = message;
            workerFailed.store(true, std::memory_order_release);
        }
        wakeAll();
    };

    // A whole batch is either enqueued or rejected due to interruption.
    // No offsets can be silently dropped on a successful GPU completion.
    const auto submitBatch = [&](GpuCandidateBatch&& batch) -> bool {
        const std::size_t n = batch.offsets.size();
        if (!n) return true;
        if (n > kQueueCandidateCapacity) {
            fail("GPU batch exceeds candidate queue capacity.");
            return false;
        }
        std::unique_lock<std::mutex> lock(queueMutex);
        const auto waitStart = Clock::now();
        while (queuedCandidates > kQueueCandidateCapacity - n && !interrupted()) {
            // requestStop() can be called without a CV notification.
            queueNotFull.wait_for(lock, 20ms);
        }
        const auto waited = std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - waitStart).count();
        producerWaitNs.fetch_add(static_cast<std::uint64_t>(waited),
                                std::memory_order_relaxed);
        if (interrupted()) return false;
        pending.push_back(std::move(batch));
        queuedCandidates += n;
        peakQueue = std::max(peakQueue, queuedCandidates);
        lock.unlock();
        queueNotEmpty.notify_one();
        return true;
    };

    const auto verifyWorker = [&]() {
        try {
            int errorCode = 0;
            ZipHandle localArchive(zip_open(filePath_.c_str(), ZIP_RDONLY, &errorCode));
            if (!localArchive) {
                fail("GPU verifier could not open ZIP archive (error " +
                     std::to_string(errorCode) + ").");
                return;
            }
            const std::uint64_t radix = static_cast<std::uint64_t>(charset_.size());
            // 16 is the maximum GPU candidate password length.
            std::string password;
            password.reserve(static_cast<std::size_t>(maxPasswordLen_));
            std::uint64_t localVerified = 0;
            std::uint64_t localWorkerNs = 0;
            std::uint64_t localBatches = 0;

            while (!interrupted()) {
                GpuCandidateBatch batch;
                {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    queueNotEmpty.wait_for(lock, 20ms, [&] {
                        return !pending.empty() || producerFinished || interrupted();
                    });
                    if (interrupted()) break;
                    if (pending.empty()) {
                        if (producerFinished) break;
                        continue;
                    }
                    batch = std::move(pending.front());
                    pending.pop_front();
                    queuedCandidates -= batch.offsets.size();
                }
                queueNotFull.notify_one();

                const auto batchStarted = Clock::now();
                const std::size_t prefixLength = batch.prefix.size();
                const std::size_t passwordLength = prefixLength + batch.suffixLength;
                password.assign(batch.prefix);
                password.resize(passwordLength);
                ++localBatches;
                for (std::uint32_t offset : batch.offsets) {
                    if (interrupted()) break;
                    std::uint64_t index = batch.startIndex + offset;
                    for (std::size_t i = passwordLength; i > prefixLength;) {
                        password[--i] = charset_[static_cast<std::size_t>(index % radix)];
                        index /= radix;
                    }
                    ++localVerified;
                    const auto check = checkPassword(
                        localArchive.get(), target, password, false);
                    handleCheckResult(password, check);
                    if (found.load(std::memory_order_acquire) ||
                        stopRequested_.load(std::memory_order_relaxed)) {
                        wakeAll();
                        break;
                    }
                }
                localWorkerNs += static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        Clock::now() - batchStarted).count());
            }
            verifications.fetch_add(localVerified, std::memory_order_relaxed);
            workerNs.fetch_add(localWorkerNs, std::memory_order_relaxed);
            completedBatches.fetch_add(localBatches, std::memory_order_relaxed);
        } catch (const std::exception& ex) {
            fail(std::string("GPU verification worker failed: ") + ex.what());
        } catch (...) {
            fail("GPU verification worker failed unexpectedly.");
        }
    };

    GpuRunResult gpu;
    std::vector<std::thread> workers;
    workers.reserve(workerCount);
    const auto started = Clock::now();
    try {
        for (std::size_t i = 0; i < workerCount; ++i)
            workers.emplace_back(verifyWorker);

        const auto shouldInterrupt = [&]() {
            return found.load(std::memory_order_acquire) ||
                   workerFailed.load(std::memory_order_acquire);
        };
        const auto reportCompleted = [&](double completed) {
            completedCountEstimate.store(completed, std::memory_order_release);
        };
        gpu = runZipCryptoGpu(input, charset_, maxPasswordLen_, stopRequested_,
                              triedCount, submitBatch, shouldInterrupt,
                              reportCompleted);
        if (gpu.outcome == GpuRunResult::Outcome::Fallback)
            workerFailed.store(true, std::memory_order_release);
    } catch (const std::exception& ex) {
        gpu.outcome = GpuRunResult::Outcome::Fallback;
        gpu.detail = std::string("GPU pipeline failed: ") + ex.what();
        workerFailed.store(true, std::memory_order_release);
    } catch (...) {
        gpu.outcome = GpuRunResult::Outcome::Fallback;
        gpu.detail = "GPU pipeline failed unexpectedly.";
        workerFailed.store(true, std::memory_order_release);
    }

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        producerFinished = true;
    }
    wakeAll();
    for (auto& workerThread : workers)
        if (workerThread.joinable()) workerThread.join();

    // Found wins over concurrent Stop/worker error. All threads are joined.
    if (found.load(std::memory_order_acquire)) {
        gpu.outcome = GpuRunResult::Outcome::Found;
        gpu.password = result_;
        gpu.detail.clear();
    } else if (stopRequested_.load(std::memory_order_acquire)) {
        gpu.outcome = GpuRunResult::Outcome::Stopped;
    } else if (workerFailed.load(std::memory_order_acquire)) {
        gpu.outcome = GpuRunResult::Outcome::Fallback;
        if (gpu.detail.empty()) gpu.detail = failureReason.empty()
            ? "GPU verifier worker failed." : failureReason;
    }

    const double elapsedS = std::chrono::duration<double>(Clock::now() - started).count();
    const auto attempts = triedCount.load(std::memory_order_relaxed);
    const auto verified = verifications.load(std::memory_order_relaxed);
    std::ostringstream profile;
    profile << std::fixed << std::setprecision(2)
            << "GPU batched profile: attempts=" << attempts
            << ", elapsed_s=" << elapsedS
            << ", passwords_per_s=" << (elapsedS > 0.0 ? attempts / elapsedS : 0.0)
            << ", libzip_verifications=" << verified
            << ", deflate_prefilter=" << (gpu.deflatePrefilterEnabled ? "on" : "off")
            << ", store_crc_prefilter=" << (gpu.storeCrcPrefilterEnabled ? "on" : "off")
            << ", store_crc_bytes=" << gpu.storeCrcBytes
            << ", header_passes=" << gpu.headerPasses
            << ", gpu_passes=" << gpu.prefilterPasses
            << ", prefilter_rejected=" <<
               (gpu.headerPasses >= gpu.prefilterPasses ?
                gpu.headerPasses - gpu.prefilterPasses : 0)
            << ", verification_worker_s=" <<
               (workerNs.load(std::memory_order_relaxed) / 1e9)
            << ", workers=" << workers.size()
            << ", batches=" << completedBatches.load(std::memory_order_relaxed)
            << ", gpu_queue_wait_s=" << (producerWaitNs.load(std::memory_order_relaxed) / 1e9)
            << ", peak_queue=" << peakQueue
            << ", outcome=" << static_cast<int>(gpu.outcome);
    Logger::getInstance().log(LogLevel::Info, profile.str());
    return gpu;
}

void Analysis::runCpu(const TargetEntry& target) {
    std::size_t threadCount = std::thread::hardware_concurrency();
    if (threadCount == 0) threadCount = 4;

    const std::size_t alphabetSize = charset_.size();
    const std::size_t taskCount = alphabetSize +
        (maxPasswordLen_ >= 2 ? alphabetSize * alphabetSize : 0);
    threadCount = std::min(threadCount, taskCount);
    std::atomic<std::size_t> nextTask{0};
    std::vector<std::thread> workers;
    workers.reserve(threadCount);

    try {
        for (std::size_t i = 0; i < threadCount; ++i) {
            workers.emplace_back(&Analysis::worker, this,
                                 std::cref(target), std::ref(nextTask), taskCount);
        }
    } catch (...) {
        requestStop();
        for (auto& workerThread : workers) workerThread.join();
        throw;
    }

    for (auto& workerThread : workers) workerThread.join();
}

void Analysis::worker(const TargetEntry& target,
                      std::atomic<std::size_t>& nextTask,
                      std::size_t taskCount) {
    int errorCode = 0;
    ZipHandle archive(zip_open(filePath_.c_str(), ZIP_RDONLY, &errorCode));
    if (!archive) {
        {
            std::lock_guard<std::mutex> lock(workerErrorMutex_);
            if (workerError_.empty()) {
                workerError_ = "A CPU worker could not open the ZIP archive.";
            }
        }
        requestStop();
        return;
    }

    const std::size_t alphabetSize = charset_.size();
    std::string attempt;
    attempt.reserve(static_cast<std::size_t>(maxPasswordLen_));

    while (!shouldStop()) {
        const std::size_t task = nextTask.fetch_add(1, std::memory_order_relaxed);
        if (task >= taskCount) break;

        if (task < alphabetSize) {
            attempt.assign(1, charset_[task]);
            const auto check = checkPassword(archive.get(), target, attempt);
            handleCheckResult(attempt, check);
            if (found.load(std::memory_order_acquire) || shouldStop()) return;
            continue;
        }

        const std::size_t pair = task - alphabetSize;
        attempt.clear();
        attempt.push_back(charset_[pair / alphabetSize]);
        attempt.push_back(charset_[pair % alphabetSize]);

        for (int length = 2; length <= maxPasswordLen_ && !shouldStop(); ++length) {
            if (search(archive.get(), target, attempt, length - 2)) return;
        }
    }
}

bool Analysis::search(zip_t* archive, const TargetEntry& target,
                      std::string& attempt, int remainingDigits) {
    if (shouldStop()) return true;

    if (remainingDigits == 0) {
        const auto check = checkPassword(archive, target, attempt);
        handleCheckResult(attempt, check);
        return found.load(std::memory_order_acquire) || shouldStop();
    }

    for (char c : charset_) {
        if (shouldStop()) return true;
        attempt.push_back(c);
        const bool stopped = search(archive, target, attempt, remainingDigits - 1);
        attempt.pop_back();
        if (stopped) return true;
    }
    return false;
}

void Analysis::addCpuAttempt() {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    auto old = triedCount.load(std::memory_order_relaxed);
    while (old != maximum &&
           !triedCount.compare_exchange_weak(old, old + 1,
                                            std::memory_order_relaxed)) {}
    auto estimate = completedCountEstimate.load(std::memory_order_relaxed);
    while (!completedCountEstimate.compare_exchange_weak(
        estimate, estimate + 1.0, std::memory_order_relaxed)) {}
}

Analysis::CheckResult Analysis::checkPassword(
    zip_t* archive, const TargetEntry& target,
    const std::string& password, bool countAttempt) {
    if (shouldStop()) return CheckResult::Rejected;
    if (countAttempt) addCpuAttempt();

    // Full extraction, including EOF and CRC/authentication verification.
    const auto verifyEntry = [&](zip_uint64_t index, zip_uint64_t expectedSize,
                                 bool sizeKnown) -> bool {
        if (shouldStop()) return false;
        zip_file_t* file = zip_fopen_index_encrypted(
            archive, index, 0, password.c_str());
        if (!file) return false;
        char buffer[8192];
        zip_uint64_t bytesRead = 0;
        bool valid = true;
        for (;;) {
            if (shouldStop()) { valid = false; break; }
            const zip_int64_t n = zip_fread(file, buffer, sizeof(buffer));
            if (n < 0) { valid = false; break; }
            if (n == 0) break;
            bytesRead += static_cast<zip_uint64_t>(n);
            if (sizeKnown && bytesRead > expectedSize) { valid = false; break; }
        }
        if (sizeKnown && bytesRead != expectedSize) valid = false;
        if (zip_fclose(file) != 0) valid = false;
        return valid && !shouldStop();
    };

    if (!verifyEntry(target.index, target.uncompressedSize, target.sizeKnown))
        return CheckResult::Rejected;

    // Authenticated AES entries can be confirmed by libzip alone.
    if (target.encryptionMethod != ZIP_EM_TRAD_PKWARE)
        return CheckResult::Confirmed;

    // ZipCrypto is weak: a primary-entry header+CRC32 match is only a
    // provisional candidate. Cross-check against other encrypted entries.
    // If another entry has a different password (or cannot be verified),
    // *keep* this primary match as a candidate; never silently discard it.
    bool hasIndependentMatch = false;
    bool allOtherEncryptedMatched = true;
    const zip_int64_t entries = zip_get_num_entries(archive, 0);
    if (entries <= 0) return CheckResult::Unconfirmed;
    for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(entries); ++i) {
        if (i == target.index) continue;
        zip_stat_t stat;
        zip_stat_init(&stat);
        if (zip_stat_index(archive, i, 0, &stat) != 0) {
            allOtherEncryptedMatched = false;
            continue;
        }
        if (!isEncryptedRegularEntry(stat)) continue;
        if (!zip_encryption_method_supported(
                static_cast<zip_int16_t>(stat.encryption_method), 1) ||
            !(stat.valid & ZIP_STAT_COMP_METHOD) ||
            !zip_compression_method_supported(
                static_cast<zip_int32_t>(stat.comp_method), 1)) {
            allOtherEncryptedMatched = false;
            continue;
        }
        const bool sizeKnown = (stat.valid & ZIP_STAT_SIZE) != 0;
        if (!verifyEntry(i, sizeKnown ? stat.size : 0, sizeKnown)) {
            allOtherEncryptedMatched = false;
            break;
        }
        if (sizeKnown && stat.size >= 4)
            hasIndependentMatch = true;
    }
    if (shouldStop()) return CheckResult::Rejected;
    return hasIndependentMatch && allOtherEncryptedMatched
        ? CheckResult::Confirmed : CheckResult::Unconfirmed;
}

void Analysis::saveResult(const std::string& candidate) {
    std::lock_guard<std::mutex> lock(resultMutex_);
    if (!found.load(std::memory_order_relaxed) &&
        !stopRequested_.load(std::memory_order_relaxed)) {
        result_ = candidate;
        found.store(true, std::memory_order_release);
    }
}

void Analysis::handleCheckResult(const std::string& password,
                                 CheckResult result) {
    if (result == CheckResult::Confirmed) saveResult(password);
    else if (result == CheckResult::Unconfirmed) recordCandidate(password);
}

void Analysis::setFailure(const std::string& error) {
    {
        std::lock_guard<std::mutex> lock(workerErrorMutex_);
        if (workerError_.empty()) workerError_ = error;
    }
    requestStop();
}

bool Analysis::openCandidateJournal() {
    try {
        const auto tick = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const std::filesystem::path zipPath = std::filesystem::u8path(filePath_);
        // Each run gets its own file, so previous candidate files are preserved.
        for (int suffix = 0; suffix < 1000; ++suffix) {
            std::filesystem::path journalPath = zipPath;
            journalPath += ".candidates." + std::to_string(tick) + "." +
                           std::to_string(suffix) + ".txt";
            if (std::filesystem::exists(journalPath)) continue;
            candidateJournal_.open(journalPath, std::ios::out | std::ios::binary);
            if (!candidateJournal_) break;
            candidateJournal_ << "# Unconfirmed ZipCrypto candidates; "
                                 "NOT guaranteed to be correct.\n";
            candidateJournal_.flush();
            if (!candidateJournal_.good()) break;
            {
                std::lock_guard<std::mutex> lock(resultMutex_);
                candidateJournalPath_ = journalPath.u8string();
            }
            Logger::getInstance().log(
                LogLevel::Info, "Candidate journal: " + journalPath.u8string());
            return true;
        }
    } catch (const std::exception& ex) {
        setFailure(std::string("Cannot create candidate journal: ") + ex.what());
        return false;
    }
    setFailure("Cannot create candidate journal beside the ZIP. "
               "Move the ZIP to a writable directory and retry.");
    return false;
}

void Analysis::recordCandidate(const std::string& password) {
    if (shouldStop()) return;
    bool writeFailed = false;
    {
        std::lock_guard<std::mutex> lock(resultMutex_);
        try {
            if (!candidateJournal_.is_open()) {
                writeFailed = true;
            } else {
                // Stream directly to disk: there is no cap on candidate records.
                // If the file fills up, stop the search rather than dropping hits.
                candidateJournal_ << password << '\n';
                candidateJournal_.flush();
                writeFailed = !candidateJournal_.good();
            }
            if (!writeFailed) {
                if (candidateCount_ != std::numeric_limits<std::uint64_t>::max())
                    ++candidateCount_;
                if (candidatePasswords_.size() < kMaxSavedCandidates &&
                    std::find(candidatePasswords_.begin(), candidatePasswords_.end(),
                              password) == candidatePasswords_.end())
                    candidatePasswords_.push_back(password);
            }
        } catch (const std::exception&) {
            writeFailed = true;
        }
    }
    if (writeFailed) setFailure("Could not write a candidate to disk; "
                                "analysis stopped to prevent silent candidate loss.");
}

Analysis::CandidateSnapshot Analysis::candidateSnapshot() const {
    std::lock_guard<std::mutex> lock(resultMutex_);
    return CandidateSnapshot{candidateCount_, candidatePasswords_,
                             candidateJournalPath_};
}

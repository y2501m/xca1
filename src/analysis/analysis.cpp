#include "analysis.hpp"
#include "../gpu/gpu_detector.hpp"
#include "../gpu/gpu_analysis.hpp"
#include "../gpu/zipcrypto_input.hpp"
#include "../logger/logger.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
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
    initializeProgress();

    try {
        if (maxPasswordLen_ < 1 || charset_.empty()) {
            statusMessage_ = "Invalid password length or character set.";
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

                    bool cpuFallback = true;
                    if (detectedGpu.available &&
                        target.encryptionMethod == ZIP_EM_TRAD_PKWARE &&
                        !stopRequested_.load(std::memory_order_relaxed)) {
                        ZipCryptoInput gpuInput;
                        std::string reason;
                        if (prepareZipCryptoInput(filePath_, archive.get(), target.index,
                                                  gpuInput, reason)) {
                            Logger::getInstance().log(
                                LogLevel::Info, "Attempting OpenCL GPU analysis: " +
                                detectedGpu.deviceName);
                            activeBackend.store(2, std::memory_order_release);
                            const auto verify = [&](const std::string& password) {
                                return testPassword(archive.get(), target, password, false);
                            };
                            const GpuRunResult gpu = runZipCryptoGpu(
                                gpuInput, charset_, maxPasswordLen_, stopRequested_,
                                triedCount, verify);
                            if (gpu.outcome == GpuRunResult::Outcome::Found) {
                                saveResult(gpu.password);
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
                        activeBackend.store(1, std::memory_order_release);
                        archive.reset(); // CPU threads each create a separate zip_t.
                        runCpu(target);
                    }

                    if (!workerError_.empty()) {
                        statusMessage_ = workerError_;
                    } else if (found.load(std::memory_order_acquire)) {
                        statusMessage_ = "Password found.";
                    } else if (stopRequested_.load(std::memory_order_acquire)) {
                        statusMessage_ = "Analysis stopped.";
                    } else {
                        statusMessage_ = "Password not found within the selected length.";
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
            if (testPassword(archive.get(), target, attempt)) {
                saveResult(attempt);
                return;
            }
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
        if (testPassword(archive, target, attempt)) {
            saveResult(attempt);
            return true;
        }
        return false;
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

bool Analysis::testPassword(zip_t* archive, const TargetEntry& target,
                            const std::string& password, bool countAttempt) {
    if (shouldStop()) return false;
    if (countAttempt) triedCount.fetch_add(1, std::memory_order_relaxed);

    zip_file_t* file = zip_fopen_index_encrypted(
        archive, target.index, 0, password.c_str());
    if (!file) return false;

    char buffer[8192];
    zip_uint64_t bytesRead = 0;
    bool valid = true;
    for (;;) {
        if (shouldStop()) {
            valid = false;
            break;
        }
        const zip_int64_t n = zip_fread(file, buffer, sizeof(buffer));
        if (n < 0) {
            valid = false;
            break;
        }
        if (n == 0) break; // Reaching EOF lets libzip validate the checksum.

        bytesRead += static_cast<zip_uint64_t>(n);
        if (target.sizeKnown && bytesRead > target.uncompressedSize) {
            valid = false;
            break;
        }
    }

    if (target.sizeKnown && bytesRead != target.uncompressedSize) valid = false;
    if (zip_fclose(file) != 0) valid = false;
    return valid && !shouldStop();
}

void Analysis::saveResult(const std::string& candidate) {
    std::lock_guard<std::mutex> lock(resultMutex_);
    if (!found.load(std::memory_order_relaxed) &&
        !stopRequested_.load(std::memory_order_relaxed)) {
        result_ = candidate;
        found.store(true, std::memory_order_release);
    }
}

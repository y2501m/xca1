#include "gpu_analysis.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#define CL_API WINAPI
#else
#include <dlfcn.h>
#define CL_API
#endif

namespace {
using ClInt = std::int32_t;
using ClUInt = std::uint32_t;
using ClULong = std::uint64_t;
using ClBool = ClUInt;
using ClDeviceType = ClULong;
using ClMemFlags = ClULong;
using ClCommandQueueProps = ClULong;
using ClPlatformId = void*;
using ClDeviceId = void*;
using ClContext = void*;
using ClCommandQueue = void*;
using ClProgram = void*;
using ClKernel = void*;
using ClMem = void*;
using ClEvent = void*;

constexpr ClInt kSuccess = 0;
constexpr ClDeviceType kGpuDevice = 1ull << 2;
constexpr ClUInt kDeviceAvailable = 0x1027;
constexpr ClUInt kDeviceName = 0x102b;
constexpr ClUInt kDeviceVendor = 0x102c;
constexpr ClUInt kProgramBuildLog = 0x1183;
constexpr ClMemFlags kReadOnly = 1ull << 2;
constexpr ClMemFlags kReadWrite = 1ull << 0;
constexpr ClBool kBlocking = 1;
// Larger batches reduce per-dispatch synchronization overhead. Keep the
// 1-byte-filter hit buffer comfortably above the expected (batch / 256) count.
constexpr std::size_t kBatchSize = 524288;
constexpr ClUInt kMaxHits = 8192;
constexpr int kMaxGpuSuffix = 8; // 91^8 fits in uint64_t; 91^16 does not.

// Kept as source in the binary: no runtime .cl file or SDK is needed.
// GPU checks ZipCrypto header, optional DEFLATE structure, or STORE CRC32.
// CPU/libzip still validates all remaining candidates in full.
constexpr char kKernelSource[] = R"OPENCL(
#ifndef CHARSET_SIZE
#error CHARSET_SIZE must be passed at build time
#endif
#ifndef LOW_DIGITS
#error LOW_DIGITS must be passed at build time
#endif

uint crc_byte(uint key, uchar b, __constant const uint* table) {
    return (key >> 8) ^ table[(key ^ (uint)b) & 255u];
}
void update_keys(uint* k0, uint* k1, uint* k2,
                 uchar b, __constant const uint* table) {
    *k0 = crc_byte(*k0, b, table);
    *k1 = (*k1 + (*k0 & 255u)) * 134775813u + 1u;
    *k2 = crc_byte(*k2, (uchar)(*k1 >> 24), table);
}
__kernel void search_zipcrypto(
    __global const uchar* alphabet,
    uint suffixLen,
    uint prefixK0,
    uint prefixK1,
    uint prefixK2,
    __constant const uchar* encryptedHeader,
    uint checkByte,
    __constant const uint* crcTable,
    uint lowStart,
    uint highIndex,
    __global uint* hitOffsets,
    volatile __global uint* hitCount,
    uint hitCapacity,
    __constant const uchar* encryptedDeflatePrefix,
    uint enableDeflatePrefilter,
    __global const uchar* encryptedStoreData,
    uint storeDataSize,
    uint storeExpectedCrc32,
    uint enableStoreCrcPrefilter)
{
    const uint gid = (uint)get_global_id(0);
    uchar password[8];

    // Split suffix indexes into two 32-bit portions. The host guarantees
    // that one batch never crosses the low-part radix boundary. Hence this
    // avoids any 64-bit division/modulo per candidate, even for 8 characters.
    const uint lowDigits = min(suffixLen, (uint)LOW_DIGITS);
    const uint highDigits = suffixLen - lowDigits;
    uint low = lowStart + gid;
    uint high = highIndex;
    for (int i = (int)suffixLen - 1; i >= (int)highDigits; --i) {
        password[(uint)i] = alphabet[low % (uint)CHARSET_SIZE];
        low /= (uint)CHARSET_SIZE;
    }
    for (int i = (int)highDigits - 1; i >= 0; --i) {
        password[(uint)i] = alphabet[high % (uint)CHARSET_SIZE];
        high /= (uint)CHARSET_SIZE;
    }

    // Prefix key state was computed once on the host, not once per candidate.
    uint k0 = prefixK0;
    uint k1 = prefixK1;
    uint k2 = prefixK2;
    for (uint i = 0; i < suffixLen; ++i)
        update_keys(&k0, &k1, &k2, password[i], crcTable);

    uchar plain = 0;
    for (uint j = 0; j < 12; ++j) {
        uint tmp = (k2 | 2u) & 65535u;
        uchar streamByte = (uchar)((tmp * (tmp ^ 1u)) >> 8);
        plain = encryptedHeader[j] ^ streamByte;
        update_keys(&k0, &k1, &k2, plain, crcTable);
    }
    if ((uint)plain == checkByte) {
        // hitCount[1] is the number passing the original ZipCrypto check.
        // hitCount[0] is the number forwarded to CPU after optional filtering.
        if (enableDeflatePrefilter != 0u || enableStoreCrcPrefilter != 0u)
            atomic_inc(hitCount + 1);
        if (enableStoreCrcPrefilter != 0u) {
            // ZipCrypto state is now positioned at the first STORE payload
            // byte. STORE means plaintext == uncompressed bytes: compute the
            // standard ZIP CRC32 on the *entire* plaintext, not ciphertext.
            uint crc = 0xffffffffu;
            for (uint i = 0u; i < storeDataSize; ++i) {
                uint t = (k2 | 2u) & 65535u;
                uchar plainByte = encryptedStoreData[i] ^
                    (uchar)((t * (t ^ 1u)) >> 8);
                update_keys(&k0, &k1, &k2, plainByte, crcTable);
                crc = crc_byte(crc, plainByte, crcTable);
            }
            if ((crc ^ 0xffffffffu) != storeExpectedCrc32) return;
        } else if (enableDeflatePrefilter != 0u) {
            uint t = (k2 | 2u) & 65535u;
            uchar first = encryptedDeflatePrefix[0] ^
                (uchar)((t * (t ^ 1u)) >> 8);
            uint blockType = ((uint)first >> 1) & 3u;

            // RFC 1951, section 3.2.3: BTYPE=11 is reserved/invalid.
            if (blockType == 3u) return;
            // RFC 1951, section 3.2.7: HLIT encodes 257..286 (0..29).
            if (blockType == 2u && ((uint)first >> 3) > 29u) return;
            // BTYPE=00: at the next byte boundary, NLEN must complement LEN.
            // Only decrypt these extra four bytes when needed.
            if (blockType == 0u) {
                update_keys(&k0, &k1, &k2, first, crcTable);
                uint len = 0u;
                uint nlen = 0u;
                for (uint i = 1u; i < 5u; ++i) {
                    t = (k2 | 2u) & 65535u;
                    uchar b = encryptedDeflatePrefix[i] ^
                        (uchar)((t * (t ^ 1u)) >> 8);
                    if (i <= 2u) len |= ((uint)b) << (8u * (i - 1u));
                    else nlen |= ((uint)b) << (8u * (i - 3u));
                    update_keys(&k0, &k1, &k2, b, crcTable);
                }
                if ((len ^ nlen) != 65535u) return;
            }
        }
        uint position = atomic_inc(hitCount);
        if (position < hitCapacity)
            hitOffsets[position] = gid;
    }
}
)OPENCL";


// Shared CRC table for the GPU kernel and host-side prefix state.
const std::array<std::uint32_t, 256>& crcTable() {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> values{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int bit = 0; bit < 8; ++bit)
                c = (c >> 1) ^ ((c & 1u) ? 0xedb88320u : 0u);
            values[i] = c;
        }
        return values;
    }();
    return table;
}

// Largest number of candidate digits whose radix space fits in uint32_t.
int maxLowDigits(std::size_t alphabetSize) {
    std::uint64_t span = 1;
    int digits = 0;
    while (digits < kMaxGpuSuffix &&
           span <= std::numeric_limits<std::uint32_t>::max() / alphabetSize) {
        span *= alphabetSize;
        ++digits;
    }
    return digits;
}

std::array<std::uint32_t, 3> keysForPrefix(const std::string& prefix) {
    std::array<std::uint32_t, 3> k{{0x12345678u, 0x23456789u, 0x34567890u}};
    const auto& table = crcTable();
    for (unsigned char b : prefix) {
        k[0] = (k[0] >> 8) ^ table[(k[0] ^ b) & 255u];
        k[1] = (k[1] + (k[0] & 255u)) * 134775813u + 1u;
        k[2] = (k[2] >> 8) ^ table[(k[2] ^ (k[1] >> 24)) & 255u];
    }
    return k;
}

struct OpenCl {
    using GetPlatforms = ClInt(CL_API*)(ClUInt, ClPlatformId*, ClUInt*);
    using GetDevices = ClInt(CL_API*)(ClPlatformId, ClDeviceType, ClUInt, ClDeviceId*, ClUInt*);
    using GetDeviceInfo = ClInt(CL_API*)(ClDeviceId, ClUInt, std::size_t, void*, std::size_t*);
    using CreateContext = ClContext(CL_API*)(const std::intptr_t*, ClUInt, const ClDeviceId*,
                                             void (CL_API*)(const char*, const void*, std::size_t, void*), void*, ClInt*);
    using CreateQueue = ClCommandQueue(CL_API*)(ClContext, ClDeviceId, ClCommandQueueProps, ClInt*);
    using CreateProgram = ClProgram(CL_API*)(ClContext, ClUInt, const char**, const std::size_t*, ClInt*);
    using BuildProgram = ClInt(CL_API*)(ClProgram, ClUInt, const ClDeviceId*, const char*,
                                        void (CL_API*)(ClProgram, void*), void*);
    using GetBuildInfo = ClInt(CL_API*)(ClProgram, ClDeviceId, ClUInt, std::size_t, void*, std::size_t*);
    using CreateKernel = ClKernel(CL_API*)(ClProgram, const char*, ClInt*);
    using CreateBuffer = ClMem(CL_API*)(ClContext, ClMemFlags, std::size_t, void*, ClInt*);
    using SetKernelArg = ClInt(CL_API*)(ClKernel, ClUInt, std::size_t, const void*);
    using WriteBuffer = ClInt(CL_API*)(ClCommandQueue, ClMem, ClBool, std::size_t, std::size_t,
                                       const void*, ClUInt, const ClEvent*, ClEvent*);
    using ReadBuffer = ClInt(CL_API*)(ClCommandQueue, ClMem, ClBool, std::size_t, std::size_t,
                                      void*, ClUInt, const ClEvent*, ClEvent*);
    using EnqueueKernel = ClInt(CL_API*)(ClCommandQueue, ClKernel, ClUInt, const std::size_t*,
                                         const std::size_t*, const std::size_t*, ClUInt,
                                         const ClEvent*, ClEvent*);
    using ReleaseMem = ClInt(CL_API*)(ClMem);
    using ReleaseKernel = ClInt(CL_API*)(ClKernel);
    using ReleaseProgram = ClInt(CL_API*)(ClProgram);
    using ReleaseQueue = ClInt(CL_API*)(ClCommandQueue);
    using ReleaseContext = ClInt(CL_API*)(ClContext);

    GetPlatforms platforms = nullptr;
    GetDevices devices = nullptr;
    GetDeviceInfo deviceInfo = nullptr;
    CreateContext createContext = nullptr;
    CreateQueue createQueue = nullptr;
    CreateProgram createProgram = nullptr;
    BuildProgram buildProgram = nullptr;
    GetBuildInfo getBuildInfo = nullptr;
    CreateKernel createKernel = nullptr;
    CreateBuffer createBuffer = nullptr;
    SetKernelArg setArg = nullptr;
    WriteBuffer writeBuffer = nullptr;
    ReadBuffer readBuffer = nullptr;
    EnqueueKernel enqueueKernel = nullptr;
    ReleaseMem releaseMem = nullptr;
    ReleaseKernel releaseKernel = nullptr;
    ReleaseProgram releaseProgram = nullptr;
    ReleaseQueue releaseQueue = nullptr;
    ReleaseContext releaseContext = nullptr;

#if defined(_WIN32)
    HMODULE library = nullptr;
#else
    void* library = nullptr;
#endif
    ClContext context = nullptr;
    ClCommandQueue queue = nullptr;
    ClProgram program = nullptr;
    ClKernel kernel = nullptr;
    std::array<ClMem, 7> buffers{};
    ClDeviceId device = nullptr;
    std::string deviceName;

    ~OpenCl() {
        if (releaseMem) for (ClMem b : buffers) if (b) releaseMem(b);
        if (kernel && releaseKernel) releaseKernel(kernel);
        if (program && releaseProgram) releaseProgram(program);
        if (queue && releaseQueue) releaseQueue(queue);
        if (context && releaseContext) releaseContext(context);
#if defined(_WIN32)
        if (library) FreeLibrary(library);
#else
        if (library) dlclose(library);
#endif
    }
    OpenCl() = default;
    OpenCl(const OpenCl&) = delete;
    OpenCl& operator=(const OpenCl&) = delete;

    template<typename T> bool loadSymbol(T& address, const char* name) {
#if defined(_WIN32)
        address = reinterpret_cast<T>(GetProcAddress(library, name));
#else
        address = reinterpret_cast<T>(dlsym(library, name));
#endif
        return address != nullptr;
    }
    bool init(ClUInt alphabetSize, int lowDigits, std::string& reason) {
#if defined(_WIN32)
        library = LoadLibraryExW(L"OpenCL.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
#else
        library = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
#endif
        if (!library) { reason = "OpenCL runtime not installed."; return false; }
#define LOAD(x, name) if (!loadSymbol(x, name)) { reason = "OpenCL runtime is missing " name; return false; }
        LOAD(platforms, "clGetPlatformIDs")
        LOAD(devices, "clGetDeviceIDs")
        LOAD(deviceInfo, "clGetDeviceInfo")
        LOAD(createContext, "clCreateContext")
        LOAD(createQueue, "clCreateCommandQueue")
        LOAD(createProgram, "clCreateProgramWithSource")
        LOAD(buildProgram, "clBuildProgram")
        LOAD(getBuildInfo, "clGetProgramBuildInfo")
        LOAD(createKernel, "clCreateKernel")
        LOAD(createBuffer, "clCreateBuffer")
        LOAD(setArg, "clSetKernelArg")
        LOAD(writeBuffer, "clEnqueueWriteBuffer")
        LOAD(readBuffer, "clEnqueueReadBuffer")
        LOAD(enqueueKernel, "clEnqueueNDRangeKernel")
        LOAD(releaseMem, "clReleaseMemObject")
        LOAD(releaseKernel, "clReleaseKernel")
        LOAD(releaseProgram, "clReleaseProgram")
        LOAD(releaseQueue, "clReleaseCommandQueue")
        LOAD(releaseContext, "clReleaseContext")
#undef LOAD
        ClUInt platformCount = 0;
        if (platforms(0, nullptr, &platformCount) != kSuccess || platformCount == 0) {
            reason = "No OpenCL platform was found."; return false;
        }
        std::vector<ClPlatformId> platformIds(platformCount);
        if (platforms(platformCount, platformIds.data(), nullptr) != kSuccess) {
            reason = "Unable to enumerate OpenCL platforms."; return false;
        }
        ClDeviceId first = nullptr;
        for (ClPlatformId platform : platformIds) {
            ClUInt count = 0;
            if (devices(platform, kGpuDevice, 0, nullptr, &count) != kSuccess || count == 0)
                continue;
            std::vector<ClDeviceId> ids(count);
            if (devices(platform, kGpuDevice, count, ids.data(), nullptr) != kSuccess)
                continue;
            for (ClDeviceId candidate : ids) {
                ClBool available = 0;
                if (deviceInfo(candidate, kDeviceAvailable, sizeof(available),
                               &available, nullptr) != kSuccess || !available) continue;
                if (!first) first = candidate;
                const std::string vendor = stringInfo(candidate, kDeviceVendor);
                const std::string name = stringInfo(candidate, kDeviceName);
                if (vendor.find("NVIDIA") != std::string::npos ||
                    name.find("GeForce") != std::string::npos) {
                    first = candidate;
                    break;
                }
            }
            if (first && (stringInfo(first, kDeviceVendor).find("NVIDIA") != std::string::npos ||
                          stringInfo(first, kDeviceName).find("GeForce") != std::string::npos))
                break;
        }
        if (!first) { reason = "No usable OpenCL GPU was found."; return false; }
        device = first;
        deviceName = stringInfo(device, kDeviceName);
        if (deviceName.empty()) deviceName = "OpenCL GPU";
        ClInt err = 0;
        context = createContext(nullptr, 1, &device, nullptr, nullptr, &err);
        if (!context || err != kSuccess) { reason = "clCreateContext failed."; return false; }
        queue = createQueue(context, device, 0, &err);
        if (!queue || err != kSuccess) { reason = "clCreateCommandQueue failed."; return false; }
        const char* src = kKernelSource;
        program = createProgram(context, 1, &src, nullptr, &err);
        if (!program || err != kSuccess) { reason = "clCreateProgramWithSource failed."; return false; }
        // Constant radix lets the OpenCL compiler strength-reduce / and %.
        const std::string buildOptions = "-cl-std=CL1.2 -DCHARSET_SIZE=" +
                                         std::to_string(alphabetSize) +
                                         " -DLOW_DIGITS=" + std::to_string(lowDigits);
        err = buildProgram(program, 1, &device, buildOptions.c_str(), nullptr, nullptr);
        if (err != kSuccess) {
            std::string log = buildLog();
            reason = "OpenCL ZipCrypto kernel build failed" +
                     (log.empty() ? std::string(".") : ": " + log.substr(0, 1200));
            return false;
        }
        kernel = createKernel(program, "search_zipcrypto", &err);
        if (!kernel || err != kSuccess) { reason = "clCreateKernel failed."; return false; }
        return true;
    }
    std::string stringInfo(ClDeviceId id, ClUInt field) const {
        std::size_t size = 0;
        if (deviceInfo(id, field, 0, nullptr, &size) != kSuccess || size == 0 || size > 4096)
            return {};
        std::vector<char> data(size + 1, 0);
        if (deviceInfo(id, field, size, data.data(), nullptr) != kSuccess) return {};
        return data.data();
    }
    std::string buildLog() const {
        std::size_t size = 0;
        if (getBuildInfo(program, device, kProgramBuildLog, 0, nullptr, &size) != kSuccess ||
            size == 0 || size > 16384) return {};
        std::vector<char> buf(size + 1, 0);
        if (getBuildInfo(program, device, kProgramBuildLog,
                         size, buf.data(), nullptr) != kSuccess) return {};
        return buf.data();
    }
    bool createBuffers(const ZipCryptoInput& input,
                       const std::string& alphabet, std::string& reason) {
        const std::array<std::size_t, 7> sizes{{
            alphabet.size(), input.encryptedHeader.size(),
            256 * sizeof(std::uint32_t), kMaxHits * sizeof(std::uint32_t),
            2 * sizeof(ClUInt), input.encryptedDeflatePrefix.size(),
            std::max<std::size_t>(1, input.encryptedStoreData.size())
        }};
        for (std::size_t i = 0; i < buffers.size(); ++i) {
            ClInt err = 0;
            buffers[i] = createBuffer(context, (i == 3 || i == 4) ? kReadWrite : kReadOnly,
                                      sizes[i], nullptr, &err);
            if (!buffers[i] || err != kSuccess) {
                reason = "clCreateBuffer failed for buffer " + std::to_string(i);
                return false;
            }
        }
        const auto& table = crcTable();
        if (!write(0, alphabet.data(), alphabet.size()) ||
            !write(1, input.encryptedHeader.data(), input.encryptedHeader.size()) ||
            !write(2, table.data(), table.size() * sizeof(table[0])) ||
            !write(5, input.encryptedDeflatePrefix.data(),
                   input.encryptedDeflatePrefix.size())) {
            reason = "Failed to upload ZipCrypto data to GPU."; return false;
        }
        if (input.storeCrcPrefilterEnabled &&
            !write(6, input.encryptedStoreData.data(), input.encryptedStoreData.size())) {
            reason = "Failed to upload encrypted STORE payload to GPU.";
            return false;
        }
        const ClUInt check = input.checkByte;
        const ClUInt capacity = kMaxHits;
        const ClUInt prefilter = input.deflatePrefilterEnabled ? 1u : 0u;
        const ClUInt storeEnabled = input.storeCrcPrefilterEnabled ? 1u : 0u;
        const ClUInt storeLen = storeEnabled ?
            static_cast<ClUInt>(input.encryptedStoreData.size()) : 0u;
        if (!argMem(0, 0) || !argMem(5, 1) || !arg(6, check) ||
            !argMem(7, 2) || !argMem(10, 3) || !argMem(11, 4) ||
            !arg(12, capacity) || !argMem(13, 5) || !arg(14, prefilter) ||
            !argMem(15, 6) || !arg(16, storeLen) ||
            !arg(17, input.storeExpectedCrc32) || !arg(18, storeEnabled)) {
            reason = "Failed to configure ZipCrypto kernel arguments."; return false;
        }
        return true;
    }
    bool write(std::size_t index, const void* data, std::size_t size) {
        return writeBuffer(queue, buffers[index], kBlocking, 0, size,
                           data, 0, nullptr, nullptr) == kSuccess;
    }
    bool read(std::size_t index, void* data, std::size_t size) {
        return readBuffer(queue, buffers[index], kBlocking, 0, size,
                          data, 0, nullptr, nullptr) == kSuccess;
    }
    template<typename T> bool arg(ClUInt slot, const T& value) {
        return setArg(kernel, slot, sizeof(T), &value) == kSuccess;
    }
    bool argMem(ClUInt slot, std::size_t buffer) {
        return arg(slot, buffers[buffer]);
    }
};

std::uint64_t powerOf(std::uint64_t base, int exponent) {
    std::uint64_t value = 1;
    for (int i = 0; i < exponent; ++i) value *= base;
    return value;
}
std::string decodeIndex(std::uint64_t index, int length,
                        const std::string& charset) {
    std::string password(static_cast<std::size_t>(length), charset.front());
    for (int j = length - 1; j >= 0; --j) {
        password[static_cast<std::size_t>(j)] = charset[index % charset.size()];
        index /= charset.size();
    }
    return password;
}
void saturatingAdd(std::atomic<std::uint64_t>& target, std::uint64_t increment) {
    std::uint64_t previous = target.load(std::memory_order_relaxed);
    for (;;) {
        const std::uint64_t next = increment > std::numeric_limits<std::uint64_t>::max() - previous
            ? std::numeric_limits<std::uint64_t>::max() : previous + increment;
        if (target.compare_exchange_weak(previous, next, std::memory_order_relaxed)) break;
    }
}
void saturatingAccumulate(std::uint64_t& target, std::uint64_t increment) {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    target = (increment > maximum - target) ? maximum : target + increment;
}
} // namespace

GpuRunResult runZipCryptoGpu(const ZipCryptoInput& input, const std::string& charset,
                             int maxPasswordLength,
                             std::atomic<bool>& stopRequested,
                             std::atomic<std::uint64_t>& triedCount,
                             const std::function<bool(GpuCandidateBatch&&)>& submitBatch,
                             const std::function<bool()>& shouldInterrupt,
                             const std::function<void(double)>& reportCompleted) {
    GpuRunResult result;
    if (charset.empty() || charset.size() > 128 || maxPasswordLength < 1 ||
        maxPasswordLength > 16) {
        result.detail = "Unsupported GPU password alphabet or length.";
        return result;
    }
    const int maxLow = maxLowDigits(charset.size());
    OpenCl cl;
    if (!cl.init(static_cast<ClUInt>(charset.size()), maxLow, result.detail) ||
        !cl.createBuffers(input, charset, result.detail))
        return result;
    result.deviceName = cl.deviceName;
    result.deflatePrefilterEnabled = input.deflatePrefilterEnabled;
    result.storeCrcPrefilterEnabled = input.storeCrcPrefilterEnabled;
    result.storeCrcBytes = static_cast<std::uint32_t>(input.encryptedStoreData.size());
    std::vector<std::uint32_t> hitOffsets(kMaxHits);
    double completedShorterLengths = 0.0;
    double combinationsThisLength = 1.0;

    for (int len = 1; len <= maxPasswordLength; ++len) {
        combinationsThisLength *= static_cast<double>(charset.size());
        const int suffixLen = std::min(len, kMaxGpuSuffix);
        const int prefixLen = len - suffixLen;
        const std::uint64_t prefixCount = powerOf(charset.size(), prefixLen);
        const std::uint64_t suffixCount = powerOf(charset.size(), suffixLen);
        const std::uint64_t lowSpan = powerOf(charset.size(), std::min(suffixLen, maxLow));
        if (!cl.arg(1, static_cast<ClUInt>(suffixLen))) {
            result.detail = "Unable to configure GPU password length.";
            return result;
        }
        for (std::uint64_t p = 0; p < prefixCount; ++p) {
            if (stopRequested.load(std::memory_order_relaxed) ||
                (shouldInterrupt && shouldInterrupt())) {
                result.outcome = GpuRunResult::Outcome::Stopped;
                return result;
            }
            const std::string prefix = decodeIndex(p, prefixLen, charset);
            const auto prefixKeys = keysForPrefix(prefix);
            if (!cl.arg(2, prefixKeys[0]) || !cl.arg(3, prefixKeys[1]) ||
                !cl.arg(4, prefixKeys[2])) {
                result.detail = "Failed to configure GPU prefix key state.";
                return result;
            }
            for (std::uint64_t start = 0; start < suffixCount;) {
                if (stopRequested.load(std::memory_order_relaxed) ||
                    (shouldInterrupt && shouldInterrupt())) {
                    result.outcome = GpuRunResult::Outcome::Stopped;
                    return result;
                }
                const std::uint64_t lowStart = start % lowSpan;
                const std::size_t count = static_cast<std::size_t>(
                    std::min({static_cast<std::uint64_t>(kBatchSize),
                              suffixCount - start, lowSpan - lowStart}));
                const std::array<ClUInt, 2> zero{{0, 0}};
                if (!cl.write(4, zero.data(), sizeof(zero)) ||
                    !cl.arg(8, static_cast<ClUInt>(lowStart)) ||
                    !cl.arg(9, static_cast<ClUInt>(start / lowSpan)) ||
                    cl.enqueueKernel(cl.queue, cl.kernel, 1, nullptr, &count,
                                     nullptr, 0, nullptr, nullptr) != kSuccess) {
                    result.detail = "OpenCL kernel dispatch failed.";
                    return result;
                }
                std::array<ClUInt, 2> counters{};
                if (!cl.read(4, counters.data(), sizeof(counters))) {
                    result.detail = "Unable to retrieve GPU match count.";
                    return result;
                }
                const ClUInt hits = counters[0];
                saturatingAccumulate(result.headerPasses,
                    (input.deflatePrefilterEnabled ||
                     input.storeCrcPrefilterEnabled) ? counters[1] : hits);
                saturatingAccumulate(result.prefilterPasses, hits);
                if (hits > kMaxHits) {
                    // Crucial: never drop unverified candidates. Retry on CPU.
                    result.detail = "GPU candidate buffer overflow; retrying on CPU.";
                    return result;
                }
                if (hits && !cl.read(3, hitOffsets.data(), hits * sizeof(hitOffsets[0]))) {
                    result.detail = "Unable to retrieve GPU candidates.";
                    return result;
                }
                saturatingAdd(triedCount, count);
                // Report *absolute* work, not 524288-sized additions to a
                // double counter. At 16 characters, a relative tiny increment
                // can round to zero; an absolute value remains accurate enough.
                if (reportCompleted) {
                    reportCompleted(completedShorterLengths +
                        static_cast<double>(p) * static_cast<double>(suffixCount) +
                        static_cast<double>(start + count));
                }
                // One submission per GPU batch. The CPU verifies offsets
                // against the same immutable prefix / suffix alphabet.
                if (hits) {
                    GpuCandidateBatch batch;
                    batch.prefix = prefix;
                    batch.startIndex = start;
                    batch.suffixLength = static_cast<std::uint32_t>(suffixLen);
                    batch.offsets.reserve(hits);
                    for (ClUInt i = 0; i < hits; ++i) {
                        if (hitOffsets[i] >= count) {
                            result.detail = "GPU candidate offset is invalid.";
                            return result; // Fallback; no silent skip.
                        }
                        batch.offsets.push_back(hitOffsets[i]);
                    }
                    if (!submitBatch(std::move(batch))) {
                        result.outcome = GpuRunResult::Outcome::Stopped;
                        return result;
                    }
                }
                start += count;
            }
        }
        completedShorterLengths += combinationsThisLength;
    }
    result.outcome = GpuRunResult::Outcome::Completed;
    return result;
}

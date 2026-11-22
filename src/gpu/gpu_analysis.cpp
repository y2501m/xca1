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
constexpr std::size_t kBatchSize = 131072;
constexpr ClUInt kMaxHits = 4096;
constexpr int kMaxGpuSuffix = 8; // 91^8 fits in uint64_t; 91^16 does not.

// Kept as source in the binary: no runtime .cl file or SDK is needed.
// A one-byte header check is a filter only; host verifies every hit via libzip.
constexpr char kKernelSource[] = R"OPENCL(
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
    uint alphabetSize,
    __global const uchar* prefix,
    uint prefixLen,
    uint suffixLen,
    __constant const uchar* encryptedHeader,
    uint checkByte,
    __constant const uint* crcTable,
    ulong start,
    __global uint* hitOffsets,
    volatile __global uint* hitCount,
    uint hitCapacity)
{
    const uint gid = (uint)get_global_id(0);
    ulong index = start + (ulong)gid;
    uchar password[16];
    for (uint i = 0; i < prefixLen; ++i)
        password[i] = prefix[i];
    for (int i = (int)suffixLen - 1; i >= 0; --i) {
        password[prefixLen + (uint)i] = alphabet[(uint)(index % alphabetSize)];
        index /= (ulong)alphabetSize;
    }
    uint k0 = 0x12345678u;
    uint k1 = 0x23456789u;
    uint k2 = 0x34567890u;
    for (uint i = 0; i < prefixLen + suffixLen; ++i)
        update_keys(&k0, &k1, &k2, password[i], crcTable);
    uchar plain = 0;
    for (uint j = 0; j < 12; ++j) {
        uint tmp = (k2 | 2u) & 65535u;
        uchar streamByte = (uchar)((tmp * (tmp ^ 1u)) >> 8);
        plain = encryptedHeader[j] ^ streamByte;
        update_keys(&k0, &k1, &k2, plain, crcTable);
    }
    if ((uint)plain == checkByte) {
        uint position = atomic_inc(hitCount);
        if (position < hitCapacity)
            hitOffsets[position] = gid;
    }
}
)OPENCL";

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
    std::array<ClMem, 6> buffers{};
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
    bool init(std::string& reason) {
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
        err = buildProgram(program, 1, &device, "-cl-std=CL1.2", nullptr, nullptr);
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
        const std::array<std::size_t, 6> sizes{{
            alphabet.size(), 16, input.encryptedHeader.size(),
            256 * sizeof(std::uint32_t), kMaxHits * sizeof(std::uint32_t), sizeof(ClUInt)
        }};
        for (std::size_t i = 0; i < buffers.size(); ++i) {
            ClInt err = 0;
            buffers[i] = createBuffer(context, i >= 4 ? kReadWrite : kReadOnly,
                                      sizes[i], nullptr, &err);
            if (!buffers[i] || err != kSuccess) {
                reason = "clCreateBuffer failed for buffer " + std::to_string(i);
                return false;
            }
        }
        std::array<std::uint32_t, 256> crcTable{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int bit = 0; bit < 8; ++bit)
                c = (c >> 1) ^ ((c & 1u) ? 0xedb88320u : 0u);
            crcTable[i] = c;
        }
        if (!write(0, alphabet.data(), alphabet.size()) ||
            !write(2, input.encryptedHeader.data(), input.encryptedHeader.size()) ||
            !write(3, crcTable.data(), crcTable.size() * sizeof(crcTable[0]))) {
            reason = "Failed to upload ZipCrypto data to GPU."; return false;
        }
        const ClUInt base = static_cast<ClUInt>(alphabet.size());
        const ClUInt check = input.checkByte;
        const ClUInt capacity = kMaxHits;
        if (!argMem(0, 0) || !arg(1, base) || !argMem(2, 1) ||
            !argMem(5, 2) || !arg(6, check) || !argMem(7, 3) ||
            !argMem(9, 4) || !argMem(10, 5) || !arg(11, capacity)) {
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
} // namespace

GpuRunResult runZipCryptoGpu(const ZipCryptoInput& input, const std::string& charset,
                             int maxPasswordLength,
                             std::atomic<bool>& stopRequested,
                             std::atomic<std::uint64_t>& triedCount,
                             const std::function<bool(const std::string&)>& verifyPassword) {
    GpuRunResult result;
    if (charset.empty() || charset.size() > 128 || maxPasswordLength < 1 ||
        maxPasswordLength > 16) {
        result.detail = "Unsupported GPU password alphabet or length.";
        return result;
    }
    OpenCl cl;
    if (!cl.init(result.detail) || !cl.createBuffers(input, charset, result.detail))
        return result;
    result.deviceName = cl.deviceName;
    std::vector<std::uint32_t> hitOffsets(kMaxHits);
    std::array<std::uint8_t, 16> prefixBytes{};

    for (int len = 1; len <= maxPasswordLength; ++len) {
        const int suffixLen = std::min(len, kMaxGpuSuffix);
        const int prefixLen = len - suffixLen;
        const std::uint64_t prefixCount = powerOf(charset.size(), prefixLen);
        const std::uint64_t suffixCount = powerOf(charset.size(), suffixLen);
        if (!cl.arg(3, static_cast<ClUInt>(prefixLen)) ||
            !cl.arg(4, static_cast<ClUInt>(suffixLen))) {
            result.detail = "Unable to configure GPU password length.";
            return result;
        }
        for (std::uint64_t p = 0; p < prefixCount; ++p) {
            if (stopRequested.load(std::memory_order_relaxed)) {
                result.outcome = GpuRunResult::Outcome::Stopped;
                return result;
            }
            const std::string prefix = decodeIndex(p, prefixLen, charset);
            std::copy(prefix.begin(), prefix.end(), prefixBytes.begin());
            if (!cl.write(1, prefixBytes.data(), prefixBytes.size())) {
                result.detail = "Failed to write GPU password prefix.";
                return result;
            }
            for (std::uint64_t start = 0; start < suffixCount;) {
                if (stopRequested.load(std::memory_order_relaxed)) {
                    result.outcome = GpuRunResult::Outcome::Stopped;
                    return result;
                }
                const std::size_t count = static_cast<std::size_t>(
                    std::min<std::uint64_t>(kBatchSize, suffixCount - start));
                const ClUInt zero = 0;
                if (!cl.write(5, &zero, sizeof(zero)) ||
                    !cl.arg(8, static_cast<ClULong>(start)) ||
                    cl.enqueueKernel(cl.queue, cl.kernel, 1, nullptr, &count,
                                     nullptr, 0, nullptr, nullptr) != kSuccess) {
                    result.detail = "OpenCL kernel dispatch failed.";
                    return result;
                }
                ClUInt hits = 0;
                if (!cl.read(5, &hits, sizeof(hits))) {
                    result.detail = "Unable to retrieve GPU match count.";
                    return result;
                }
                if (hits > kMaxHits) {
                    // Crucial: never drop unverified candidates. Retry on CPU.
                    result.detail = "GPU candidate buffer overflow; retrying on CPU.";
                    return result;
                }
                if (hits && !cl.read(4, hitOffsets.data(), hits * sizeof(hitOffsets[0]))) {
                    result.detail = "Unable to retrieve GPU candidates.";
                    return result;
                }
                saturatingAdd(triedCount, count);
                for (ClUInt i = 0; i < hits; ++i) {
                    if (stopRequested.load(std::memory_order_relaxed)) {
                        result.outcome = GpuRunResult::Outcome::Stopped;
                        return result;
                    }
                    if (hitOffsets[i] >= count) {
                        result.detail = "GPU candidate offset is invalid.";
                        return result;
                    }
                    const std::string password = prefix +
                        decodeIndex(start + hitOffsets[i], suffixLen, charset);
                    if (verifyPassword(password)) {
                        result.outcome = GpuRunResult::Outcome::Found;
                        result.password = password;
                        return result;
                    }
                }
                start += count;
            }
        }
    }
    result.outcome = GpuRunResult::Outcome::Completed;
    return result;
}

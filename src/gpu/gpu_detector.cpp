#include "gpu_detector.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace {
// The OpenCL ABI definitions needed for enumeration only. By resolving symbols at
// runtime, this file requires neither OpenCL SDK headers nor OpenCL.lib at build time.
using ClInt = std::int32_t;
using ClUInt = std::uint32_t;
using ClBool = ClUInt;
using ClDeviceType = std::uint64_t;
using ClPlatformId = void*;
using ClDeviceId = void*;
using ClDeviceInfo = ClUInt;

constexpr ClInt CL_SUCCESS_VALUE = 0;
constexpr ClDeviceType CL_DEVICE_TYPE_GPU_VALUE = (1ULL << 2);
constexpr ClDeviceInfo CL_DEVICE_AVAILABLE_VALUE = 0x1027;
constexpr ClDeviceInfo CL_DEVICE_NAME_VALUE = 0x102B;
constexpr ClDeviceInfo CL_DEVICE_VENDOR_VALUE = 0x102C;

using GetPlatformIds = ClInt(WINAPI*)(ClUInt, ClPlatformId*, ClUInt*);
using GetDeviceIds = ClInt(WINAPI*)(ClPlatformId, ClDeviceType, ClUInt, ClDeviceId*, ClUInt*);
using GetDeviceInfo = ClInt(WINAPI*)(ClDeviceId, ClDeviceInfo, std::size_t, void*, std::size_t*);

class OpenClLibrary {
public:
    OpenClLibrary()
        : handle_(LoadLibraryExW(L"OpenCL.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {}
    ~OpenClLibrary() {
        if (handle_) FreeLibrary(handle_);
    }
    OpenClLibrary(const OpenClLibrary&) = delete;
    OpenClLibrary& operator=(const OpenClLibrary&) = delete;
    HMODULE get() const { return handle_; }

private:
    HMODULE handle_ = nullptr;
};

std::string readDeviceString(GetDeviceInfo getInfo, ClDeviceId device, ClDeviceInfo field) {
    std::size_t byteCount = 0;
    if (getInfo(device, field, 0, nullptr, &byteCount) != CL_SUCCESS_VALUE ||
        byteCount == 0 || byteCount > 4096) {
        return {};
    }

    std::vector<char> buffer(byteCount + 1, '\0');
    if (getInfo(device, field, byteCount, buffer.data(), nullptr) != CL_SUCCESS_VALUE) {
        return {};
    }
    return std::string(buffer.data());
}

bool isDeviceAvailable(GetDeviceInfo getInfo, ClDeviceId device) {
    ClBool available = 0;
    return getInfo(device, CL_DEVICE_AVAILABLE_VALUE, sizeof(available),
                   &available, nullptr) == CL_SUCCESS_VALUE && available != 0;
}
} // namespace
#endif

GpuDetection detectOpenCLGpu() {
#ifdef _WIN32
    OpenClLibrary openCl;
    if (!openCl.get()) {
        return {false, "", "OpenCL.dll is not installed or cannot be loaded."};
    }

    const auto getPlatforms = reinterpret_cast<GetPlatformIds>(
        GetProcAddress(openCl.get(), "clGetPlatformIDs"));
    const auto getDevices = reinterpret_cast<GetDeviceIds>(
        GetProcAddress(openCl.get(), "clGetDeviceIDs"));
    const auto getInfo = reinterpret_cast<GetDeviceInfo>(
        GetProcAddress(openCl.get(), "clGetDeviceInfo"));

    if (!getPlatforms || !getDevices || !getInfo) {
        return {false, "", "OpenCL runtime is missing device-enumeration functions."};
    }

    ClUInt platformCount = 0;
    if (getPlatforms(0, nullptr, &platformCount) != CL_SUCCESS_VALUE || platformCount == 0) {
        return {false, "", "No OpenCL platforms were found."};
    }

    std::vector<ClPlatformId> platforms(platformCount);
    if (getPlatforms(platformCount, platforms.data(), nullptr) != CL_SUCCESS_VALUE) {
        return {false, "", "Unable to enumerate OpenCL platforms."};
    }

    GpuDetection firstGpu;
    for (ClPlatformId platform : platforms) {
        ClUInt deviceCount = 0;
        if (getDevices(platform, CL_DEVICE_TYPE_GPU_VALUE, 0, nullptr, &deviceCount)
                != CL_SUCCESS_VALUE || deviceCount == 0) {
            continue;
        }

        std::vector<ClDeviceId> devices(deviceCount);
        if (getDevices(platform, CL_DEVICE_TYPE_GPU_VALUE, deviceCount,
                       devices.data(), nullptr) != CL_SUCCESS_VALUE) {
            continue;
        }

        for (ClDeviceId device : devices) {
            if (!isDeviceAvailable(getInfo, device)) continue;

            std::string name = readDeviceString(getInfo, device, CL_DEVICE_NAME_VALUE);
            std::string vendor = readDeviceString(getInfo, device, CL_DEVICE_VENDOR_VALUE);
            if (name.empty()) name = "Unknown OpenCL GPU";

            GpuDetection detected{true, name, "OpenCL GPU device detected."};
            // Prefer a discrete NVIDIA GPU when multiple OpenCL GPUs exist.
            if (vendor.find("NVIDIA") != std::string::npos ||
                name.find("NVIDIA") != std::string::npos ||
                name.find("GeForce") != std::string::npos) {
                return detected;
            }
            if (!firstGpu.available) firstGpu = detected;
        }
    }

    if (firstGpu.available) return firstGpu;
    return {false, "", "No available OpenCL GPU devices were found."};
#else
    return {false, "", "OpenCL GPU detection is currently implemented for Windows only."};
#endif
}

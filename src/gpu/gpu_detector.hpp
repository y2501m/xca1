#pragma once

#include <string>

struct GpuDetection {
    bool available = false;       // OpenCL GPU device was detected and is available.
    std::string deviceName;
    std::string reason;
};

// GPU detection only. This does not execute ZIP password checks on the GPU.
GpuDetection detectOpenCLGpu();

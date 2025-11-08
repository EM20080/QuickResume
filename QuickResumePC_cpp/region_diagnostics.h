#pragma once
#include <string>
#include <vector>

enum class RegionFailureReason
{
    Success = 0,
    RegionDoesNotExist,
    RegionNotCommitted,
    RegionShrunk,
    ProtectionChangeFailed,
    WriteMemoryFailed,
    PartialWriteOnly
};

struct RegionDiagnostic
{
    uint64_t baseAddress;
    uint64_t savedSize;
    uint64_t currentSize;
    uint32_t savedProtect;
    uint32_t currentProtect;
    uint32_t currentState;
    RegionFailureReason reason;
    std::string details;
};

bool LoadRamStateWithDiagnostics(int pid, const char* inputPath,
                                bool suspendThreads, bool skipExecutable,
                                std::string& outMessage,
                                std::vector<RegionDiagnostic>& diagnostics);

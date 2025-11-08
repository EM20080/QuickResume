#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <unordered_set>

#pragma comment(lib, "psapi.lib")

struct ProcessInfo
{
    int pid;
    std::string name;
    std::string path;
    bool isSystem;
};

static const std::unordered_set<std::string> SYSTEM_PROCESSES = {
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "WUDFHost.exe", "dasHost.exe",
    "spoolsv.exe", "audiodg.exe", "conhost.exe", "sihost.exe", "taskhostw.exe", 
    "SearchIndexer.exe", "RuntimeBroker.exe", "dllhost.exe", "MsMpEng.exe", "NisSrv.exe",
    "SecurityHealthService.exe", "SgrmBroker.exe", "Memory Compression", "Secure System",
    "explorer.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe", "SearchApp.exe",
    "TextInputHost.exe", "ApplicationFrameHost.exe", "SystemSettings.exe", 
    "backgroundTaskHost.exe", "WmiPrvSE.exe", "msdtc.exe", "sppsvc.exe", "VSSVC.exe",
    "wuauclt.exe", "TrustedInstaller.exe"
};

constexpr DWORD MEM_READABLE = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | 
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
constexpr DWORD MEM_WRITABLE = PAGE_READWRITE | PAGE_EXECUTE_READWRITE;
constexpr DWORD MEM_EXECUTABLE = PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

struct RamStateHeader
{
    char magic[10];
    int version;
    int originalPid;
    int64_t timestamp;
    int regionCount;
};

struct RamStateRegion
{
    uint64_t baseAddress;
    uint64_t size;
    uint32_t protect;
    uint32_t state;
    uint32_t type;
};

bool InitRamDumper()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    return result;
}

void ShutdownRamDumper()
{
}

std::vector<ProcessInfo> GetProcessList(bool hideSystemProcesses)
{
    std::vector<ProcessInfo> processes;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return processes;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            
            char procName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, procName, MAX_PATH, NULL, NULL);
            info.name = procName;
            
            info.isSystem = SYSTEM_PROCESSES.find(info.name) != SYSTEM_PROCESSES.end();

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess)
            {
                WCHAR pathBufW[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, pathBufW, &size))
                {
                    char pathBuf[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, pathBufW, -1, pathBuf, MAX_PATH, NULL, NULL);
                    info.path = pathBuf;
                }
                CloseHandle(hProcess);
            }

            if (!hideSystemProcesses || !info.isSystem)
            {
                processes.push_back(info);
            }

        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    std::sort(processes.begin(), processes.end(), 
              [](const ProcessInfo& a, const ProcessInfo& b) {
                  return a.name < b.name;
              });

    return processes;
}

static std::vector<HANDLE> SuspendProcessThreads(DWORD pid)
{
    std::vector<HANDLE> suspendedThreads;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return suspendedThreads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == pid)
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread && hThread != INVALID_HANDLE_VALUE)
                {
                    if (SuspendThread(hThread) != (DWORD)-1)
                    {
                        suspendedThreads.push_back(hThread);
                    }
                    else
                    {
                        CloseHandle(hThread);
                    }
                }
            }
            te32.dwSize = sizeof(THREADENTRY32);
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return suspendedThreads;
}

static void ResumeProcessThreads(std::vector<HANDLE>& threads)
{
    for (auto hThread : threads)
    {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }
    threads.clear();
}

bool DumpProcess(int pid, const char* outputPath, bool suspendThreads, std::string& outMessage)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, 
                                  FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
    {
        outMessage = "try running as administrator maybe that would work.";
        return false;
    }

    std::vector<HANDLE> suspendedThreadHandles;
    if (suspendThreads)
    {
        suspendedThreadHandles = SuspendProcessThreads(pid);
    }

    bool success = false;
    try
    {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        SIZE_T address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            if ((mbi.State & MEM_COMMIT) &&
                (mbi.Protect & MEM_READABLE) &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                !(mbi.Protect & PAGE_GUARD) &&
                mbi.RegionSize > 0)
            {
                regions.push_back(mbi);
            }

            address += mbi.RegionSize;
            if (address == 0) break;
        }

        if (regions.empty())
        {
            outMessage = "No readable memory regions found";
            CloseHandle(hProcess);
            ResumeProcessThreads(suspendedThreadHandles);
            return false;
        }

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile)
        {
            outMessage = "Failed to create output file";
            CloseHandle(hProcess);
            ResumeProcessThreads(suspendedThreadHandles);
            return false;
        }

        RamStateHeader header;
        strcpy_s(header.magic, "QKRESUME1");
        header.version = 1;
        header.originalPid = pid;
        
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        header.timestamp = ((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        header.regionCount = (int)regions.size();

        outFile.write((char*)&header, sizeof(header));

        int successCount = 0;
        int failedCount = 0;
        uint64_t totalBytes = 0;

        for (const auto& mbi : regions)
        {
            RamStateRegion region;
            region.baseAddress = (uint64_t)mbi.BaseAddress;
            region.size = (uint64_t)mbi.RegionSize;
            region.protect = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;

            outFile.write((char*)&region, sizeof(region));

            const size_t CHUNK_SIZE = 16 * 1024 * 1024;
            std::vector<BYTE> buffer(CHUNK_SIZE);
            SIZE_T remaining = mbi.RegionSize;
            SIZE_T offset = 0;
            bool regionSuccess = true;

            while (remaining > 0)
            {
                SIZE_T toRead = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, 
                                     (LPCVOID)((SIZE_T)mbi.BaseAddress + offset),
                                     buffer.data(), toRead, &bytesRead))
                {
                    outFile.write((char*)buffer.data(), bytesRead);
                    totalBytes += bytesRead;
                    
                    if (bytesRead < toRead)
                    {
                        buffer.assign(toRead - bytesRead, 0);
                        outFile.write((char*)buffer.data(), toRead - bytesRead);
                        regionSuccess = false;
                    }
                }
                else
                {
                    buffer.assign(toRead, 0);
                    outFile.write((char*)buffer.data(), toRead);
                    regionSuccess = false;
                }

                offset += toRead;
                remaining -= toRead;
            }

            if (regionSuccess)
                successCount++;
            else
                failedCount++;
        }

        outFile.close();

        char msg[256];
        snprintf(msg, sizeof(msg), "Dumped %d/%d regions (%llu MB)", 
                successCount, (int)regions.size(), totalBytes / (1024 * 1024));
        if (failedCount > 0)
        {
            snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), ", %d had errors", failedCount);
        }
        outMessage = msg;
        success = true;
    }
    catch (...)
    {
        outMessage = "Exception during dump";
    }

    CloseHandle(hProcess);
    ResumeProcessThreads(suspendedThreadHandles);
    
    return success;
}

bool LoadRamState(int pid, const char* inputPath, bool suspendThreads, 
                  bool skipExecutable, std::string& outMessage)
{
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile)
    {
        outMessage = "Failed to open input file";
        return false;
    }

    RamStateHeader header;
    inFile.read((char*)&header, sizeof(header));
    
    if (strncmp(header.magic, "QKRESUME1", 9) != 0 && 
        strncmp(header.magic, "RAMSTATE1", 9) != 0)
    {
        outMessage = "Invalid file format";
        return false;
    }

    bool isNewFormat = (strncmp(header.magic, "QKRESUME1", 9) == 0);

    if (header.regionCount <= 0 || header.regionCount > 100000)
    {
        outMessage = "Invalid region count";
        return false;
    }

    std::vector<RamStateRegion> regions;
    std::vector<std::vector<BYTE>> regionData;

    for (int i = 0; i < header.regionCount; i++)
    {
        RamStateRegion region;
        inFile.read((char*)&region, sizeof(region));
        
        if (!isNewFormat)
        {
            region.state = MEM_COMMIT;
            region.type = MEM_PRIVATE;
        }

        if (region.size > 4ULL * 1024 * 1024 * 1024)
        {
            outMessage = "Invalid region size";
            return false;
        }

        std::vector<BYTE> data(region.size);
        inFile.read((char*)data.data(), region.size);

        if ((size_t)inFile.gcount() != region.size)
        {
            outMessage = "Truncated file";
            return false;
        }

        regions.push_back(region);
        regionData.push_back(std::move(data));
    }

    inFile.close();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | 
                                  PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                  FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
    {
        outMessage = "Failed to open process. Try running as Administrator.";
        return false;
    }

    std::vector<HANDLE> suspendedThreadHandles;
    bool threadsSuspended = false;
    bool success = false;

    try
    {
        int successCount = 0;
        int skippedCount = 0;
        int failedCount = 0;
        uint64_t bytesWritten = 0;

        std::sort(regions.begin(), regions.end(),
                 [](const RamStateRegion& a, const RamStateRegion& b) {
                     return a.baseAddress < b.baseAddress;
                 });

        for (size_t i = 0; i < regions.size(); i++)
        {
            const auto& region = regions[i];
            const auto& data = regionData[i];

            bool isExecutable = (region.protect & MEM_EXECUTABLE) != 0;

            if (skipExecutable && isExecutable)
            {
                skippedCount++;
                continue;
            }

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, (LPCVOID)region.baseAddress, &mbi, sizeof(mbi)) == 0)
            {
                failedCount++;
                continue;
            }

            if ((mbi.State & MEM_COMMIT) == 0)
            {
                failedCount++;
                continue;
            }

            if (mbi.RegionSize < region.size)
            {
                failedCount++;
                continue;
            }

            if (!threadsSuspended && suspendThreads)
            {
                suspendedThreadHandles = SuspendProcessThreads(pid);
                threadsSuspended = true;
            }

            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, (LPVOID)region.baseAddress, mbi.RegionSize,
                                 PAGE_READWRITE, &oldProtect))
            {
                failedCount++;
                continue;
            }

            SIZE_T chunkSize;
            if (region.size > 512ULL * 1024 * 1024)
                chunkSize = 128 * 1024 * 1024;
            else if (region.size > 64ULL * 1024 * 1024)
                chunkSize = 32 * 1024 * 1024;
            else if (region.size > 16ULL * 1024 * 1024)
                chunkSize = 16 * 1024 * 1024;
            else
                chunkSize = region.size;

            SIZE_T remaining = region.size;
            SIZE_T offset = 0;
            bool writeSuccess = true;

            while (remaining > 0 && writeSuccess)
            {
                SIZE_T toWrite = (remaining > chunkSize) ? chunkSize : remaining;
                SIZE_T written = 0;

                if (WriteProcessMemory(hProcess,
                                      (LPVOID)(region.baseAddress + offset),
                                      data.data() + offset, toWrite, &written))
                {
                    bytesWritten += written;
                    
                    if (written == 0)
                    {
                        writeSuccess = false;
                        break;
                    }
                }
                else
                {
                    DWORD error = GetLastError();
                    if (error == ERROR_PARTIAL_COPY)
                    {
                    }
                    else
                    {
                        writeSuccess = false;
                        break;
                    }
                }

                offset += toWrite;
                remaining -= toWrite;
            }

            VirtualProtectEx(hProcess, (LPVOID)region.baseAddress, mbi.RegionSize,
                           oldProtect, &oldProtect);

            if (writeSuccess && isExecutable)
            {
                FlushInstructionCache(hProcess, (LPCVOID)region.baseAddress, region.size);
            }

            if (writeSuccess)
                successCount++;
            else
                failedCount++;
        }

        FlushInstructionCache(hProcess, nullptr, 0);

        char msg[256];
        snprintf(msg, sizeof(msg), "Restored %d/%d regions (%llu MB)",
                successCount, (int)regions.size(), bytesWritten / (1024 * 1024));
        if (skippedCount > 0)
        {
            snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), 
                    ", skipped %d executable", skippedCount);
        }
        if (failedCount > 0)
        {
            snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), 
                    ", %d incompatible", failedCount);
        }
        
        outMessage = msg;
        
        success = (successCount > 0);
    }
    catch (...)
    {
        outMessage = "Exception during restore";
        success = false;
    }

    if (threadsSuspended && !suspendedThreadHandles.empty())
    {
        for (int i = (int)suspendedThreadHandles.size() - 1; i >= 0; i--)
        {
            try
            {
                DWORD suspendCount = ResumeThread(suspendedThreadHandles[i]);
                
                while (suspendCount > 1 && suspendCount != (DWORD)-1)
                {
                    suspendCount = ResumeThread(suspendedThreadHandles[i]);
                }
                
                CloseHandle(suspendedThreadHandles[i]);
            }
            catch (...)
            {
            }
        }
        suspendedThreadHandles.clear();
        
        Sleep(0);
        Sleep(50);
        Sleep(100);
    }

    if (hProcess && hProcess != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hProcess);
    }

    return success;
}

#include "enhanced_snapshot.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <fstream>

static bool RestoreThreadContexts(DWORD pid, const std::vector<ThreadInfo>& threadInfos, std::string& error)
{
    int restored = 0;
    int failed = 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        error = "Failed to create thread snapshot";
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == pid)
            {
                const ThreadInfo* matchingInfo = nullptr;
                for (const auto& ti : threadInfos)
                {
                    if (ti.threadId == te32.th32ThreadID)
                    {
                        matchingInfo = &ti;
                        break;
                    }
                }
                
                if (matchingInfo)
                {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 
                                               FALSE, te32.th32ThreadID);
                    if (hThread && hThread != INVALID_HANDLE_VALUE)
                    {
                        if (SuspendThread(hThread) != (DWORD)-1)
                        {
                            CONTEXT ctx = {};
                            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
                            ctx.Rip = matchingInfo->rip;
                            ctx.Rsp = matchingInfo->rsp;
                            ctx.Rbp = matchingInfo->rbp;
                            ctx.Rax = matchingInfo->rax;
                            ctx.Rbx = matchingInfo->rbx;
                            ctx.Rcx = matchingInfo->rcx;
                            ctx.Rdx = matchingInfo->rdx;
                            ctx.Rsi = matchingInfo->rsi;
                            ctx.Rdi = matchingInfo->rdi;
                            ctx.R8 = matchingInfo->r8;
                            ctx.R9 = matchingInfo->r9;
                            ctx.R10 = matchingInfo->r10;
                            ctx.R11 = matchingInfo->r11;
                            ctx.R12 = matchingInfo->r12;
                            ctx.R13 = matchingInfo->r13;
                            ctx.R14 = matchingInfo->r14;
                            ctx.R15 = matchingInfo->r15;
                            ctx.EFlags = (DWORD)matchingInfo->rflags;
                            ctx.SegCs = matchingInfo->cs;
                            ctx.SegSs = matchingInfo->ss;
                            ctx.SegDs = matchingInfo->ds;
                            ctx.SegEs = matchingInfo->es;
                            ctx.SegFs = matchingInfo->fs;
                            ctx.SegGs = matchingInfo->gs;
                            
                            if (SetThreadContext(hThread, &ctx))
                            {
                                restored++;
                            }
                            else
                            {
                                failed++;
                            }
                            
                            ResumeThread(hThread);
                        }
                        CloseHandle(hThread);
                    }
                }
            }
            te32.dwSize = sizeof(THREADENTRY32);
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    
    if (restored > 0)
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "Restored %d thread contexts (%d failed)", restored, failed);
        error = msg;
        return true;
    }
    
    error = "No thread contexts restored";
    return false;
}

static bool RestoreWindows(DWORD pid, const std::vector<WindowInfo>& windowInfos, std::string& error)
{
    int restored = 0;
    
    for (const auto& wi : windowInfos)
    {
        HWND hwnd = (HWND)wi.hwnd;
        
        if (!IsWindow(hwnd))
            continue;
            
        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);
        if (windowPid != pid)
            continue;
        
        RECT rect = {wi.x, wi.y, wi.x + wi.width, wi.y + wi.height};
        SetWindowPos(hwnd, nullptr, rect.left, rect.top, 
                    rect.right - rect.left, rect.bottom - rect.top,
                    SWP_NOZORDER | SWP_NOACTIVATE);
        
        WINDOWPLACEMENT wp = {};
        wp.length = sizeof(WINDOWPLACEMENT);
        wp.showCmd = wi.showState;
        wp.rcNormalPosition = rect;
        SetWindowPlacement(hwnd, &wp);
        
        restored++;
    }
    
    char msg[128];
    snprintf(msg, sizeof(msg), "Restored %d windows", restored);
    error = msg;
    return restored > 0;
}

static int64_t CalculateTimerDrift(const TimerState& captured)
{
    LARGE_INTEGER currentQpc;
    QueryPerformanceCounter(&currentQpc);
    
    int64_t drift = currentQpc.QuadPart - captured.qpcAtSnapshot;
    
    return drift;
}

bool LoadRamStateEnhanced(int pid, const char* inputPath, bool suspendThreads,
                         bool skipExecutable, bool restoreThreads,
                         bool restoreWindows, std::string& outMessage)
{
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile)
    {
        outMessage = "Failed to open input file";
        return false;
    }

    EnhancedHeader header;
    inFile.read((char*)&header, sizeof(header));
    
    if (memcmp(header.magic, QKRESUME_MAGIC_V2, 9) != 0)
    {
        outMessage = "Not an enhanced snapshot file (V2 format required)";
        return false;
    }

    TimerState timers = {};
    if (header.captureFlags & CAPTURE_TIMERS)
    {
        inFile.read((char*)&timers, sizeof(timers));
    }

    int64_t timerDriftTicks = CalculateTimerDrift(timers);
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    double driftSeconds = (double)timerDriftTicks / freq.QuadPart;

    std::vector<EnhancedMemoryRegion> regions;
    for (uint32_t i = 0; i < header.regionCount; i++)
    {
        EnhancedMemoryRegion region;
        inFile.read((char*)&region, sizeof(region));
        regions.push_back(region);
    }

    std::vector<std::vector<BYTE>> regionData;
    for (const auto& region : regions)
    {
        std::vector<BYTE> data(region.size);
        inFile.read((char*)data.data(), region.size);
        regionData.push_back(std::move(data));
    }

    std::vector<ThreadInfo> threadInfos;
    if (header.captureFlags & CAPTURE_THREADS)
    {
        for (uint32_t i = 0; i < header.threadCount; i++)
        {
            ThreadInfo ti;
            inFile.read((char*)&ti, sizeof(ti));
            threadInfos.push_back(ti);
        }
    }

    std::vector<ModuleInfo> moduleInfos;
    if (header.captureFlags & CAPTURE_MODULES)
    {
        for (uint32_t i = 0; i < header.moduleCount; i++)
        {
            ModuleInfo mi;
            inFile.read((char*)&mi, sizeof(mi));
            
            std::wstring name;
            if (mi.nameLength > 0)
            {
                name.resize(mi.nameLength / sizeof(wchar_t));
                inFile.read((char*)name.data(), mi.nameLength);
            }
            
            moduleInfos.push_back(mi);
        }
    }

    std::vector<WindowInfo> windowInfos;
    if (header.captureFlags & CAPTURE_WINDOWS)
    {
        for (uint32_t i = 0; i < header.windowCount; i++)
        {
            WindowInfo wi;
            inFile.read((char*)&wi, sizeof(wi));
            
            if (wi.titleLength > 0)
                inFile.seekg(wi.titleLength, std::ios::cur);
            if (wi.classLength > 0)
                inFile.seekg(wi.classLength, std::ios::cur);
            
            windowInfos.push_back(wi);
        }
    }

    inFile.close();

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
    {
        outMessage = "Failed to open process with PROCESS_ALL_ACCESS";
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

        if (suspendThreads)
        {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE)
            {
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
                                    suspendedThreadHandles.push_back(hThread);
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
                threadsSuspended = true;
            }
        }

        for (size_t i = 0; i < regions.size(); i++)
        {
            const auto& region = regions[i];
            const auto& data = regionData[i];

            bool isExecutable = (region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            if (skipExecutable && isExecutable)
            {
                skippedCount++;
                continue;
            }

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, (LPCVOID)region.baseAddress, &mbi, sizeof(mbi)) == 0)
            {
                LPVOID allocated = VirtualAllocEx(hProcess, (LPVOID)region.baseAddress, 
                                                 region.size, MEM_COMMIT | MEM_RESERVE, 
                                                 PAGE_READWRITE);
                if (allocated)
                {
                    SIZE_T written = 0;
                    if (WriteProcessMemory(hProcess, allocated, data.data(), region.size, &written))
                    {
                        bytesWritten += written;
                        successCount++;
                        
                        DWORD oldProtect;
                        VirtualProtectEx(hProcess, allocated, region.size, region.protect, &oldProtect);
                        continue;
                    }
                }
                
                failedCount++;
                continue;
            }

            SIZE_T writeSize = region.size;
            bool sizeChanged = false;
            
            if ((mbi.State & MEM_COMMIT) == 0)
            {
                failedCount++;
                continue;
            }
            
            if (mbi.RegionSize < region.size)
            {
                writeSize = mbi.RegionSize;
                sizeChanged = true;
            }

            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, (LPVOID)region.baseAddress, writeSize,
                                 PAGE_READWRITE, &oldProtect))
            {
                failedCount++;
                continue;
            }

            SIZE_T written = 0;
            if (WriteProcessMemory(hProcess, (LPVOID)region.baseAddress,
                                  data.data(), writeSize, &written))
            {
                bytesWritten += written;
                successCount++;
                
                if (sizeChanged)
                {
                    skippedCount++;
                }
            }
            else
            {
                failedCount++;
            }

            VirtualProtectEx(hProcess, (LPVOID)region.baseAddress, writeSize,
                           oldProtect, &oldProtect);

            if (isExecutable)
            {
                FlushInstructionCache(hProcess, (LPCVOID)region.baseAddress, writeSize);
            }
        }

        FlushInstructionCache(hProcess, nullptr, 0);

        char msg[512];
        snprintf(msg, sizeof(msg), 
                "Restored %d/%d regions (%llu MB, drift: %.2fs)",
                successCount, (int)regions.size(), 
                bytesWritten / (1024 * 1024), driftSeconds);
        
        if (restoreThreads && !threadInfos.empty())
        {
            std::string threadMsg;
            if (RestoreThreadContexts(pid, threadInfos, threadMsg))
            {
                strncat_s(msg, sizeof(msg), ", ", _TRUNCATE);
                strncat_s(msg, sizeof(msg), threadMsg.c_str(), _TRUNCATE);
            }
        }

        outMessage = msg;
        success = (successCount > 0);
    }
    catch (...)
    {
        outMessage = "Exception during restore";
        success = false;
    }

    if (threadsSuspended)
    {
        for (int i = (int)suspendedThreadHandles.size() - 1; i >= 0; i--)
        {
            DWORD suspendCount = ResumeThread(suspendedThreadHandles[i]);
            while (suspendCount > 1 && suspendCount != (DWORD)-1)
            {
                suspendCount = ResumeThread(suspendedThreadHandles[i]);
            }
            CloseHandle(suspendedThreadHandles[i]);
        }
        Sleep(150);
    }

    if (restoreWindows && !windowInfos.empty())
    {
        std::string windowMsg;
        RestoreWindows(pid, windowInfos, windowMsg);
    }

    CloseHandle(hProcess);
    return success;
}

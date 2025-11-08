#include "enhanced_snapshot.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#ifndef THREAD_BASIC_INFORMATION
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
#endif

static uint64_t GetThreadStartAddress(HANDLE hThread)
{
    typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );

    static pNtQueryInformationThread NtQueryInformationThread = nullptr;
    if (!NtQueryInformationThread)
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
    }

    if (!NtQueryInformationThread)
        return 0;

    PVOID startAddress = nullptr;
    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddress, sizeof(startAddress), nullptr);
    
    return (status == 0) ? (uint64_t)startAddress : 0;
}

static uint64_t GetThreadTEB(HANDLE hThread)
{
    THREAD_BASIC_INFORMATION tbi;
    typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );

    static pNtQueryInformationThread NtQueryInformationThread = nullptr;
    if (!NtQueryInformationThread)
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
    }

    if (!NtQueryInformationThread)
        return 0;

    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), nullptr);
    return (status == 0) ? (uint64_t)tbi.TebBaseAddress : 0;
}

static std::vector<CapturedThread> CaptureThreads(DWORD pid)
{
    std::vector<CapturedThread> threads;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return threads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == pid)
            {
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, 
                                           FALSE, te32.th32ThreadID);
                if (hThread && hThread != INVALID_HANDLE_VALUE)
                {
                    CapturedThread capturedThread = {};
                    capturedThread.handle = hThread;
                    capturedThread.threadId = te32.th32ThreadID;
                    
                    if (SuspendThread(hThread) != (DWORD)-1)
                    {
                        CONTEXT ctx = {};
                        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
                        if (GetThreadContext(hThread, &ctx))
                        {
                            capturedThread.context = ctx;
                        }
                        
                        capturedThread.tebAddress = GetThreadTEB(hThread);
                        capturedThread.stackBase = 0;
                        capturedThread.stackLimit = 0;
                        
                        ResumeThread(hThread);
                    }
                    
                    threads.push_back(capturedThread);
                    CloseHandle(hThread);
                }
            }
            te32.dwSize = sizeof(THREADENTRY32);
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threads;
}

static std::vector<CapturedModule> CaptureModules(HANDLE hProcess)
{
    std::vector<CapturedModule> modules;
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            {
                CapturedModule mod = {};
                mod.baseAddress = (uint64_t)modInfo.lpBaseOfDll;
                mod.size = modInfo.SizeOfImage;
                mod.entryPoint = (uint64_t)modInfo.EntryPoint;
                
                WCHAR szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH))
                {
                    mod.name = szModName;
                }
                
                modules.push_back(mod);
            }
        }
    }
    
    return modules;
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    auto* windows = reinterpret_cast<std::vector<CapturedWindow>*>(lParam);
    
    DWORD processId = 0;
    DWORD threadId = GetWindowThreadProcessId(hwnd, &processId);
    
    if (processId == GetCurrentProcessId())
    {
        CapturedWindow window = {};
        window.hwnd = hwnd;
        window.threadId = threadId;
        
        GetWindowRect(hwnd, &window.rect);
        
        window.style = GetWindowLong(hwnd, GWL_STYLE);
        window.exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        
        WINDOWPLACEMENT wp = {};
        wp.length = sizeof(WINDOWPLACEMENT);
        if (GetWindowPlacement(hwnd, &wp))
        {
            window.showState = wp.showCmd;
        }
        
        WCHAR title[512];
        if (GetWindowTextW(hwnd, title, 512) > 0)
        {
            window.title = title;
        }
        
        WCHAR className[256];
        if (GetClassNameW(hwnd, className, 256) > 0)
        {
            window.className = className;
        }
        
        windows->push_back(window);
    }
    
    return TRUE;
}

static std::vector<CapturedWindow> CaptureWindows(DWORD pid)
{
    std::vector<CapturedWindow> windows;
    
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&windows));
    
    return windows;
}

static TimerState CaptureTimers()
{
    TimerState timers = {};
    
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    timers.qpcFrequency = freq.QuadPart;
    
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    timers.qpcAtSnapshot = qpc.QuadPart;
    
    timers.tickCountAtSnapshot = GetTickCount64();
    
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    timers.systemTimeAtSnapshot = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    
    return timers;
}

bool DumpProcessEnhanced(int pid, const char* outputPath, bool suspendThreads, 
                        uint32_t captureFlags, std::string& outMessage)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
    {
        outMessage = "Failed to open process with PROCESS_ALL_ACCESS. Run as Administrator.";
        return false;
    }

    EnhancedHeader header = {};
    memcpy(header.magic, QKRESUME_MAGIC_V2, 9);
    header.version = QKRESUME_VERSION;
    header.compressionType = COMPRESS_NONE;
    header.originalPid = pid;
    header.captureFlags = captureFlags;
    
    TimerState timers = CaptureTimers();
    header.snapshotTime = timers.systemTimeAtSnapshot;
    header.qpcValue = timers.qpcAtSnapshot;

    std::vector<CapturedThread> threads;
    if (captureFlags & CAPTURE_THREADS)
    {
        threads = CaptureThreads(pid);
        header.threadCount = (uint32_t)threads.size();
    }

    std::vector<CapturedModule> modules;
    if (captureFlags & CAPTURE_MODULES)
    {
        modules = CaptureModules(hProcess);
        header.moduleCount = (uint32_t)modules.size();
    }

    std::vector<CapturedWindow> windows;
    if (captureFlags & CAPTURE_WINDOWS)
    {
        windows = CaptureWindows(pid);
        header.windowCount = (uint32_t)windows.size();
    }

    std::vector<MEMORY_BASIC_INFORMATION> memRegions;
    SIZE_T address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if ((mbi.State & MEM_COMMIT) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize > 0)
        {
            memRegions.push_back(mbi);
        }
        address += mbi.RegionSize;
        if (address == 0) break;
    }
    
    header.regionCount = (uint32_t)memRegions.size();

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile)
    {
        outMessage = "Failed to create output file";
        CloseHandle(hProcess);
        return false;
    }

    outFile.write((char*)&header, sizeof(header));
    
    if (captureFlags & CAPTURE_TIMERS)
    {
        outFile.write((char*)&timers, sizeof(timers));
    }

    std::vector<EnhancedMemoryRegion> enhancedRegions;
    for (const auto& mbi : memRegions)
    {
        EnhancedMemoryRegion region = {};
        region.baseAddress = (uint64_t)mbi.BaseAddress;
        region.size = (uint64_t)mbi.RegionSize;
        region.compressedSize = 0;
        region.protect = mbi.Protect;
        region.state = mbi.State;
        region.type = mbi.Type;
        
        enhancedRegions.push_back(region);
        outFile.write((char*)&region, sizeof(region));
    }

    uint64_t totalBytes = 0;
    const size_t CHUNK_SIZE = 16 * 1024 * 1024;
    std::vector<BYTE> buffer(CHUNK_SIZE);
    
    for (size_t i = 0; i < memRegions.size(); i++)
    {
        const auto& mbi = memRegions[i];
        SIZE_T remaining = mbi.RegionSize;
        SIZE_T offset = 0;
        
        while (remaining > 0)
        {
            SIZE_T toRead = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
            SIZE_T bytesRead = 0;
            
            if (ReadProcessMemory(hProcess, (LPCVOID)((SIZE_T)mbi.BaseAddress + offset),
                                buffer.data(), toRead, &bytesRead))
            {
                outFile.write((char*)buffer.data(), bytesRead);
                totalBytes += bytesRead;
                
                if (bytesRead < toRead)
                {
                    buffer.assign(toRead - bytesRead, 0);
                    outFile.write((char*)buffer.data(), toRead - bytesRead);
                }
            }
            else
            {
                buffer.assign(toRead, 0);
                outFile.write((char*)buffer.data(), toRead);
            }
            
            offset += toRead;
            remaining -= toRead;
        }
    }

    for (const auto& thread : threads)
    {
        ThreadInfo ti = {};
        ti.threadId = thread.threadId;
        ti.tebAddress = thread.tebAddress;
        ti.stackBase = thread.stackBase;
        ti.stackLimit = thread.stackLimit;
        
        ti.rip = thread.context.Rip;
        ti.rsp = thread.context.Rsp;
        ti.rbp = thread.context.Rbp;
        ti.rax = thread.context.Rax;
        ti.rbx = thread.context.Rbx;
        ti.rcx = thread.context.Rcx;
        ti.rdx = thread.context.Rdx;
        ti.rsi = thread.context.Rsi;
        ti.rdi = thread.context.Rdi;
        ti.r8 = thread.context.R8;
        ti.r9 = thread.context.R9;
        ti.r10 = thread.context.R10;
        ti.r11 = thread.context.R11;
        ti.r12 = thread.context.R12;
        ti.r13 = thread.context.R13;
        ti.r14 = thread.context.R14;
        ti.r15 = thread.context.R15;
        ti.rflags = thread.context.EFlags;
        ti.cs = thread.context.SegCs;
        ti.ss = thread.context.SegSs;
        ti.ds = thread.context.SegDs;
        ti.es = thread.context.SegEs;
        ti.fs = thread.context.SegFs;
        ti.gs = thread.context.SegGs;
        
        outFile.write((char*)&ti, sizeof(ti));
    }

    for (const auto& mod : modules)
    {
        ModuleInfo mi = {};
        mi.baseAddress = mod.baseAddress;
        mi.entryPoint = mod.entryPoint;
        mi.size = mod.size;
        mi.nameLength = (uint32_t)(mod.name.length() * sizeof(wchar_t));
        
        outFile.write((char*)&mi, sizeof(mi));
        outFile.write((char*)mod.name.c_str(), mi.nameLength);
    }

    for (const auto& win : windows)
    {
        WindowInfo wi = {};
        wi.hwnd = (uint64_t)win.hwnd;
        wi.threadId = win.threadId;
        wi.style = win.style;
        wi.exStyle = win.exStyle;
        wi.x = win.rect.left;
        wi.y = win.rect.top;
        wi.width = win.rect.right - win.rect.left;
        wi.height = win.rect.bottom - win.rect.top;
        wi.showState = win.showState;
        wi.titleLength = (uint32_t)(win.title.length() * sizeof(wchar_t));
        wi.classLength = (uint32_t)(win.className.length() * sizeof(wchar_t));
        
        outFile.write((char*)&wi, sizeof(wi));
        outFile.write((char*)win.title.c_str(), wi.titleLength);
        outFile.write((char*)win.className.c_str(), wi.classLength);
    }

    header.totalUncompressedSize = totalBytes;
    header.totalCompressedSize = totalBytes;
    
    outFile.seekp(0);
    outFile.write((char*)&header, sizeof(header));
    
    outFile.close();
    CloseHandle(hProcess);

    char msg[512];
    snprintf(msg, sizeof(msg), 
            "Enhanced dump: %d regions (%llu MB), %d threads, %d modules, %d windows",
            header.regionCount, totalBytes / (1024 * 1024),
            header.threadCount, header.moduleCount, header.windowCount);
    outMessage = msg;

    return true;
}

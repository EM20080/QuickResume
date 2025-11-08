// Enhanced Quick Resume Snapshot Format v2
// Captures additional process state beyond just memory

#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <vector>
#include <string>

constexpr char QKRESUME_MAGIC_V2[] = "QKRESV2\0\0";
constexpr int QKRESUME_VERSION = 2;

constexpr uint32_t COMPRESS_NONE = 0;
constexpr uint32_t COMPRESS_LZ4 = 1;

struct EnhancedHeader
{
    char magic[9];
    uint32_t version;
    uint32_t compressionType;
    
    uint32_t originalPid;
    int64_t snapshotTime;
    int64_t qpcValue;
    
    uint32_t regionCount;
    uint32_t handleCount;
    uint32_t threadCount;
    uint32_t moduleCount;
    uint32_t windowCount;
    
    uint64_t totalUncompressedSize;
    uint64_t totalCompressedSize;
    
    uint32_t captureFlags;
    uint32_t reserved[8];
};

constexpr uint32_t CAPTURE_MEMORY = 0x0001;
constexpr uint32_t CAPTURE_HANDLES = 0x0002;
constexpr uint32_t CAPTURE_THREADS = 0x0004;
constexpr uint32_t CAPTURE_MODULES = 0x0008;
constexpr uint32_t CAPTURE_WINDOWS = 0x0010;
constexpr uint32_t CAPTURE_TIMERS = 0x0020;

struct EnhancedMemoryRegion
{
    uint64_t baseAddress;
    uint64_t size;
    uint64_t compressedSize;
    uint32_t protect;
    uint32_t state;
    uint32_t type;
    uint32_t reserved;
};

struct HandleInfo
{
    uint64_t handle;
    uint32_t handleType;
    uint32_t accessRights;
    uint32_t flags;
    uint32_t nameLength;
};

constexpr uint32_t HANDLE_TYPE_FILE = 1;
constexpr uint32_t HANDLE_TYPE_SOCKET = 2;
constexpr uint32_t HANDLE_TYPE_MUTEX = 3;
constexpr uint32_t HANDLE_TYPE_EVENT = 4;
constexpr uint32_t HANDLE_TYPE_SEMAPHORE = 5;
constexpr uint32_t HANDLE_TYPE_THREAD = 6;
constexpr uint32_t HANDLE_TYPE_PROCESS = 7;
constexpr uint32_t HANDLE_TYPE_REGISTRY = 8;
constexpr uint32_t HANDLE_TYPE_DEVICE = 9;
constexpr uint32_t HANDLE_TYPE_UNKNOWN = 0xFF;

struct ThreadInfo
{
    uint32_t threadId;
    uint32_t suspendCount;
    uint64_t startAddress;
    uint64_t stackBase;
    uint64_t stackLimit;
    uint64_t tebAddress;
    
    uint64_t rip, rsp, rbp;
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rflags;
    
    uint16_t cs, ss, ds, es, fs, gs;
    uint16_t reserved[2];
};

struct ModuleInfo
{
    uint64_t baseAddress;
    uint64_t entryPoint;
    uint64_t size;
    uint32_t nameLength;
    uint32_t reserved;
};

struct WindowInfo
{
    uint64_t hwnd;
    uint32_t threadId;
    uint32_t processId;
    uint32_t style;
    uint32_t exStyle;
    int32_t x, y, width, height;
    uint32_t showState;
    uint32_t titleLength;
    uint32_t classLength;
    uint32_t reserved;
};

struct TimerState
{
    int64_t qpcFrequency;
    int64_t qpcAtSnapshot;
    int64_t tickCountAtSnapshot;
    uint64_t systemTimeAtSnapshot;
};

struct CapturedHandle
{
    HANDLE handle;
    uint32_t type;
    uint32_t access;
    std::wstring name;
    std::vector<uint8_t> metadata;
};

struct CapturedThread
{
    HANDLE handle;
    DWORD threadId;
    CONTEXT context;
    uint64_t tebAddress;
    uint64_t stackBase;
    uint64_t stackLimit;
};

struct CapturedModule
{
    uint64_t baseAddress;
    uint64_t size;
    uint64_t entryPoint;
    std::wstring name;
};

struct CapturedWindow
{
    HWND hwnd;
    DWORD threadId;
    RECT rect;
    DWORD style;
    DWORD exStyle;
    int showState;
    std::wstring title;
    std::wstring className;
};

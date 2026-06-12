#pragma once

//
// Globals.h - 驱动全局上下文、结构体定义、未导出内核函数声明
//

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "Debug.h"

// ============================================================================
// 内核模式下缺少的用户态常量
// ============================================================================

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION        0x0008
#endif

#ifndef MEM_IMAGE
#define MEM_IMAGE                   0x1000000
#endif

#ifndef MEM_MAPPED
#define MEM_MAPPED                  0x40000
#endif

#ifndef MEM_PRIVATE
#define MEM_PRIVATE                 0x20000
#endif

#ifndef MEM_COMMIT
#define MEM_COMMIT                  0x1000
#endif

#ifndef MEM_FREE
#define MEM_FREE                    0x10000
#endif

#ifndef MEM_RESERVE
#define MEM_RESERVE                 0x2000
#endif

// ============================================================================
// 驱动设备上下文
// ============================================================================

typedef struct _DUMPER_DEVICE_CONTEXT
{
    // 目标进程
    PEPROCESS       TargetProcess;
    HANDLE          TargetProcessId;

    // 共享内存 (命名 Section + MmMapViewInSystemSpace)
    HANDLE          SectionHandle;          // ZwCreateSection 返回的句柄
    PVOID           SharedMemoryKernelVa;   // MmMapViewInSystemSpace 映射地址
    ULONG           SharedMemorySize;

    // 同步事件 (PKEVENT 对象指针 + HANDLE 句柄)
    PKEVENT         RequestEvent;           // 用户态通知驱动有新命令
    PKEVENT         ResponseEvent;          // 驱动通知用户态命令完成
    HANDLE          RequestEventHandle;
    HANDLE          ResponseEventHandle;

    // 工作线程
    PKTHREAD        WorkerThread;
    volatile BOOLEAN WorkerShouldStop;
    KEVENT          WorkerStopEvent;

    // 初始化标志
    BOOLEAN         Initialized;

} DUMPER_DEVICE_CONTEXT, *PDUMPER_DEVICE_CONTEXT;

// ============================================================================
// 未导出/缺失内核函数声明 (集中管理，避免各模块重复声明)
// ============================================================================

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize
);

NTKERNELAPI NTSTATUS PsSuspendProcess(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS PsResumeProcess(_In_ PEPROCESS Process);

// 线程上下文获取
NTKERNELAPI
NTSTATUS
PsGetContextThread(
    _In_ PETHREAD Thread,
    _Inout_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE PreviousMode
);

// PEB 访问
NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);

// WoW64 检测 (返回 PEB32 地址, NULL = 非 WoW64)
NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);

// 进程 SectionBaseAddress
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);

// SeLocateProcessImageName 已在 ntifs.h 中声明, 无需重复声明

// ZwQuerySystemInformation (用于线程枚举)
// SystemProcessInformation = 5
#define SystemProcessInformation 5

typedef struct _SYSTEM_THREAD_INFORMATION_ENTRY
{
    LARGE_INTEGER   KernelTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   CreateTime;
    ULONG           WaitTime;
    PVOID           StartAddress;
    CLIENT_ID       ClientId;
    KPRIORITY       Priority;
    LONG            BasePriority;
    ULONG           ContextSwitches;
    ULONG           ThreadState;
    ULONG           WaitReason;
} SYSTEM_THREAD_INFORMATION_ENTRY, *PSYSTEM_THREAD_INFORMATION_ENTRY;

typedef struct _SYSTEM_PROCESS_INFORMATION_ENTRY
{
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
    SYSTEM_THREAD_INFORMATION_ENTRY Threads[1];
} SYSTEM_PROCESS_INFORMATION_ENTRY, *PSYSTEM_PROCESS_INFORMATION_ENTRY;

NTKERNELAPI
NTSTATUS
ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// ============================================================================
// PE 头结构体 (内核模式下不可用, 手动定义)
// ============================================================================

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif

#pragma pack(push, 1)

typedef struct _K_IMAGE_DOS_HEADER {
    USHORT  e_magic;
    USHORT  e_cblp;
    USHORT  e_cp;
    USHORT  e_crlc;
    USHORT  e_cparhdr;
    USHORT  e_minalloc;
    USHORT  e_maxalloc;
    USHORT  e_ss;
    USHORT  e_sp;
    USHORT  e_csum;
    USHORT  e_ip;
    USHORT  e_cs;
    USHORT  e_lfarlc;
    USHORT  e_ovno;
    USHORT  e_res[4];
    USHORT  e_oemid;
    USHORT  e_oeminfo;
    USHORT  e_res2[10];
    LONG    e_lfanew;
} K_IMAGE_DOS_HEADER;

typedef struct _K_IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} K_IMAGE_FILE_HEADER;

typedef struct _K_IMAGE_OPTIONAL_HEADER64 {
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONGLONG ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
} K_IMAGE_OPTIONAL_HEADER64;

typedef struct _K_IMAGE_OPTIONAL_HEADER32 {
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;
    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
} K_IMAGE_OPTIONAL_HEADER32;

typedef struct _K_IMAGE_NT_HEADERS64 {
    ULONG Signature;
    K_IMAGE_FILE_HEADER FileHeader;
    K_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} K_IMAGE_NT_HEADERS64;

typedef struct _K_IMAGE_NT_HEADERS32 {
    ULONG Signature;
    K_IMAGE_FILE_HEADER FileHeader;
    K_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} K_IMAGE_NT_HEADERS32;

#pragma pack(pop)

// ============================================================================
// 内核态 MEMORY_BASIC_INFORMATION (ntifs.h 不提供此结构体)
// ============================================================================

typedef struct _MEMORY_BASIC_INFORMATION_KERNEL
{
    PVOID       BaseAddress;
    PVOID       AllocationBase;
    ULONG       AllocationProtect;
    SIZE_T      RegionSize;
    ULONG       State;
    ULONG       Protect;
    ULONG       Type;
} MEMORY_BASIC_INFORMATION_KERNEL, *PMEMORY_BASIC_INFORMATION_KERNEL;

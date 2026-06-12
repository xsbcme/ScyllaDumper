#pragma once

//
// DumperProtocol.h - 驱动与用户态共享内存通信协议
//
// 通信模型 (KDMapper 兼容):
//   驱动在 DriverEntry 创建命名 Section + 命名 Event →
//   驱动用 MmMapViewInSystemSpace 映射到内核地址空间 →
//   用户态通过 OpenFileMapping/OpenEvent 打开同名对象 →
//   双方通过 Event 信号做请求/响应同步
//

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif
#endif

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union

// ============================================================================
// 版本与常量
// ============================================================================
//
// DUMPER_PROTOCOL_VERSION — 协议 ABI 版本号（用户态与驱动必须一致）
//
// 含义：双方对「共享内存头布局、Params 联合体、数据区约定、命令语义」是否兼容。
// 连接时校验，不一致则拒绝通信，避免旧驱动 + 新客户端（或反之）静默错位。
//
// 何时必须升高版本（破坏性变更）：
//   - 修改 DUMPER_SHARED_HEADER / Params 任意字段布局或含义
//   - 修改已有命令的输入、输出或数据缓冲区格式
//   - 调整已有 DUMPER_COMMAND_TYPE 的数值（除非旧端永不再用）
//   - 修改共享 Section 大小、事件名等导致无法共存的约定
//
// 何时不必仅因「新增命令」就升版本：
//   - 仅追加新命令，且命令枚举使用显式固定数值（见下方 =1,=2,...），
//     不改动已有命令的数值与语义，且 Header/Params 布局不变。
//   此时旧驱动仍能理解旧命令；不认识的新命令应由驱动返回明确错误。
//
// 实践：若希望「每次发版强制同编」，也可在任意协议变更时升版本；但这不是语法规则。
//

#define DUMPER_PROTOCOL_VERSION     3   // 与 v2 不兼容：命名 Section/Event/Device 使用 DUMPER_OBJECT_NAME_TAG
#define DUMPER_SHARED_MEMORY_SIZE   (4 * 1024 * 1024)  // 4 MB 共享缓冲区
#define DUMPER_DATA_BUFFER_SIZE     (DUMPER_SHARED_MEMORY_SIZE - sizeof(DUMPER_SHARED_HEADER))

//
// 命名对象唯一标签（Section / Event / 可选 Device 名后缀）
//
// - Windows 不会替你「独占」某个名字；无法阻止别的程序也创建同名对象。
// - 做法：把默认的通用名（如 DumperSharedSection）换成带 GUID/项目前缀的标签，
//   与第三方、示例代码撞名的概率会极低；改标签后必须同时重编驱动与用户态。
//
// 仅改此宏即可；名称由标签拼接而成，勿在别处再写死一套路径。
//
#define DUMPER_OBJECT_NAME_TAG      L"Xsbcme_2974550071@qq.com_Dumper"

#define DUMPER_DEVICE_NAME          L"\\Device\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG
#define DUMPER_SYMBOLIC_LINK        L"\\DosDevices\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG
#define DUMPER_USERMODE_PATH        L"\\\\.\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG

#define DUMPER_SECTION_NAME         L"\\BaseNamedObjects\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_Section"
#define DUMPER_REQUEST_EVENT_NAME   L"\\BaseNamedObjects\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_RequestEvent"
#define DUMPER_RESPONSE_EVENT_NAME  L"\\BaseNamedObjects\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_ResponseEvent"

// 用户态：Global\ 与内核 \BaseNamedObjects\ 下同名对象对应
#define DUMPER_SECTION_NAME_USER    L"Global\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_Section"
#define DUMPER_REQUEST_EVENT_USER   L"Global\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_RequestEvent"
#define DUMPER_RESPONSE_EVENT_USER  L"Global\\ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_ResponseEvent"

// OpenFileMapping/OpenEvent 失败时，再试当前会话命名空间（无 Global\ 前缀）
#define DUMPER_SECTION_NAME_USER_SESSION   L"ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_Section"
#define DUMPER_REQUEST_EVENT_USER_SESSION  L"ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_RequestEvent"
#define DUMPER_RESPONSE_EVENT_USER_SESSION L"ScyllaDumper_" DUMPER_OBJECT_NAME_TAG L"_ResponseEvent"

// ============================================================================
// 命令类型
// ============================================================================

typedef enum _DUMPER_COMMAND_TYPE
{
    DumperCmdNone = 0,

    // 进程操作
    DumperCmdOpenProcess = 1,       // 打开进程获取内核句柄
    DumperCmdCloseProcess = 2,      // 关闭内核进程引用

    // 内存操作 (核心)
    DumperCmdReadMemory = 3,        // 读取目标进程内存
    DumperCmdWriteMemory = 4,       // 写入目标进程内存
    DumperCmdQueryMemory = 5,       // 查询内存区域信息
    DumperCmdReadMemoryPartial = 6, // 部分读取（跳过未提交页面）

    // 内存保护
    DumperCmdProtectMemory = 7,     // 修改内存保护属性

    // 进程控制
    DumperCmdSuspendProcess = 8,    // 挂起进程
    DumperCmdResumeProcess = 9,     // 恢复进程

    // 模块枚举
    DumperCmdEnumModules = 10,      // 枚举进程模块

    // 进程/线程信息 (驱动层获取，对保护进程有效)
    DumperCmdEnumThreads = 11,      // 枚举进程线程
    DumperCmdGetThreadContext = 12, // 获取线程上下文 (寄存器)
    DumperCmdGetProcessInfo = 13,   // 获取进程信息 (PEB, ImageBase等)

    // 进程枚举 (无需先 OpenProcess)
    DumperCmdEnumProcesses = 14,    // 枚举系统所有进程

    // 控制
    DumperCmdShutdown = 15,         // 通知驱动关闭工作线程并释放资源

    DumperCmdMax
} DUMPER_COMMAND_TYPE;

// ============================================================================
// 状态码
// ============================================================================

typedef enum _DUMPER_STATUS
{
    DumperStatusIdle = 0,           // 空闲，可以接受新命令
    DumperStatusPending,            // 命令已提交，等待驱动处理
    DumperStatusCompleted,          // 命令已完成
    DumperStatusError               // 命令执行出错
} DUMPER_STATUS;

// ============================================================================
// 共享内存头部 (位于共享内存起始位置)
// ============================================================================

typedef struct _DUMPER_SHARED_HEADER
{
    // 版本校验
    ULONG       ProtocolVersion;

    // 命令/状态 (用户态写命令，驱动写状态)
    volatile DUMPER_COMMAND_TYPE Command;
    volatile DUMPER_STATUS      Status;
    volatile NTSTATUS           NtStatus;       // 驱动返回的 NTSTATUS

    // 命令参数联合体
    union
    {
        // DumperCmdOpenProcess
        struct
        {
            ULONG   ProcessId;
        } OpenProcess;

        // DumperCmdCloseProcess
        struct
        {
            ULONG   Reserved;
        } CloseProcess;

        // DumperCmdReadMemory / DumperCmdReadMemoryPartial
        struct
        {
            ULONGLONG   BaseAddress;
            ULONG       Size;               // 请求读取大小
            ULONG       BytesRead;          // 实际读取大小 (驱动填写)
        } ReadMemory;

        // DumperCmdWriteMemory
        struct
        {
            ULONGLONG   BaseAddress;
            ULONG       Size;               // 写入大小
            ULONG       BytesWritten;       // 实际写入大小 (驱动填写)
        } WriteMemory;

        // DumperCmdQueryMemory
        struct
        {
            ULONGLONG   BaseAddress;
            ULONGLONG   AllocationBase;     // 输出
            ULONGLONG   RegionSize;         // 输出
            ULONG       State;              // 输出: MEM_COMMIT, MEM_FREE, MEM_RESERVE
            ULONG       Protect;            // 输出: PAGE_XXX
            ULONG       Type;               // 输出: MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
        } QueryMemory;

        // DumperCmdProtectMemory
        struct
        {
            ULONGLONG   BaseAddress;
            ULONG       Size;
            ULONG       NewProtect;
            ULONG       OldProtect;         // 输出
        } ProtectMemory;

        // DumperCmdSuspendProcess / DumperCmdResumeProcess
        struct
        {
            ULONG       Reserved;
        } ProcessControl;

        // DumperCmdEnumModules
        struct
        {
            ULONG       ModuleCount;        // 输出
            ULONG       TotalSize;          // 数据缓冲区中的总大小
        } EnumModules;

        // DumperCmdEnumThreads
        struct
        {
            ULONG       ThreadCount;        // 输出
            ULONG       TotalSize;          // 数据缓冲区中的总大小
        } EnumThreads;

        // DumperCmdGetThreadContext
        struct
        {
            ULONG       ThreadId;           // 输入: 线程ID
            ULONG       ContextFlags;       // 输入: CONTEXT_XXX 标志
            // 输出在数据缓冲区 (DUMPER_THREAD_CONTEXT)
        } GetThreadContext;

        // DumperCmdGetProcessInfo
        struct
        {
            ULONGLONG   PebAddress;         // 输出: PEB 地址
            ULONGLONG   ImageBase;          // 输出: 进程映像基址
            ULONGLONG   EntryPoint;         // 输出: 入口点 (AddressOfEntryPoint + ImageBase)
            ULONG       IsWow64;            // 输出: 是否 WoW64 进程
            ULONG       ParentProcessId;    // 输出: 父进程 ID
        } ProcessInfo;

        // DumperCmdEnumProcesses
        struct
        {
            ULONG       ProcessCount;       // 输出: 进程数量
            ULONG       TotalSize;          // 数据缓冲区中的总大小
        } EnumProcesses;

    } Params;

    // 数据缓冲区偏移标记 (数据紧跟 header 之后)
    // DataBuffer starts at ((PUCHAR)SharedHeader + sizeof(DUMPER_SHARED_HEADER))

} DUMPER_SHARED_HEADER, *PDUMPER_SHARED_HEADER;

// ============================================================================
// 模块枚举条目 (存储在数据缓冲区中)
// ============================================================================

typedef struct _DUMPER_MODULE_ENTRY
{
    ULONGLONG   BaseAddress;
    ULONG       Size;
    WCHAR       FullPath[260];
} DUMPER_MODULE_ENTRY, *PDUMPER_MODULE_ENTRY;

// ============================================================================
// 进程枚举条目 (存储在数据缓冲区中)
// ============================================================================

typedef struct _DUMPER_PROCESS_ENTRY
{
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG       ThreadCount;
    ULONGLONG   WorkingSetSize;         // 内存占用
    WCHAR       ImageName[260];         // 进程名
} DUMPER_PROCESS_ENTRY, *PDUMPER_PROCESS_ENTRY;

// ============================================================================
// 线程枚举条目 (存储在数据缓冲区中)
// ============================================================================

typedef struct _DUMPER_THREAD_ENTRY
{
    ULONG       ThreadId;
    ULONGLONG   StartAddress;
    ULONG       State;              // KTHREAD_STATE
    ULONG       WaitReason;         // KWAIT_REASON
    LONG        Priority;
    LONG        BasePriority;
} DUMPER_THREAD_ENTRY, *PDUMPER_THREAD_ENTRY;

// ============================================================================
// 线程上下文 (精简版, 写入数据缓冲区)
// ============================================================================

typedef struct _DUMPER_THREAD_CONTEXT
{
    // 通用寄存器
    ULONGLONG   Rax;
    ULONGLONG   Rbx;
    ULONGLONG   Rcx;
    ULONGLONG   Rdx;
    ULONGLONG   Rsi;
    ULONGLONG   Rdi;
    ULONGLONG   Rbp;
    ULONGLONG   Rsp;
    ULONGLONG   R8;
    ULONGLONG   R9;
    ULONGLONG   R10;
    ULONGLONG   R11;
    ULONGLONG   R12;
    ULONGLONG   R13;
    ULONGLONG   R14;
    ULONGLONG   R15;

    // 指令指针
    ULONGLONG   Rip;

    // 标志寄存器
    ULONG       EFlags;

    // 段寄存器
    USHORT      SegCs;
    USHORT      SegDs;
    USHORT      SegEs;
    USHORT      SegFs;
    USHORT      SegGs;
    USHORT      SegSs;
} DUMPER_THREAD_CONTEXT, *PDUMPER_THREAD_CONTEXT;

// ============================================================================
// 辅助宏
// ============================================================================

// 获取数据缓冲区指针
#define DUMPER_GET_DATA_BUFFER(pHeader) \
    ((PUCHAR)(pHeader) + sizeof(DUMPER_SHARED_HEADER))

#pragma warning(pop)

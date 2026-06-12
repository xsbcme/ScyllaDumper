#pragma once

//
// DumperClient.h - 用户态驱动通信客户端
//
// 封装与 KernelDumper 驱动的共享内存通信，
// 提供与原 ProcessAccessHelp 兼容的接口。
// KDMapper 兼容: 不依赖 IOCTL，直接通过命名对象通信。
//

#include <Windows.h>
#include <string>
#include <vector>
#include "../Common/DumperProtocol.h"

enum class DumperBackendType
{
    Driver,
    UserMode
};

// ============================================================================
// 模块信息 (用户态表示)
// ============================================================================

struct DumperModuleInfo
{
    DWORD_PTR   BaseAddress;
    DWORD       Size;
    std::wstring FullPath;
};

// ============================================================================
// 内存区域信息
// ============================================================================

struct DumperMemoryInfo
{
    DWORD_PTR   BaseAddress;
    DWORD_PTR   AllocationBase;
    SIZE_T      RegionSize;
    DWORD       State;      // MEM_COMMIT, MEM_FREE, MEM_RESERVE
    DWORD       Protect;    // PAGE_XXX
    DWORD       Type;       // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
};

// ============================================================================
// 线程信息 (枚举结果)
// ============================================================================

struct DumperThreadInfo
{
    DWORD       ThreadId;
    DWORD_PTR   StartAddress;
    DWORD       State;
    DWORD       WaitReason;
    LONG        Priority;
    LONG        BasePriority;
};

// ============================================================================
// 线程上下文 (寄存器)
// ============================================================================

struct DumperThreadContext
{
    DWORD_PTR   Rax, Rbx, Rcx, Rdx;
    DWORD_PTR   Rsi, Rdi, Rbp, Rsp;
    DWORD_PTR   R8, R9, R10, R11, R12, R13, R14, R15;
    DWORD_PTR   Rip;
    DWORD       EFlags;
    WORD        SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
};

// ============================================================================
// 进程信息
// ============================================================================

struct DumperProcessInfo
{
    DWORD_PTR   PebAddress;
    DWORD_PTR   ImageBase;
    DWORD_PTR   EntryPoint;     // VA (ImageBase + AddressOfEntryPoint)
    bool        IsWow64;
    DWORD       ParentProcessId;
};

// ============================================================================
// 进程枚举条目
// ============================================================================

struct DumperProcessEntry
{
    DWORD       ProcessId;
    DWORD       ParentProcessId;
    DWORD       ThreadCount;
    ULONGLONG   WorkingSetSize;
    std::wstring ImageName;
};

namespace DumperClientDriver { struct Ops; }
namespace DumperClientUser { struct Ops; }

// ============================================================================
// DumperClient 类
// ============================================================================

class DumperClient
{
public:
    DumperClient();
    ~DumperClient();

    // 禁止拷贝
    DumperClient(const DumperClient&) = delete;
    DumperClient& operator=(const DumperClient&) = delete;

    // ---- 连接管理 ----

    // 连接驱动并初始化共享内存
    bool Connect();

    // 断开连接，释放资源
    void Disconnect();

    // 通知驱动关闭工作线程并释放资源
    void Shutdown();

    // 是否已连接
    bool IsConnected() const { return m_Connected; }
    bool IsDriverBackend() const { return m_Connected; }
    bool IsUserBackend() const { return !m_Connected; }
    DumperBackendType GetBackendType() const
    {
        return m_Connected ? DumperBackendType::Driver : DumperBackendType::UserMode;
    }

    // ---- 进程操作 ----

    // 打开目标进程
    bool OpenProcess(DWORD processId);

    // 关闭目标进程
    bool CloseProcess();

    // ---- 内存读写 (核心转存功能) ----

    // 读取进程内存
    bool ReadMemory(DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead = nullptr);

    // 部分读取进程内存 (跳过未提交页面，用于转存)
    bool ReadMemoryPartial(DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead = nullptr);

    // 写入进程内存
    bool WriteMemory(DWORD_PTR address, SIZE_T size, LPCVOID buffer, SIZE_T* bytesWritten = nullptr);

    // ---- 内存查询 ----

    // 查询内存区域信息
    bool QueryMemory(DWORD_PTR address, DumperMemoryInfo& info);

    // ---- 内存保护 ----

    // 修改内存保护属性
    bool ProtectMemory(DWORD_PTR address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);

    // ---- 进程控制 ----

    bool SuspendProcess();
    bool ResumeProcess();

    // ---- 模块枚举 ----

    // 枚举进程加载的模块
    bool EnumModules(std::vector<DumperModuleInfo>& modules);

    // ---- 线程枚举 (驱动层, 绕过保护) ----

    // 枚举进程线程
    bool EnumThreads(std::vector<DumperThreadInfo>& threads);

    // ---- 线程上下文 (驱动层, 绕过保护) ----

    // 获取线程寄存器状态
    bool GetThreadContext(DWORD threadId, DumperThreadContext& ctx);

    // ---- 进程信息 (驱动层, 绕过保护) ----

    // 获取进程基本信息 (PEB, ImageBase, EntryPoint, WoW64)
    bool GetProcessInfo(DumperProcessInfo& info);

    // ---- 进程枚举 (无需先 OpenProcess) ----

    // 枚举系统所有进程
    bool EnumProcesses(std::vector<DumperProcessEntry>& processes);

    // ---- 状态查询 ----

    // 获取最后的 NTSTATUS
    NTSTATUS GetLastNtStatus() const { return m_LastNtStatus; }

    friend struct DumperClientDriver::Ops;
    friend struct DumperClientUser::Ops;

private:
    // 发送命令并等待响应
    bool SendCommand(DUMPER_COMMAND_TYPE cmd, DWORD timeoutMs = 10000);

    // 获取共享头部指针
    PDUMPER_SHARED_HEADER GetHeader() const
    {
        return reinterpret_cast<PDUMPER_SHARED_HEADER>(m_SharedMemory);
    }

    // 获取数据缓冲区指针
    PUCHAR GetDataBuffer() const
    {
        return reinterpret_cast<PUCHAR>(m_SharedMemory) + sizeof(DUMPER_SHARED_HEADER);
    }

    // 数据缓冲区可用大小
    ULONG GetDataBufferSize() const
    {
        return DUMPER_DATA_BUFFER_SIZE;
    }

private:
    // 用户层进程句柄 (驱动不可用时回退路径使用)
    HANDLE      m_UserProcessHandle;
    DWORD       m_UserProcessId;

    bool        m_Connected;

    // 共享内存 (通过命名 Section 映射)
    PVOID       m_SharedMemory;
    ULONG       m_SharedMemorySize;

    // 同步事件
    HANDLE      m_RequestEvent;     // 通知驱动有新命令
    HANDLE      m_ResponseEvent;    // 等待驱动完成

    // 状态
    NTSTATUS    m_LastNtStatus;
};

// ============================================================================
// 后端实现 (定义见 DumperClientDriver.cpp / DumperClientUser.cpp)
// ============================================================================

namespace DumperClientDriver
{
struct Ops
{
    static bool OpenProcess(DumperClient& c, DWORD processId);
    static bool CloseProcess(DumperClient& c);
    static bool ReadMemory(DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead);
    static bool ReadMemoryPartial(DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead);
    static bool WriteMemory(DumperClient& c, DWORD_PTR address, SIZE_T size, LPCVOID buffer, SIZE_T* bytesWritten);
    static bool QueryMemory(DumperClient& c, DWORD_PTR address, DumperMemoryInfo& info);
    static bool ProtectMemory(DumperClient& c, DWORD_PTR address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
    static bool SuspendProcess(DumperClient& c);
    static bool ResumeProcess(DumperClient& c);
    static bool EnumModules(DumperClient& c, std::vector<DumperModuleInfo>& modules);
    static bool EnumThreads(DumperClient& c, std::vector<DumperThreadInfo>& threads);
    static bool GetThreadContext(DumperClient& c, DWORD threadId, DumperThreadContext& ctx);
    static bool GetProcessInfo(DumperClient& c, DumperProcessInfo& info);
    static bool EnumProcesses(DumperClient& c, std::vector<DumperProcessEntry>& processes);
};
}

namespace DumperClientUser
{
struct Ops
{
    static bool OpenProcess(DumperClient& c, DWORD processId);
    static bool CloseProcess(DumperClient& c);
    static bool ReadMemory(DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead);
    static bool ReadMemoryPartial(DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead);
    static bool WriteMemory(DumperClient& c, DWORD_PTR address, SIZE_T size, LPCVOID buffer, SIZE_T* bytesWritten);
    static bool QueryMemory(DumperClient& c, DWORD_PTR address, DumperMemoryInfo& info);
    static bool ProtectMemory(DumperClient& c, DWORD_PTR address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
    static bool SuspendProcess(DumperClient& c);
    static bool ResumeProcess(DumperClient& c);
    static bool EnumModules(DumperClient& c, std::vector<DumperModuleInfo>& modules);
    static bool EnumThreads(DumperClient& c, std::vector<DumperThreadInfo>& threads);
    static bool GetThreadContext(DumperClient& c, DWORD threadId, DumperThreadContext& ctx);
    static bool GetProcessInfo(DumperClient& c, DumperProcessInfo& info);
    static bool EnumProcesses(DumperClient& c, std::vector<DumperProcessEntry>& processes);
};
}

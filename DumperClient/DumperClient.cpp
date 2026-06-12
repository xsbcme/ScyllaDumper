//
// DumperClient.cpp - 连接管理与 API 分发 (驱动 / 用户层后端见独立 .cpp)
//
// KDMapper 兼容: 不依赖 IOCTL/设备句柄，直接通过命名 Section + Event 通信。
//

#include "DumperClient.h"
#include "DebugLog.h"
#include "VirtualizerSDKMacros.h"
#include <cstdio>
#include <cstring>

namespace {

const wchar_t* DumperCommandNameW(DUMPER_COMMAND_TYPE cmd)
{
    switch (cmd)
    {
    case DumperCmdNone: return L"None";
    case DumperCmdOpenProcess: return L"OpenProcess";
    case DumperCmdCloseProcess: return L"CloseProcess";
    case DumperCmdReadMemory: return L"ReadMemory";
    case DumperCmdWriteMemory: return L"WriteMemory";
    case DumperCmdQueryMemory: return L"QueryMemory";
    case DumperCmdReadMemoryPartial: return L"ReadMemoryPartial";
    case DumperCmdProtectMemory: return L"ProtectMemory";
    case DumperCmdSuspendProcess: return L"SuspendProcess";
    case DumperCmdResumeProcess: return L"ResumeProcess";
    case DumperCmdEnumModules: return L"EnumModules";
    case DumperCmdEnumThreads: return L"EnumThreads";
    case DumperCmdGetThreadContext: return L"GetThreadContext";
    case DumperCmdGetProcessInfo: return L"GetProcessInfo";
    case DumperCmdEnumProcesses: return L"EnumProcesses";
    case DumperCmdShutdown: return L"Shutdown";
    default: return L"Unknown";
    }
}

} // namespace

// ============================================================================
// 构造 / 析构
// ============================================================================

DumperClient::DumperClient()
    : m_UserProcessHandle(NULL)
    , m_UserProcessId(0)
    , m_Connected(false)
    , m_SharedMemory(nullptr)
    , m_SharedMemorySize(0)
    , m_RequestEvent(NULL)
    , m_ResponseEvent(NULL)
    , m_LastNtStatus(0)
{
}

DumperClient::~DumperClient()
{
    Disconnect();
}

// ============================================================================
// Connect - 打开驱动创建的命名 Section + Event
// ============================================================================

bool DumperClient::Connect()
{
    if (m_Connected)
    {
        return true;
    }

    HANDLE sectionHandle = OpenFileMappingW(
        FILE_MAP_ALL_ACCESS,
        FALSE,
        DUMPER_SECTION_NAME_USER);

    if (sectionHandle == NULL)
    {
        DWORD err1 = GetLastError();
        DBG_LOG(L"[DBG] OpenFileMappingW('%s') failed, error=%lu\n", DUMPER_SECTION_NAME_USER, err1);
        sectionHandle = OpenFileMappingW(
            FILE_MAP_ALL_ACCESS,
            FALSE,
            DUMPER_SECTION_NAME_USER_SESSION);
        if (sectionHandle == NULL)
        {
            DWORD err2 = GetLastError();
            DBG_LOG(L"[DBG] OpenFileMappingW('%s') also failed, error=%lu\n",
                    DUMPER_SECTION_NAME_USER_SESSION, err2);
        }
    }

    if (sectionHandle == NULL)
    {
        DBG_LOG(L"[DBG] 无法打开 Section，连接失败\n");
        return false;
    }
    DBG_LOG(L"[DBG] Section opened OK\n");

    m_SharedMemorySize = DUMPER_SHARED_MEMORY_SIZE;
    m_SharedMemory = MapViewOfFile(
        sectionHandle,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        m_SharedMemorySize);
    CloseHandle(sectionHandle);

    if (m_SharedMemory == NULL)
    {
        DBG_LOG(L"[DBG] MapViewOfFile failed, error=%lu\n", GetLastError());
        return false;
    }
    DBG_LOG(L"[DBG] MapViewOfFile OK, addr=%p\n", m_SharedMemory);

    m_RequestEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, DUMPER_REQUEST_EVENT_USER);
    if (m_RequestEvent == NULL)
    {
        DWORD err = GetLastError();
        DBG_LOG(L"[DBG] OpenEventW('%s') failed, error=%lu\n", DUMPER_REQUEST_EVENT_USER, err);
        m_RequestEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, DUMPER_REQUEST_EVENT_USER_SESSION);
    }

    m_ResponseEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, DUMPER_RESPONSE_EVENT_USER);
    if (m_ResponseEvent == NULL)
    {
        DWORD err = GetLastError();
        DBG_LOG(L"[DBG] OpenEventW('%s') failed, error=%lu\n", DUMPER_RESPONSE_EVENT_USER, err);
        m_ResponseEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, DUMPER_RESPONSE_EVENT_USER_SESSION);
    }

    if (m_RequestEvent == NULL || m_ResponseEvent == NULL)
    {
        DBG_LOG(L"[DBG] Event 打开失败 (req=%p, resp=%p)\n", m_RequestEvent, m_ResponseEvent);
        Disconnect();
        return false;
    }
    DBG_LOG(L"[DBG] Events opened OK\n");

    PDUMPER_SHARED_HEADER header = GetHeader();
    DBG_LOG(L"[DBG] Protocol version in shared memory: %u (expected %u)\n",
            header->ProtocolVersion, DUMPER_PROTOCOL_VERSION);
    if (header->ProtocolVersion != DUMPER_PROTOCOL_VERSION)
    {
        DBG_LOG(L"[DBG] Protocol version mismatch!\n");
        Disconnect();
        return false;
    }

    m_Connected = true;
    return true;
}

// ============================================================================
// Disconnect - 断开连接，释放本地资源
// ============================================================================

void DumperClient::Disconnect()
{
    if (m_UserProcessHandle != NULL)
    {
        CloseHandle(m_UserProcessHandle);
        m_UserProcessHandle = NULL;
        m_UserProcessId = 0;
    }

    if (m_SharedMemory != NULL)
    {
        UnmapViewOfFile(m_SharedMemory);
        m_SharedMemory = nullptr;
    }

    if (m_RequestEvent != NULL)
    {
        CloseHandle(m_RequestEvent);
        m_RequestEvent = NULL;
    }

    if (m_ResponseEvent != NULL)
    {
        CloseHandle(m_ResponseEvent);
        m_ResponseEvent = NULL;
    }

    m_Connected = false;
    m_SharedMemorySize = 0;
}

// ============================================================================
// Shutdown - 通知驱动关闭工作线程并释放内核资源
// ============================================================================

void DumperClient::Shutdown()
{
    if (!m_Connected)
    {
        return;
    }

    SendCommand(DumperCmdShutdown, 5000);
}

// ============================================================================
// SendCommand - 发送命令到驱动并等待响应
// ============================================================================

bool DumperClient::SendCommand(DUMPER_COMMAND_TYPE cmd, DWORD timeoutMs)
{
    if (!m_Connected)
    {
        return false;
    }
    VIRTUALIZER_START
    PDUMPER_SHARED_HEADER header = GetHeader();

    bool       success = false;
    DWORD      waitResult = 0;
    NTSTATUS   ntStatusSnapshot = 0;
    DUMPER_STATUS statusSnapshot = DumperStatusIdle;

    header->Command = cmd;
    MemoryBarrier();
    header->Status = DumperStatusPending;
    MemoryBarrier();
    SetEvent(m_RequestEvent);
    VIRTUALIZER_END

    waitResult = WaitForSingleObject(m_ResponseEvent, timeoutMs);
    if (waitResult != WAIT_OBJECT_0)
    {
        header->Status = DumperStatusIdle;
    }
    else
    {
        ntStatusSnapshot = header->NtStatus;
        statusSnapshot = header->Status;
        success = (header->Status == DumperStatusCompleted);
        header->Status = DumperStatusIdle;
    }

    if (waitResult != WAIT_OBJECT_0)
    {
        DBG_LOG(L"[DBG] SendCommand timeout/fail: %s id=%u wait=0x%08X timeoutMs=%lu\n",
                DumperCommandNameW(cmd),
                static_cast<unsigned>(cmd),
                waitResult,
                timeoutMs);
    }
    else
    {
        m_LastNtStatus = ntStatusSnapshot;
        DBG_LOG(L"[DBG] SendCommand done: %s id=%u status=%u nt=0x%08X\n",
                DumperCommandNameW(cmd),
                static_cast<unsigned>(cmd),
                static_cast<unsigned>(statusSnapshot),
                static_cast<unsigned>(m_LastNtStatus));
    }
    return success;
}

// ============================================================================
// 公开 API：按后端分发
// ============================================================================

bool DumperClient::OpenProcess(DWORD processId)
{
    if (!m_Connected)
    {
        DBG_LOG(L"[DBG] OpenProcess routed to User backend, pid=%u\n", processId);
        return DumperClientUser::Ops::OpenProcess(*this, processId);
    }
    DBG_LOG(L"[DBG] OpenProcess routed to Driver backend, pid=%u\n", processId);
    return DumperClientDriver::Ops::OpenProcess(*this, processId);
}

bool DumperClient::CloseProcess()
{
    if (!m_Connected)
    {
        DBG_LOG(L"[DBG] CloseProcess routed to User backend\n");
        return DumperClientUser::Ops::CloseProcess(*this);
    }
    DBG_LOG(L"[DBG] CloseProcess routed to Driver backend\n");
    return DumperClientDriver::Ops::CloseProcess(*this);
}

bool DumperClient::ReadMemory(DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead)
{
    if (buffer == nullptr || size == 0)
    {
        return false;
    }

    if (!m_Connected)
    {
        return DumperClientUser::Ops::ReadMemory(*this, address, size, buffer, bytesRead);
    }
    return DumperClientDriver::Ops::ReadMemory(*this, address, size, buffer, bytesRead);
}

bool DumperClient::ReadMemoryPartial(DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead)
{
    if (buffer == nullptr || size == 0)
    {
        return false;
    }

    if (!m_Connected)
    {
        return DumperClientUser::Ops::ReadMemoryPartial(*this, address, size, buffer, bytesRead);
    }
    return DumperClientDriver::Ops::ReadMemoryPartial(*this, address, size, buffer, bytesRead);
}

bool DumperClient::WriteMemory(DWORD_PTR address, SIZE_T size, LPCVOID buffer, SIZE_T* bytesWritten)
{
    if (buffer == nullptr || size == 0)
    {
        return false;
    }

    if (!m_Connected)
    {
        return DumperClientUser::Ops::WriteMemory(*this, address, size, buffer, bytesWritten);
    }
    return DumperClientDriver::Ops::WriteMemory(*this, address, size, buffer, bytesWritten);
}

bool DumperClient::QueryMemory(DWORD_PTR address, DumperMemoryInfo& info)
{
    if (!m_Connected)
    {
        return DumperClientUser::Ops::QueryMemory(*this, address, info);
    }
    return DumperClientDriver::Ops::QueryMemory(*this, address, info);
}

bool DumperClient::ProtectMemory(DWORD_PTR address, SIZE_T size, DWORD newProtect, DWORD* oldProtect)
{
    if (!m_Connected)
    {
        return DumperClientUser::Ops::ProtectMemory(*this, address, size, newProtect, oldProtect);
    }
    return DumperClientDriver::Ops::ProtectMemory(*this, address, size, newProtect, oldProtect);
}

bool DumperClient::SuspendProcess()
{
    if (!m_Connected)
    {
        return DumperClientUser::Ops::SuspendProcess(*this);
    }
    return DumperClientDriver::Ops::SuspendProcess(*this);
}

bool DumperClient::ResumeProcess()
{
    if (!m_Connected)
    {
        return DumperClientUser::Ops::ResumeProcess(*this);
    }
    return DumperClientDriver::Ops::ResumeProcess(*this);
}

bool DumperClient::EnumModules(std::vector<DumperModuleInfo>& modules)
{
    modules.clear();

    if (!m_Connected)
    {
        return DumperClientUser::Ops::EnumModules(*this, modules);
    }
    return DumperClientDriver::Ops::EnumModules(*this, modules);
}

bool DumperClient::EnumThreads(std::vector<DumperThreadInfo>& threads)
{
    threads.clear();

    if (!m_Connected)
    {
        return DumperClientUser::Ops::EnumThreads(*this, threads);
    }
    return DumperClientDriver::Ops::EnumThreads(*this, threads);
}

bool DumperClient::GetThreadContext(DWORD threadId, DumperThreadContext& ctx)
{
    memset(&ctx, 0, sizeof(ctx));

    if (!m_Connected)
    {
        return DumperClientUser::Ops::GetThreadContext(*this, threadId, ctx);
    }
    return DumperClientDriver::Ops::GetThreadContext(*this, threadId, ctx);
}

bool DumperClient::GetProcessInfo(DumperProcessInfo& info)
{
    memset(&info, 0, sizeof(info));

    if (!m_Connected)
    {
        return DumperClientUser::Ops::GetProcessInfo(*this, info);
    }
    return DumperClientDriver::Ops::GetProcessInfo(*this, info);
}

bool DumperClient::EnumProcesses(std::vector<DumperProcessEntry>& processes)
{
    processes.clear();

    if (!m_Connected)
    {
        return DumperClientUser::Ops::EnumProcesses(*this, processes);
    }
    return DumperClientDriver::Ops::EnumProcesses(*this, processes);
}

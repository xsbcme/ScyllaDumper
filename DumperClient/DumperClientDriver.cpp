//
// DumperClientDriver.cpp - 驱动层后端 (共享内存命令)
//

#include "DumperClient.h"
#include "DumperClientDetail.h"
#include "DebugLog.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

bool DumperClientDriver::Ops::OpenProcess(DumperClient& c, DWORD processId)
{
    PDUMPER_SHARED_HEADER header = c.GetHeader();
    header->Params.OpenProcess.ProcessId = processId;
    bool ok = c.SendCommand(DumperCmdOpenProcess);
    DBG_LOG(L"[DBG] Driver.OpenProcess pid=%u -> %s nt=0x%08X\n",
            processId, ok ? L"ok" : L"fail", static_cast<unsigned>(c.m_LastNtStatus));
    return ok;
}

bool DumperClientDriver::Ops::CloseProcess(DumperClient& c)
{
    return c.SendCommand(DumperCmdCloseProcess);
}

bool DumperClientDriver::Ops::ReadMemory(
    DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead)
{
    if (bytesRead)
    {
        *bytesRead = 0;
    }

    SIZE_T totalRead = 0;
    SIZE_T remaining = size;
    DWORD_PTR currentAddr = address;
    PUCHAR destBuffer = static_cast<PUCHAR>(buffer);
    ULONG chunkSize = c.GetDataBufferSize();

    while (remaining > 0)
    {
        ULONG toRead = static_cast<ULONG>((std::min)(remaining, static_cast<SIZE_T>(chunkSize)));

        PDUMPER_SHARED_HEADER header = c.GetHeader();
        header->Params.ReadMemory.BaseAddress = static_cast<ULONGLONG>(currentAddr);
        header->Params.ReadMemory.Size = toRead;

        if (!c.SendCommand(DumperCmdReadMemory))
        {
            DBG_LOG(L"[DBG] Driver.ReadMemory chunk fail addr=0x%llX req=0x%X nt=0x%08X\n",
                    static_cast<unsigned long long>(currentAddr), toRead,
                    static_cast<unsigned>(c.m_LastNtStatus));
            if (totalRead > 0)
            {
                break;
            }
            return false;
        }

        ULONG actualRead = header->Params.ReadMemory.BytesRead;
        if (actualRead > 0)
        {
            memcpy(destBuffer, c.GetDataBuffer(), actualRead);
        }

        totalRead += actualRead;
        destBuffer += actualRead;
        currentAddr += actualRead;
        remaining -= actualRead;

        if (actualRead < toRead)
        {
            break;
        }
    }

    if (bytesRead)
    {
        *bytesRead = totalRead;
    }
    DBG_LOG(L"[DBG] Driver.ReadMemory done addr=0x%llX size=0x%llX read=0x%llX\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(totalRead));
    return totalRead > 0;
}

bool DumperClientDriver::Ops::ReadMemoryPartial(
    DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead)
{
    if (bytesRead)
    {
        *bytesRead = 0;
    }

    SIZE_T totalRead = 0;
    SIZE_T remaining = size;
    DWORD_PTR currentAddr = address;
    PUCHAR destBuffer = static_cast<PUCHAR>(buffer);
    ULONG chunkSize = c.GetDataBufferSize();

    while (remaining > 0)
    {
        ULONG toRead = static_cast<ULONG>((std::min)(remaining, static_cast<SIZE_T>(chunkSize)));

        PDUMPER_SHARED_HEADER header = c.GetHeader();
        header->Params.ReadMemory.BaseAddress = static_cast<ULONGLONG>(currentAddr);
        header->Params.ReadMemory.Size = toRead;

        if (!c.SendCommand(DumperCmdReadMemoryPartial))
        {
            DBG_LOG(L"[DBG] Driver.ReadMemoryPartial chunk fail addr=0x%llX req=0x%X nt=0x%08X\n",
                    static_cast<unsigned long long>(currentAddr), toRead,
                    static_cast<unsigned>(c.m_LastNtStatus));
            if (totalRead > 0)
            {
                break;
            }
            return false;
        }

        ULONG actualRead = header->Params.ReadMemory.BytesRead;
        if (actualRead > 0)
        {
            memcpy(destBuffer, c.GetDataBuffer(), actualRead);
        }

        totalRead += actualRead;
        destBuffer += actualRead;
        currentAddr += actualRead;
        remaining -= actualRead;

        if (actualRead < toRead)
        {
            break;
        }
    }

    if (bytesRead)
    {
        *bytesRead = totalRead;
    }
    DBG_LOG(L"[DBG] Driver.ReadMemoryPartial done addr=0x%llX size=0x%llX read=0x%llX\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(totalRead));
    return totalRead > 0;
}

bool DumperClientDriver::Ops::WriteMemory(
    DumperClient& c, DWORD_PTR address, SIZE_T size, LPCVOID buffer, SIZE_T* bytesWritten)
{
    if (bytesWritten)
    {
        *bytesWritten = 0;
    }

    SIZE_T totalWritten = 0;
    SIZE_T remaining = size;
    DWORD_PTR currentAddr = address;
    const PUCHAR srcBuffer = const_cast<PUCHAR>(static_cast<const UCHAR*>(buffer));
    ULONG chunkSize = c.GetDataBufferSize();

    while (remaining > 0)
    {
        ULONG toWrite = static_cast<ULONG>((std::min)(remaining, static_cast<SIZE_T>(chunkSize)));

        memcpy(c.GetDataBuffer(), srcBuffer + totalWritten, toWrite);

        PDUMPER_SHARED_HEADER header = c.GetHeader();
        header->Params.WriteMemory.BaseAddress = static_cast<ULONGLONG>(currentAddr);
        header->Params.WriteMemory.Size = toWrite;

        if (!c.SendCommand(DumperCmdWriteMemory))
        {
            DBG_LOG(L"[DBG] Driver.WriteMemory chunk fail addr=0x%llX req=0x%X nt=0x%08X\n",
                    static_cast<unsigned long long>(currentAddr), toWrite,
                    static_cast<unsigned>(c.m_LastNtStatus));
            if (totalWritten > 0)
            {
                break;
            }
            return false;
        }

        ULONG actualWritten = header->Params.WriteMemory.BytesWritten;
        totalWritten += actualWritten;
        currentAddr += actualWritten;
        remaining -= actualWritten;

        if (actualWritten < toWrite)
        {
            break;
        }
    }

    if (bytesWritten)
    {
        *bytesWritten = totalWritten;
    }
    DBG_LOG(L"[DBG] Driver.WriteMemory done addr=0x%llX size=0x%llX written=0x%llX\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(totalWritten));
    return totalWritten > 0;
}

bool DumperClientDriver::Ops::QueryMemory(DumperClient& c, DWORD_PTR address, DumperMemoryInfo& info)
{
    PDUMPER_SHARED_HEADER header = c.GetHeader();
    header->Params.QueryMemory.BaseAddress = static_cast<ULONGLONG>(address);

    if (!c.SendCommand(DumperCmdQueryMemory))
    {
        return false;
    }

    info.BaseAddress = address;
    info.AllocationBase = static_cast<DWORD_PTR>(header->Params.QueryMemory.AllocationBase);
    info.RegionSize = static_cast<SIZE_T>(header->Params.QueryMemory.RegionSize);
    info.State = header->Params.QueryMemory.State;
    info.Protect = header->Params.QueryMemory.Protect;
    info.Type = header->Params.QueryMemory.Type;

    return true;
}

bool DumperClientDriver::Ops::ProtectMemory(
    DumperClient& c, DWORD_PTR address, SIZE_T size, DWORD newProtect, DWORD* oldProtect)
{
    PDUMPER_SHARED_HEADER header = c.GetHeader();
    header->Params.ProtectMemory.BaseAddress = static_cast<ULONGLONG>(address);
    header->Params.ProtectMemory.Size = static_cast<ULONG>(size);
    header->Params.ProtectMemory.NewProtect = newProtect;

    if (!c.SendCommand(DumperCmdProtectMemory))
    {
        return false;
    }

    if (oldProtect)
    {
        *oldProtect = header->Params.ProtectMemory.OldProtect;
    }

    return true;
}

bool DumperClientDriver::Ops::SuspendProcess(DumperClient& c)
{
    return c.SendCommand(DumperCmdSuspendProcess);
}

bool DumperClientDriver::Ops::ResumeProcess(DumperClient& c)
{
    return c.SendCommand(DumperCmdResumeProcess);
}

bool DumperClientDriver::Ops::EnumModules(DumperClient& c, std::vector<DumperModuleInfo>& modules)
{
    if (!c.SendCommand(DumperCmdEnumModules))
    {
        return false;
    }

    PDUMPER_SHARED_HEADER header = c.GetHeader();
    ULONG moduleCount = header->Params.EnumModules.ModuleCount;

    if (moduleCount == 0)
    {
        return true;
    }

    PDUMPER_MODULE_ENTRY entries = reinterpret_cast<PDUMPER_MODULE_ENTRY>(c.GetDataBuffer());

    modules.reserve(moduleCount);
    for (ULONG i = 0; i < moduleCount; i++)
    {
        DumperModuleInfo info;
        info.BaseAddress = static_cast<DWORD_PTR>(entries[i].BaseAddress);
        info.Size = entries[i].Size;
        info.FullPath = entries[i].FullPath;
        modules.push_back(std::move(info));
    }

    DBG_LOG(L"[DBG] Driver.EnumModules count=%u\n", static_cast<unsigned>(modules.size()));
    return true;
}

bool DumperClientDriver::Ops::EnumThreads(DumperClient& c, std::vector<DumperThreadInfo>& threads)
{
    if (!c.SendCommand(DumperCmdEnumThreads))
    {
        return false;
    }

    PDUMPER_SHARED_HEADER header = c.GetHeader();
    ULONG threadCount = header->Params.EnumThreads.ThreadCount;

    if (threadCount == 0)
    {
        return true;
    }

    PDUMPER_THREAD_ENTRY entries = reinterpret_cast<PDUMPER_THREAD_ENTRY>(c.GetDataBuffer());

    threads.reserve(threadCount);
    for (ULONG i = 0; i < threadCount; i++)
    {
        DumperThreadInfo info;
        info.ThreadId = entries[i].ThreadId;
        info.StartAddress = static_cast<DWORD_PTR>(entries[i].StartAddress);
        info.State = entries[i].State;
        info.WaitReason = entries[i].WaitReason;
        info.Priority = entries[i].Priority;
        info.BasePriority = entries[i].BasePriority;
        threads.push_back(info);
    }

    DBG_LOG(L"[DBG] Driver.EnumThreads count=%u\n", static_cast<unsigned>(threads.size()));
    return true;
}

bool DumperClientDriver::Ops::GetThreadContext(DumperClient& c, DWORD threadId, DumperThreadContext& ctx)
{
    PDUMPER_SHARED_HEADER header = c.GetHeader();
    header->Params.GetThreadContext.ThreadId = threadId;
    header->Params.GetThreadContext.ContextFlags = 0x10001F;

    if (!c.SendCommand(DumperCmdGetThreadContext))
    {
        return false;
    }

    PDUMPER_THREAD_CONTEXT driverCtx =
        reinterpret_cast<PDUMPER_THREAD_CONTEXT>(c.GetDataBuffer());

    ctx.Rax = static_cast<DWORD_PTR>(driverCtx->Rax);
    ctx.Rbx = static_cast<DWORD_PTR>(driverCtx->Rbx);
    ctx.Rcx = static_cast<DWORD_PTR>(driverCtx->Rcx);
    ctx.Rdx = static_cast<DWORD_PTR>(driverCtx->Rdx);
    ctx.Rsi = static_cast<DWORD_PTR>(driverCtx->Rsi);
    ctx.Rdi = static_cast<DWORD_PTR>(driverCtx->Rdi);
    ctx.Rbp = static_cast<DWORD_PTR>(driverCtx->Rbp);
    ctx.Rsp = static_cast<DWORD_PTR>(driverCtx->Rsp);
    ctx.R8 = static_cast<DWORD_PTR>(driverCtx->R8);
    ctx.R9 = static_cast<DWORD_PTR>(driverCtx->R9);
    ctx.R10 = static_cast<DWORD_PTR>(driverCtx->R10);
    ctx.R11 = static_cast<DWORD_PTR>(driverCtx->R11);
    ctx.R12 = static_cast<DWORD_PTR>(driverCtx->R12);
    ctx.R13 = static_cast<DWORD_PTR>(driverCtx->R13);
    ctx.R14 = static_cast<DWORD_PTR>(driverCtx->R14);
    ctx.R15 = static_cast<DWORD_PTR>(driverCtx->R15);
    ctx.Rip = static_cast<DWORD_PTR>(driverCtx->Rip);
    ctx.EFlags = driverCtx->EFlags;
    ctx.SegCs = driverCtx->SegCs;
    ctx.SegDs = driverCtx->SegDs;
    ctx.SegEs = driverCtx->SegEs;
    ctx.SegFs = driverCtx->SegFs;
    ctx.SegGs = driverCtx->SegGs;
    ctx.SegSs = driverCtx->SegSs;

    return true;
}

bool DumperClientDriver::Ops::GetProcessInfo(DumperClient& c, DumperProcessInfo& info)
{
    if (!c.SendCommand(DumperCmdGetProcessInfo))
    {
        return false;
    }

    PDUMPER_SHARED_HEADER header = c.GetHeader();
    info.PebAddress = static_cast<DWORD_PTR>(header->Params.ProcessInfo.PebAddress);
    info.ImageBase = static_cast<DWORD_PTR>(header->Params.ProcessInfo.ImageBase);
    info.EntryPoint = static_cast<DWORD_PTR>(header->Params.ProcessInfo.EntryPoint);
    info.IsWow64 = (header->Params.ProcessInfo.IsWow64 != 0);
    info.ParentProcessId = header->Params.ProcessInfo.ParentProcessId;
    DBG_LOG(L"[DBG] Driver.GetProcessInfo peb=0x%llX base=0x%llX ep=0x%llX wow64=%d ppid=%u\n",
            static_cast<unsigned long long>(info.PebAddress),
            static_cast<unsigned long long>(info.ImageBase),
            static_cast<unsigned long long>(info.EntryPoint),
            info.IsWow64 ? 1 : 0,
            info.ParentProcessId);
    return true;
}

bool DumperClientDriver::Ops::EnumProcesses(DumperClient& c, std::vector<DumperProcessEntry>& processes)
{
    if (!c.SendCommand(DumperCmdEnumProcesses))
    {
        return false;
    }

    PDUMPER_SHARED_HEADER header = c.GetHeader();
    ULONG processCount = header->Params.EnumProcesses.ProcessCount;

    if (processCount == 0)
    {
        return true;
    }

    PDUMPER_PROCESS_ENTRY entries = reinterpret_cast<PDUMPER_PROCESS_ENTRY>(c.GetDataBuffer());

    processes.reserve(processCount);
    for (ULONG i = 0; i < processCount; i++)
    {
        DumperProcessEntry entry;
        entry.ProcessId = entries[i].ProcessId;
        entry.ParentProcessId = entries[i].ParentProcessId;
        entry.ThreadCount = entries[i].ThreadCount;
        entry.WorkingSetSize = entries[i].WorkingSetSize;
        entry.ImageName = entries[i].ImageName;
        processes.push_back(std::move(entry));
    }

    DBG_LOG(L"[DBG] Driver.EnumProcesses count=%u\n", static_cast<unsigned>(processes.size()));
    return true;
}

//
// DumperClientUser.cpp - 用户层后端 (WinAPI / Toolhelp / Nt*)
//

#include "DumperClient.h"
#include "DumperClientDetail.h"
#include "DebugLog.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <TlHelp32.h>

bool DumperClientUser::Ops::OpenProcess(DumperClient& c, DWORD processId)
{
    if (c.m_UserProcessHandle != NULL)
    {
        CloseHandle(c.m_UserProcessHandle);
        c.m_UserProcessHandle = NULL;
        c.m_UserProcessId = 0;
    }

    HANDLE hProcess = ::OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_SUSPEND_RESUME,
        FALSE,
        processId);
    if (hProcess == NULL)
    {
        hProcess = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processId);
    }
    if (hProcess == NULL)
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        DBG_LOG(L"[DBG] User.OpenProcess pid=%u failed, gle=%lu nt=0x%08X\n",
                processId, GetLastError(), static_cast<unsigned>(c.m_LastNtStatus));
        return false;
    }

    c.m_UserProcessHandle = hProcess;
    c.m_UserProcessId = processId;
    c.m_LastNtStatus = 0;
    DBG_LOG(L"[DBG] User.OpenProcess pid=%u success, handle=%p\n", processId, hProcess);
    return true;
}

bool DumperClientUser::Ops::CloseProcess(DumperClient& c)
{
    if (c.m_UserProcessHandle != NULL)
    {
        CloseHandle(c.m_UserProcessHandle);
        c.m_UserProcessHandle = NULL;
        c.m_UserProcessId = 0;
    }
    return true;
}

bool DumperClientUser::Ops::ReadMemory(
    DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    if (bytesRead)
    {
        *bytesRead = 0;
    }

    SIZE_T localRead = 0;
    if (!ReadProcessMemory(c.m_UserProcessHandle,
                           reinterpret_cast<LPCVOID>(address),
                           buffer,
                           size,
                           &localRead))
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        DBG_LOG(L"[DBG] User.ReadMemory fail addr=0x%llX size=0x%llX gle=%lu nt=0x%08X\n",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                GetLastError(),
                static_cast<unsigned>(c.m_LastNtStatus));
        if (bytesRead)
        {
            *bytesRead = localRead;
        }
        return false;
    }

    if (bytesRead)
    {
        *bytesRead = localRead;
    }
    c.m_LastNtStatus = 0;
    DBG_LOG(L"[DBG] User.ReadMemory done addr=0x%llX size=0x%llX read=0x%llX\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(localRead));
    return localRead > 0;
}

bool DumperClientUser::Ops::ReadMemoryPartial(
    DumperClient& c, DWORD_PTR address, SIZE_T size, LPVOID buffer, SIZE_T* bytesRead)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    if (bytesRead)
    {
        *bytesRead = 0;
    }

    SIZE_T totalRead = 0;
    BYTE* out = static_cast<BYTE*>(buffer);
    DWORD_PTR cur = address;
    const DWORD_PTR end = address + size;

    while (cur < end)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(c.m_UserProcessHandle, reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0)
        {
            break;
        }

        DWORD_PTR regionBase = reinterpret_cast<DWORD_PTR>(mbi.BaseAddress);
        DWORD_PTR regionEnd = regionBase + mbi.RegionSize;
        DWORD_PTR readStart = (std::max)(cur, regionBase);
        DWORD_PTR readEnd = (std::min)(end, regionEnd);
        SIZE_T toRead = (readEnd > readStart) ? static_cast<SIZE_T>(readEnd - readStart) : 0;

        if (toRead > 0 &&
            mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0)
        {
            SIZE_T chunkRead = 0;
            ReadProcessMemory(c.m_UserProcessHandle,
                              reinterpret_cast<LPCVOID>(readStart),
                              out + (readStart - address),
                              toRead,
                              &chunkRead);
            totalRead += chunkRead;
        }

        if (regionEnd <= cur)
        {
            break;
        }
        cur = regionEnd;
    }

    if (bytesRead)
    {
        *bytesRead = totalRead;
    }
    c.m_LastNtStatus = (totalRead > 0) ? 0 : Win32ToPseudoNtStatus(GetLastError());
    DBG_LOG(L"[DBG] User.ReadMemoryPartial done addr=0x%llX size=0x%llX read=0x%llX nt=0x%08X\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(totalRead),
            static_cast<unsigned>(c.m_LastNtStatus));
    return totalRead > 0;
}

bool DumperClientUser::Ops::WriteMemory(
    DumperClient& c, DWORD_PTR address, SIZE_T size, LPCVOID buffer, SIZE_T* bytesWritten)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    if (bytesWritten)
    {
        *bytesWritten = 0;
    }

    SIZE_T localWritten = 0;
    if (!WriteProcessMemory(c.m_UserProcessHandle,
                            reinterpret_cast<LPVOID>(address),
                            buffer,
                            size,
                            &localWritten))
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        DBG_LOG(L"[DBG] User.WriteMemory fail addr=0x%llX size=0x%llX gle=%lu nt=0x%08X\n",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                GetLastError(),
                static_cast<unsigned>(c.m_LastNtStatus));
        if (bytesWritten)
        {
            *bytesWritten = localWritten;
        }
        return false;
    }

    if (bytesWritten)
    {
        *bytesWritten = localWritten;
    }
    c.m_LastNtStatus = 0;
    DBG_LOG(L"[DBG] User.WriteMemory done addr=0x%llX size=0x%llX written=0x%llX\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(localWritten));
    return localWritten > 0;
}

bool DumperClientUser::Ops::QueryMemory(DumperClient& c, DWORD_PTR address, DumperMemoryInfo& info)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(c.m_UserProcessHandle,
                       reinterpret_cast<LPCVOID>(address),
                       &mbi,
                       sizeof(mbi)) == 0)
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        DBG_LOG(L"[DBG] User.QueryMemory fail addr=0x%llX gle=%lu nt=0x%08X\n",
                static_cast<unsigned long long>(address),
                GetLastError(),
                static_cast<unsigned>(c.m_LastNtStatus));
        return false;
    }

    info.BaseAddress = reinterpret_cast<DWORD_PTR>(mbi.BaseAddress);
    info.AllocationBase = reinterpret_cast<DWORD_PTR>(mbi.AllocationBase);
    info.RegionSize = mbi.RegionSize;
    info.State = mbi.State;
    info.Protect = mbi.Protect;
    info.Type = mbi.Type;
    c.m_LastNtStatus = 0;
    DBG_LOG(L"[DBG] User.QueryMemory base=0x%llX alloc=0x%llX size=0x%llX state=0x%X protect=0x%X type=0x%X\n",
            static_cast<unsigned long long>(info.BaseAddress),
            static_cast<unsigned long long>(info.AllocationBase),
            static_cast<unsigned long long>(info.RegionSize),
            info.State, info.Protect, info.Type);
    return true;
}

bool DumperClientUser::Ops::ProtectMemory(
    DumperClient& c, DWORD_PTR address, SIZE_T size, DWORD newProtect, DWORD* oldProtect)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtectEx(c.m_UserProcessHandle,
                          reinterpret_cast<LPVOID>(address),
                          size,
                          newProtect,
                          &old))
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        DBG_LOG(L"[DBG] User.ProtectMemory fail addr=0x%llX size=0x%llX new=0x%X gle=%lu nt=0x%08X\n",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                newProtect,
                GetLastError(),
                static_cast<unsigned>(c.m_LastNtStatus));
        return false;
    }

    if (oldProtect)
    {
        *oldProtect = old;
    }
    c.m_LastNtStatus = 0;
    DBG_LOG(L"[DBG] User.ProtectMemory done addr=0x%llX size=0x%llX new=0x%X old=0x%X\n",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            newProtect,
            old);
    return true;
}

bool DumperClientUser::Ops::SuspendProcess(DumperClient& c)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
    {
        return false;
    }

    using PFN_NtSuspendProcess = NTSTATUS(NTAPI*)(HANDLE);
    auto fn = reinterpret_cast<PFN_NtSuspendProcess>(
        GetProcAddress(ntdll, "NtSuspendProcess"));
    if (fn == nullptr)
    {
        return false;
    }

    NTSTATUS st = fn(c.m_UserProcessHandle);
    c.m_LastNtStatus = st;
    DBG_LOG(L"[DBG] User.SuspendProcess nt=0x%08X\n", static_cast<unsigned>(st));
    return (st >= 0);
}

bool DumperClientUser::Ops::ResumeProcess(DumperClient& c)
{
    if (c.m_UserProcessHandle == NULL)
    {
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
    {
        return false;
    }

    using PFN_NtResumeProcess = NTSTATUS(NTAPI*)(HANDLE);
    auto fn = reinterpret_cast<PFN_NtResumeProcess>(
        GetProcAddress(ntdll, "NtResumeProcess"));
    if (fn == nullptr)
    {
        return false;
    }

    NTSTATUS st = fn(c.m_UserProcessHandle);
    c.m_LastNtStatus = st;
    DBG_LOG(L"[DBG] User.ResumeProcess nt=0x%08X\n", static_cast<unsigned>(st));
    return (st >= 0);
}

bool DumperClientUser::Ops::EnumModules(DumperClient& c, std::vector<DumperModuleInfo>& modules)
{
    if (c.m_UserProcessId == 0)
    {
        return false;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, c.m_UserProcessId);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me))
    {
        CloseHandle(snap);
        return false;
    }

    do
    {
        DumperModuleInfo info = {};
        info.BaseAddress = reinterpret_cast<DWORD_PTR>(me.modBaseAddr);
        info.Size = me.modBaseSize;
        info.FullPath = me.szExePath;
        modules.push_back(std::move(info));
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);

    std::sort(modules.begin(), modules.end(),
        [](const DumperModuleInfo& a, const DumperModuleInfo& b)
        {
            return a.BaseAddress < b.BaseAddress;
        });

    DBG_LOG(L"[DBG] User.EnumModules pid=%u count=%u\n",
            c.m_UserProcessId, static_cast<unsigned>(modules.size()));
    return true;
}

bool DumperClientUser::Ops::EnumThreads(DumperClient& c, std::vector<DumperThreadInfo>& threads)
{
    if (c.m_UserProcessId == 0)
    {
        return false;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (!Thread32First(snap, &te))
    {
        CloseHandle(snap);
        return false;
    }

    do
    {
        if (te.th32OwnerProcessID != c.m_UserProcessId)
        {
            continue;
        }

        DumperThreadInfo info = {};
        info.ThreadId = te.th32ThreadID;
        info.StartAddress = 0;
        info.State = 0;
        info.WaitReason = 0;
        info.Priority = THREAD_PRIORITY_NORMAL;
        info.BasePriority = te.tpBasePri;
        threads.push_back(std::move(info));
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    DBG_LOG(L"[DBG] User.EnumThreads pid=%u count=%u\n",
            c.m_UserProcessId, static_cast<unsigned>(threads.size()));
    return true;
}

bool DumperClientUser::Ops::GetThreadContext(DumperClient& c, DWORD threadId, DumperThreadContext& ctx)
{
    HANDLE hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        FALSE,
        threadId);
    if (hThread == NULL)
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        return false;
    }

    CONTEXT threadCtx = {};
    threadCtx.ContextFlags = CONTEXT_FULL;
    bool ok = false;
    DWORD suspendRet = SuspendThread(hThread);
    if (suspendRet != static_cast<DWORD>(-1))
    {
        if (::GetThreadContext(hThread, &threadCtx))
        {
            ok = true;
            ctx.Rax = static_cast<DWORD_PTR>(threadCtx.Rax);
            ctx.Rbx = static_cast<DWORD_PTR>(threadCtx.Rbx);
            ctx.Rcx = static_cast<DWORD_PTR>(threadCtx.Rcx);
            ctx.Rdx = static_cast<DWORD_PTR>(threadCtx.Rdx);
            ctx.Rsi = static_cast<DWORD_PTR>(threadCtx.Rsi);
            ctx.Rdi = static_cast<DWORD_PTR>(threadCtx.Rdi);
            ctx.Rbp = static_cast<DWORD_PTR>(threadCtx.Rbp);
            ctx.Rsp = static_cast<DWORD_PTR>(threadCtx.Rsp);
            ctx.R8 = static_cast<DWORD_PTR>(threadCtx.R8);
            ctx.R9 = static_cast<DWORD_PTR>(threadCtx.R9);
            ctx.R10 = static_cast<DWORD_PTR>(threadCtx.R10);
            ctx.R11 = static_cast<DWORD_PTR>(threadCtx.R11);
            ctx.R12 = static_cast<DWORD_PTR>(threadCtx.R12);
            ctx.R13 = static_cast<DWORD_PTR>(threadCtx.R13);
            ctx.R14 = static_cast<DWORD_PTR>(threadCtx.R14);
            ctx.R15 = static_cast<DWORD_PTR>(threadCtx.R15);
            ctx.Rip = static_cast<DWORD_PTR>(threadCtx.Rip);
            ctx.EFlags = threadCtx.EFlags;
            ctx.SegCs = threadCtx.SegCs;
            ctx.SegDs = threadCtx.SegDs;
            ctx.SegEs = threadCtx.SegEs;
            ctx.SegFs = threadCtx.SegFs;
            ctx.SegGs = threadCtx.SegGs;
            ctx.SegSs = threadCtx.SegSs;
        }
        ResumeThread(hThread);
    }

    if (!ok)
    {
        c.m_LastNtStatus = Win32ToPseudoNtStatus(GetLastError());
        DBG_LOG(L"[DBG] User.GetThreadContext tid=%u failed gle=%lu nt=0x%08X\n",
                threadId, GetLastError(), static_cast<unsigned>(c.m_LastNtStatus));
    }
    else
    {
        c.m_LastNtStatus = 0;
        DBG_LOG(L"[DBG] User.GetThreadContext tid=%u rip=0x%llX rsp=0x%llX\n",
                threadId,
                static_cast<unsigned long long>(ctx.Rip),
                static_cast<unsigned long long>(ctx.Rsp));
    }

    CloseHandle(hThread);
    return ok;
}

bool DumperClientUser::Ops::GetProcessInfo(DumperClient& c, DumperProcessInfo& info)
{
    memset(&info, 0, sizeof(info));

    if (c.m_UserProcessHandle == NULL || c.m_UserProcessId == 0)
    {
        return false;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (pe.th32ProcessID == c.m_UserProcessId)
                {
                    info.ParentProcessId = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    BOOL isWow64 = FALSE;
    if (IsWow64Process(c.m_UserProcessHandle, &isWow64))
    {
        info.IsWow64 = (isWow64 != FALSE);
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != NULL)
    {
        auto pNtQueryInformationProcess =
            reinterpret_cast<PFN_NtQueryInformationProcess>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));

        if (pNtQueryInformationProcess != nullptr)
        {
            PROCESS_BASIC_INFORMATION_TINY pbi = {};
            ULONG retLen = 0;
            NTSTATUS status = pNtQueryInformationProcess(
                c.m_UserProcessHandle,
                ProcessBasicInformation,
                &pbi,
                sizeof(pbi),
                &retLen);

            if (status >= 0 && pbi.PebBaseAddress != nullptr)
            {
                info.PebAddress = reinterpret_cast<DWORD_PTR>(pbi.PebBaseAddress);

                PEB_PARTIAL_X64 peb = {};
                SIZE_T read = 0;
                if (ReadProcessMemory(
                    c.m_UserProcessHandle,
                    pbi.PebBaseAddress,
                    &peb,
                    sizeof(peb),
                    &read) &&
                    read >= sizeof(peb))
                {
                    info.ImageBase = static_cast<DWORD_PTR>(peb.ImageBaseAddress);
                }
            }
        }
    }

    if (info.ImageBase != 0)
    {
        IMAGE_DOS_HEADER dos = {};
        SIZE_T read = 0;
        if (ReadProcessMemory(c.m_UserProcessHandle, reinterpret_cast<LPCVOID>(info.ImageBase), &dos, sizeof(dos), &read) &&
            read == sizeof(dos) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE &&
            dos.e_lfanew > 0 &&
            dos.e_lfanew < 0x1000)
        {
            BYTE ntHeaderBuf[0x200] = {};
            DWORD_PTR ntHdrAddr = info.ImageBase + static_cast<DWORD_PTR>(dos.e_lfanew);
            if (ReadProcessMemory(c.m_UserProcessHandle, reinterpret_cast<LPCVOID>(ntHdrAddr), ntHeaderBuf, sizeof(ntHeaderBuf), &read) &&
                read >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD))
            {
                auto ntSig = *reinterpret_cast<DWORD*>(ntHeaderBuf);
                if (ntSig == IMAGE_NT_SIGNATURE)
                {
                    auto fileHdr = reinterpret_cast<IMAGE_FILE_HEADER*>(ntHeaderBuf + sizeof(DWORD));
                    BYTE* optionalHeader = ntHeaderBuf + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
                    WORD magic = *reinterpret_cast<WORD*>(optionalHeader);

                    DWORD epRva = 0;
                    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                        fileHdr->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64))
                    {
                        auto opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optionalHeader);
                        epRva = opt64->AddressOfEntryPoint;
                    }
                    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                             fileHdr->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32))
                    {
                        auto opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optionalHeader);
                        epRva = opt32->AddressOfEntryPoint;
                    }

                    if (epRva != 0)
                    {
                        info.EntryPoint = info.ImageBase + static_cast<DWORD_PTR>(epRva);
                    }
                }
            }
        }
    }

    DBG_LOG(L"[DBG] User.GetProcessInfo pid=%u peb=0x%llX base=0x%llX ep=0x%llX wow64=%d ppid=%u\n",
            c.m_UserProcessId,
            static_cast<unsigned long long>(info.PebAddress),
            static_cast<unsigned long long>(info.ImageBase),
            static_cast<unsigned long long>(info.EntryPoint),
            info.IsWow64 ? 1 : 0,
            info.ParentProcessId);
    return true;
}

bool DumperClientUser::Ops::EnumProcesses(DumperClient& c, std::vector<DumperProcessEntry>& processes)
{
    (void)c;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return false;
    }

    do
    {
        DumperProcessEntry entry = {};
        entry.ProcessId = pe.th32ProcessID;
        entry.ParentProcessId = pe.th32ParentProcessID;
        entry.ThreadCount = pe.cntThreads;
        entry.ImageName = pe.szExeFile;
        entry.WorkingSetSize = 0;

        processes.push_back(std::move(entry));
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    std::sort(processes.begin(), processes.end(),
        [](const DumperProcessEntry& a, const DumperProcessEntry& b)
        {
            return a.ProcessId < b.ProcessId;
        });

    DBG_LOG(L"[DBG] User.EnumProcesses count=%u\n", static_cast<unsigned>(processes.size()));
    return true;
}

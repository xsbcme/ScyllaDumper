//
// ProcessOps.c - 进程操作：打开/关闭/挂起/恢复
//

#include "Driver.h"

// ============================================================================
// HandleOpenProcess - 通过 PID 获取 EPROCESS 引用
// ============================================================================

NTSTATUS
HandleOpenProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONG ProcessId
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;

    // 先清理旧引用
    if (Context->TargetProcess != NULL)
    {
        ObDereferenceObject(Context->TargetProcess);
        Context->TargetProcess = NULL;
    }

    // 通过 PID 查找 EPROCESS
    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId,
        &process
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("OpenProcess: PsLookupProcessByProcessId(%u) failed - 0x%X", ProcessId, status);
        return status;
    }

    Context->TargetProcess = process;
    Context->TargetProcessId = (HANDLE)(ULONG_PTR)ProcessId;

    DBG_PRINT("OpenProcess: PID=%u EPROCESS=%p", ProcessId, process);
    return STATUS_SUCCESS;
}

// ============================================================================
// HandleCloseProcess - 释放 EPROCESS 引用
// ============================================================================

NTSTATUS
HandleCloseProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context
)
{
    if (Context->TargetProcess != NULL)
    {
        DBG_PRINT("CloseProcess: releasing EPROCESS=%p", Context->TargetProcess);
        ObDereferenceObject(Context->TargetProcess);
        Context->TargetProcess = NULL;
        Context->TargetProcessId = NULL;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// HandleSuspendProcess - 挂起目标进程
// ============================================================================

NTSTATUS
HandleSuspendProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context
)
{
    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    return PsSuspendProcess(Context->TargetProcess);
}

// ============================================================================
// HandleResumeProcess - 恢复目标进程
// ============================================================================

NTSTATUS
HandleResumeProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context
)
{
    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    return PsResumeProcess(Context->TargetProcess);
}

// ============================================================================
// HandleEnumThreads - 枚举目标进程的线程
// 使用 ZwQuerySystemInformation(SystemProcessInformation) 获取全局进程/线程列表
// 在内核层执行，对受保护进程同样有效
// ============================================================================

NTSTATUS
HandleEnumThreads(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ThreadCount,
    _Out_ PULONG TotalSize
)
{
    NTSTATUS status;
    PVOID sysInfoBuffer = NULL;
    ULONG sysInfoSize = 0;
    ULONG returnedLength = 0;

    *ThreadCount = 0;
    *TotalSize = 0;

    if (Context->TargetProcess == NULL)
        return STATUS_INVALID_HANDLE;

    // 逐步增长缓冲区直到足够
    sysInfoSize = 1024 * 1024;  // 1MB 起始
    for (int attempt = 0; attempt < 3; attempt++)
    {
        sysInfoBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, sysInfoSize, 'thrD');
        if (!sysInfoBuffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            sysInfoBuffer,
            sysInfoSize,
            &returnedLength
        );

        if (NT_SUCCESS(status))
            break;

        ExFreePoolWithTag(sysInfoBuffer, 'thrD');
        sysInfoBuffer = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            sysInfoSize = returnedLength + 0x10000;
            continue;
        }

        return status;
    }

    if (!sysInfoBuffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    // 在返回的进程列表中查找目标进程
    PSYSTEM_PROCESS_INFORMATION_ENTRY procEntry =
        (PSYSTEM_PROCESS_INFORMATION_ENTRY)sysInfoBuffer;
    BOOLEAN found = FALSE;

    while (TRUE)
    {
        if (procEntry->UniqueProcessId == Context->TargetProcessId)
        {
            found = TRUE;
            break;
        }

        if (procEntry->NextEntryOffset == 0)
            break;

        procEntry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)(
            (PUCHAR)procEntry + procEntry->NextEntryOffset);
    }

    if (!found)
    {
        ExFreePoolWithTag(sysInfoBuffer, 'thrD');
        DBG_ERROR("EnumThreads: target process PID=%p not found",
                  Context->TargetProcessId);
        return STATUS_NOT_FOUND;
    }

    // 将线程信息拷贝到输出缓冲区
    PDUMPER_THREAD_ENTRY outEntry = (PDUMPER_THREAD_ENTRY)Buffer;
    ULONG count = 0;
    ULONG maxEntries = BufferSize / sizeof(DUMPER_THREAD_ENTRY);

    for (ULONG i = 0; i < procEntry->NumberOfThreads && count < maxEntries; i++)
    {
        PSYSTEM_THREAD_INFORMATION_ENTRY threadInfo = &procEntry->Threads[i];

        outEntry->ThreadId = (ULONG)(ULONG_PTR)threadInfo->ClientId.UniqueThread;
        outEntry->StartAddress = (ULONGLONG)threadInfo->StartAddress;
        outEntry->State = threadInfo->ThreadState;
        outEntry->WaitReason = threadInfo->WaitReason;
        outEntry->Priority = threadInfo->Priority;
        outEntry->BasePriority = threadInfo->BasePriority;

        outEntry++;
        count++;
    }

    ExFreePoolWithTag(sysInfoBuffer, 'thrD');

    *ThreadCount = count;
    *TotalSize = count * sizeof(DUMPER_THREAD_ENTRY);

    DBG_PRINT("EnumThreads: found %u threads for PID=%p",
              count, Context->TargetProcessId);
    return STATUS_SUCCESS;
}

// ============================================================================
// HandleGetThreadContext - 获取线程上下文 (寄存器)
// 使用 PsGetContextThread, 在内核层执行，绕过用户态保护
// ============================================================================

NTSTATUS
HandleGetThreadContext(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONG ThreadId,
    _Out_ PDUMPER_THREAD_CONTEXT OutContext
)
{
    NTSTATUS status;
    PETHREAD thread = NULL;
    CONTEXT ctx;

    UNREFERENCED_PARAMETER(Context);

    RtlZeroMemory(OutContext, sizeof(DUMPER_THREAD_CONTEXT));

    // 通过 TID 查找 ETHREAD
    status = PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)ThreadId,
        &thread
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("GetThreadContext: PsLookupThreadByThreadId(%u) failed - 0x%X",
                  ThreadId, status);
        return status;
    }

    // 准备 CONTEXT 结构
    RtlZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_FULL;

    // 获取线程上下文 (UserMode = 获取用户态寄存器状态)
    status = PsGetContextThread(thread, &ctx, UserMode);

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("GetThreadContext: PsGetContextThread TID=%u failed - 0x%X",
                  ThreadId, status);
        ObDereferenceObject(thread);
        return status;
    }

    // 拷贝关键寄存器到精简结构
    OutContext->Rax    = ctx.Rax;
    OutContext->Rbx    = ctx.Rbx;
    OutContext->Rcx    = ctx.Rcx;
    OutContext->Rdx    = ctx.Rdx;
    OutContext->Rsi    = ctx.Rsi;
    OutContext->Rdi    = ctx.Rdi;
    OutContext->Rbp    = ctx.Rbp;
    OutContext->Rsp    = ctx.Rsp;
    OutContext->R8     = ctx.R8;
    OutContext->R9     = ctx.R9;
    OutContext->R10    = ctx.R10;
    OutContext->R11    = ctx.R11;
    OutContext->R12    = ctx.R12;
    OutContext->R13    = ctx.R13;
    OutContext->R14    = ctx.R14;
    OutContext->R15    = ctx.R15;
    OutContext->Rip    = ctx.Rip;
    OutContext->EFlags = ctx.EFlags;
    OutContext->SegCs  = ctx.SegCs;
    OutContext->SegDs  = ctx.SegDs;
    OutContext->SegEs  = ctx.SegEs;
    OutContext->SegFs  = ctx.SegFs;
    OutContext->SegGs  = ctx.SegGs;
    OutContext->SegSs  = ctx.SegSs;

    ObDereferenceObject(thread);

    DBG_PRINT("GetThreadContext: TID=%u RIP=0x%llX RSP=0x%llX",
              ThreadId, ctx.Rip, ctx.Rsp);
    return STATUS_SUCCESS;
}

// ============================================================================
// HandleGetProcessInfo - 获取进程信息 (PEB, ImageBase, WoW64)
// 内核层直接访问 EPROCESS 结构, 对受保护进程有效
// ============================================================================

NTSTATUS
HandleGetProcessInfo(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _Out_ PULONGLONG PebAddress,
    _Out_ PULONGLONG ImageBase,
    _Out_ PULONGLONG EntryPoint,
    _Out_ PULONG IsWow64,
    _Out_ PULONG ParentProcessId
)
{
    if (Context->TargetProcess == NULL)
        return STATUS_INVALID_HANDLE;

    // PEB
    PPEB peb = PsGetProcessPeb(Context->TargetProcess);
    *PebAddress = (ULONGLONG)peb;

    // ImageBase (SectionBaseAddress)
    PVOID sectionBase = PsGetProcessSectionBaseAddress(Context->TargetProcess);
    *ImageBase = (ULONGLONG)sectionBase;

    // 入口点: 从进程内存中的 PE 头读取
    *EntryPoint = 0;
    if (sectionBase)
    {
        // 读取 DOS 头 e_lfanew
        K_IMAGE_DOS_HEADER dosHeader;
        SIZE_T bytesRead = 0;
        NTSTATUS status = MmCopyVirtualMemory(
            Context->TargetProcess,
            sectionBase,
            PsGetCurrentProcess(),
            &dosHeader,
            sizeof(dosHeader),
            KernelMode,
            &bytesRead
        );

        if (NT_SUCCESS(status) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE)
        {
            // 读取 NT 头来获取 AddressOfEntryPoint
            K_IMAGE_NT_HEADERS64 ntHeaders;
            status = MmCopyVirtualMemory(
                Context->TargetProcess,
                (PVOID)((ULONG_PTR)sectionBase + dosHeader.e_lfanew),
                PsGetCurrentProcess(),
                &ntHeaders,
                sizeof(ntHeaders),
                KernelMode,
                &bytesRead
            );

            if (NT_SUCCESS(status) && ntHeaders.Signature == IMAGE_NT_SIGNATURE)
            {
                ULONG ep = 0;
                if (ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    ep = ntHeaders.OptionalHeader.AddressOfEntryPoint;
                else
                    ep = ((K_IMAGE_NT_HEADERS32*)&ntHeaders)->OptionalHeader.AddressOfEntryPoint;

                *EntryPoint = (ULONGLONG)sectionBase + ep;
            }
        }
    }

    // WoW64 检查
    PVOID wow64Peb = PsGetProcessWow64Process(Context->TargetProcess);
    *IsWow64 = (wow64Peb != NULL) ? 1 : 0;

    // 父进程 ID - 通过 ZwQuerySystemInformation 获取更可靠
    // 简单方案: 使用 InheritedFromUniqueProcessId 但需要 EPROCESS 偏移
    // 安全方案: 设为 0, 由客户端按需查询
    *ParentProcessId = 0;

    DBG_PRINT("GetProcessInfo: PEB=%p ImageBase=%p EP=0x%llX WoW64=%u",
              peb, sectionBase, *EntryPoint, *IsWow64);
    return STATUS_SUCCESS;
}

// ============================================================================
// HandleEnumProcesses - 枚举系统所有进程
// 使用 ZwQuerySystemInformation(SystemProcessInformation)
// 无需先 OpenProcess, 由驱动层直接查询
// ============================================================================

NTSTATUS
HandleEnumProcesses(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ProcessCount,
    _Out_ PULONG TotalSize
)
{
    NTSTATUS status;
    PVOID sysInfoBuffer = NULL;
    ULONG sysInfoSize = 0;
    ULONG returnedLength = 0;

    *ProcessCount = 0;
    *TotalSize = 0;

    // 逐步增长缓冲区直到足够
    sysInfoSize = 2 * 1024 * 1024;  // 2MB 起始
    for (int attempt = 0; attempt < 3; attempt++)
    {
        sysInfoBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, sysInfoSize, 'psED');
        if (!sysInfoBuffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            sysInfoBuffer,
            sysInfoSize,
            &returnedLength
        );

        if (NT_SUCCESS(status))
            break;

        ExFreePoolWithTag(sysInfoBuffer, 'psED');
        sysInfoBuffer = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            sysInfoSize = returnedLength + 0x10000;
            continue;
        }

        return status;
    }

    if (!sysInfoBuffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    // 遍历进程列表, 写入输出缓冲区
    PDUMPER_PROCESS_ENTRY outEntry = (PDUMPER_PROCESS_ENTRY)Buffer;
    ULONG maxEntries = BufferSize / sizeof(DUMPER_PROCESS_ENTRY);
    ULONG count = 0;

    PSYSTEM_PROCESS_INFORMATION_ENTRY procEntry =
        (PSYSTEM_PROCESS_INFORMATION_ENTRY)sysInfoBuffer;

    while (count < maxEntries)
    {
        ULONG pid = (ULONG)(ULONG_PTR)procEntry->UniqueProcessId;

        outEntry->ProcessId = pid;
        outEntry->ParentProcessId = (ULONG)(ULONG_PTR)procEntry->InheritedFromUniqueProcessId;
        outEntry->ThreadCount = procEntry->NumberOfThreads;
        outEntry->WorkingSetSize = (ULONGLONG)procEntry->WorkingSetSize;
        outEntry->ImageName[0] = L'\0';

        // 拷贝进程名
        if (procEntry->ImageName.Length > 0 && procEntry->ImageName.Buffer != NULL)
        {
            USHORT copyLen = procEntry->ImageName.Length / sizeof(WCHAR);
            if (copyLen >= 260)
                copyLen = 259;
            RtlCopyMemory(outEntry->ImageName, procEntry->ImageName.Buffer, copyLen * sizeof(WCHAR));
            outEntry->ImageName[copyLen] = L'\0';
        }
        else if (pid == 0)
        {
            RtlCopyMemory(outEntry->ImageName, L"[System Idle]", 14 * sizeof(WCHAR));
        }
        else if (pid == 4)
        {
            RtlCopyMemory(outEntry->ImageName, L"System", 7 * sizeof(WCHAR));
        }

        outEntry++;
        count++;

        if (procEntry->NextEntryOffset == 0)
            break;

        procEntry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)(
            (PUCHAR)procEntry + procEntry->NextEntryOffset);
    }

    ExFreePoolWithTag(sysInfoBuffer, 'psED');

    *ProcessCount = count;
    *TotalSize = count * sizeof(DUMPER_PROCESS_ENTRY);

    DBG_PRINT("EnumProcesses: found %u processes", count);
    return STATUS_SUCCESS;
}

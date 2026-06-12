//
// MemoryOps.c - 内存操作：读取/写入/查询/保护
//
// 核心功能：通过内核 API 读写目标进程的虚拟内存，
// 替代用户态的 ReadProcessMemory / WriteProcessMemory 等调用。
//

#include "Driver.h"

// ============================================================================
// HandleReadMemory - 使用 MmCopyVirtualMemory 读取目标进程内存
// ============================================================================

NTSTATUS
HandleReadMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _Out_ PVOID Buffer,
    _Out_ PULONG BytesRead
)
{
    NTSTATUS status;
    SIZE_T   returnSize = 0;

    *BytesRead = 0;

    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    if (Size == 0 || Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 使用 MmCopyVirtualMemory 从目标进程复制到当前进程(System)
    status = MmCopyVirtualMemory(
        Context->TargetProcess,                     // 源进程
        (PVOID)(ULONG_PTR)BaseAddress,              // 源地址
        PsGetCurrentProcess(),                      // 目标进程 (System)
        Buffer,                                     // 目标缓冲区
        (SIZE_T)Size,                               // 大小
        KernelMode,                                 // 模式
        &returnSize                                 // 实际复制大小
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("ReadMemory: MmCopyVirtualMemory(0x%llX, 0x%X) failed - 0x%X",
                  BaseAddress, Size, status);
    }

    *BytesRead = (ULONG)returnSize;
    return status;
}

// ============================================================================
// HandleReadMemoryPartial - 部分读取，跳过未提交的页面
//
// 模拟 Scylla 的 readMemoryPartlyFromProcess：
// 逐区域查询，对已提交区域读取，对未提交区域填零。
// ============================================================================

NTSTATUS
HandleReadMemoryPartial(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _Out_ PVOID Buffer,
    _Out_ PULONG BytesRead
)
{
    NTSTATUS status;
    HANDLE   processHandle = NULL;
    ULONG    totalRead = 0;

    *BytesRead = 0;

    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    if (Size == 0 || Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 先全部填零
    RtlZeroMemory(Buffer, Size);

    // 获取目标进程的句柄 (在 System 上下文中)
    status = ObOpenObjectByPointer(
        Context->TargetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("ReadMemoryPartial: ObOpenObjectByPointer failed - 0x%X", status);
        return status;
    }

    ULONGLONG currentAddress = BaseAddress;
    ULONGLONG endAddress = BaseAddress + Size;

    while (currentAddress < endAddress)
    {
        MEMORY_BASIC_INFORMATION_KERNEL memInfo = { 0 };
        SIZE_T returnLength = 0;

        status = ZwQueryVirtualMemory(
            processHandle,
            (PVOID)(ULONG_PTR)currentAddress,
            MemoryBasicInformation,
            &memInfo,
            sizeof(memInfo),
            &returnLength
        );

        if (!NT_SUCCESS(status))
        {
            break;
        }

        ULONGLONG regionStart = (ULONGLONG)(ULONG_PTR)memInfo.BaseAddress;
        ULONGLONG regionEnd = regionStart + memInfo.RegionSize;

        // 限制到我们的请求范围
        if (regionStart < BaseAddress)
            regionStart = BaseAddress;
        if (regionEnd > endAddress)
            regionEnd = endAddress;

        SIZE_T bytesToProcess = (SIZE_T)(regionEnd - regionStart);
        ULONG  bufferOffset = (ULONG)(regionStart - BaseAddress);

        if (memInfo.State == MEM_COMMIT)
        {
            // 已提交页面 - 尝试读取 (失败则保持零填充)
            SIZE_T returnSize = 0;
            MmCopyVirtualMemory(
                Context->TargetProcess,
                (PVOID)(ULONG_PTR)regionStart,
                PsGetCurrentProcess(),
                (PUCHAR)Buffer + bufferOffset,
                bytesToProcess,
                KernelMode,
                &returnSize
            );
        }

        // 无论是否成功读取，都计入 totalRead (缓冲区已预填零)
        totalRead += (ULONG)bytesToProcess;

        // 前进到下一个区域
        currentAddress = (ULONGLONG)(ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize;

        if (currentAddress <= regionStart)
        {
            // 安全检查防止无限循环
            break;
        }
    }

    ZwClose(processHandle);

    DBG_PRINT("ReadMemoryPartial: addr=0x%llX size=0x%X totalRead=0x%X", BaseAddress, Size, totalRead);

    *BytesRead = totalRead;
    return STATUS_SUCCESS;
}

// ============================================================================
// HandleWriteMemory - 写入目标进程内存
// ============================================================================

NTSTATUS
HandleWriteMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _In_ PVOID Buffer,
    _Out_ PULONG BytesWritten
)
{
    NTSTATUS status;
    SIZE_T   returnSize = 0;

    *BytesWritten = 0;

    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    if (Size == 0 || Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 写入：从 System 进程复制到目标进程
    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),                      // 源进程 (System)
        Buffer,                                     // 源地址
        Context->TargetProcess,                     // 目标进程
        (PVOID)(ULONG_PTR)BaseAddress,              // 目标地址
        (SIZE_T)Size,
        KernelMode,
        &returnSize
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("WriteMemory: MmCopyVirtualMemory(0x%llX, 0x%X) failed - 0x%X",
                  BaseAddress, Size, status);
    }

    *BytesWritten = (ULONG)returnSize;
    return status;
}

// ============================================================================
// HandleQueryMemory - 查询内存区域信息
// ============================================================================

NTSTATUS
HandleQueryMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _Out_ PULONGLONG AllocationBase,
    _Out_ PULONGLONG RegionSize,
    _Out_ PULONG State,
    _Out_ PULONG Protect,
    _Out_ PULONG Type
)
{
    NTSTATUS status;
    HANDLE   processHandle = NULL;

    *AllocationBase = 0;
    *RegionSize = 0;
    *State = 0;
    *Protect = 0;
    *Type = 0;

    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    status = ObOpenObjectByPointer(
        Context->TargetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    MEMORY_BASIC_INFORMATION_KERNEL memInfo = { 0 };
    SIZE_T returnLength = 0;

    status = ZwQueryVirtualMemory(
        processHandle,
        (PVOID)(ULONG_PTR)BaseAddress,
        MemoryBasicInformation,
        &memInfo,
        sizeof(memInfo),
        &returnLength
    );

    ZwClose(processHandle);

    if (NT_SUCCESS(status))
    {
        *AllocationBase = (ULONGLONG)(ULONG_PTR)memInfo.AllocationBase;
        *RegionSize = (ULONGLONG)memInfo.RegionSize;
        *State = memInfo.State;
        *Protect = memInfo.Protect;
        *Type = memInfo.Type;
    }

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("QueryMemory: ZwQueryVirtualMemory(0x%llX) failed - 0x%X", BaseAddress, status);
    }

    return status;
}

// ============================================================================
// HandleProtectMemory - 修改内存保护属性
// ============================================================================

NTSTATUS
HandleProtectMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
)
{
    NTSTATUS status;
    HANDLE   processHandle = NULL;

    *OldProtect = 0;

    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    status = ObOpenObjectByPointer(
        Context->TargetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_VM_OPERATION,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID  baseAddr = (PVOID)(ULONG_PTR)BaseAddress;
    SIZE_T regionSize = (SIZE_T)Size;

    status = ZwProtectVirtualMemory(
        processHandle,
        &baseAddr,
        &regionSize,
        NewProtect,
        OldProtect
    );

    ZwClose(processHandle);
    return status;
}

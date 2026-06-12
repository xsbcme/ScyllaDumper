#pragma once

//
// MemoryOps.h - 内存操作 (读/写/查询/保护)
//

#include "Globals.h"

// 使用 MmCopyVirtualMemory 读取目标进程内存
NTSTATUS HandleReadMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _Out_ PVOID Buffer,
    _Out_ PULONG BytesRead
);

// 部分读取，跳过未提交的页面 (用于转存)
NTSTATUS HandleReadMemoryPartial(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _Out_ PVOID Buffer,
    _Out_ PULONG BytesRead
);

// 写入目标进程内存
NTSTATUS HandleWriteMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _In_ PVOID Buffer,
    _Out_ PULONG BytesWritten
);

// 查询内存区域信息
NTSTATUS HandleQueryMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _Out_ PULONGLONG AllocationBase,
    _Out_ PULONGLONG RegionSize,
    _Out_ PULONG State,
    _Out_ PULONG Protect,
    _Out_ PULONG Type
);

// 修改内存保护属性
NTSTATUS HandleProtectMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG Size,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

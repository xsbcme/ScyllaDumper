#pragma once

//
// ProcessOps.h - 进程操作 (打开/关闭/挂起/恢复)
//

#include "Globals.h"
#include "../Common/DumperProtocol.h"

// 通过 PID 获取 EPROCESS 引用
NTSTATUS HandleOpenProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONG ProcessId
);

// 释放 EPROCESS 引用
NTSTATUS HandleCloseProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context
);

// 挂起目标进程
NTSTATUS HandleSuspendProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context
);

// 恢复目标进程
NTSTATUS HandleResumeProcess(
    _In_ PDUMPER_DEVICE_CONTEXT Context
);

// 枚举目标进程的线程 (内核层, 对保护进程有效)
NTSTATUS HandleEnumThreads(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ThreadCount,
    _Out_ PULONG TotalSize
);

// 获取线程上下文/寄存器 (内核层, 通过 PsGetContextThread)
NTSTATUS HandleGetThreadContext(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _In_ ULONG ThreadId,
    _Out_ PDUMPER_THREAD_CONTEXT OutContext
);

// 获取进程信息: PEB, ImageBase, EntryPoint, WoW64 (内核层, 对保护进程有效)
NTSTATUS HandleGetProcessInfo(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _Out_ PULONGLONG PebAddress,
    _Out_ PULONGLONG ImageBase,
    _Out_ PULONGLONG EntryPoint,
    _Out_ PULONG IsWow64,
    _Out_ PULONG ParentProcessId
);

// 枚举系统所有进程 (无需先 OpenProcess)
NTSTATUS HandleEnumProcesses(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ProcessCount,
    _Out_ PULONG TotalSize
);

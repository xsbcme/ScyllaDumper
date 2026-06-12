//
// Driver.c - 驱动框架：入口、卸载、资源清理
//
// 作者: xsbcme  |  2974550071@qq.com
//
// KDMapper 兼容:
//   - DriverEntry 检测 DriverObject 是否为 NULL 以区分加载方式
//   - KDMapper 加载: DriverObject==NULL，不创建设备对象，直接初始化共享内存+工作线程
//   - 正常加载 (sc start): DriverObject!=NULL，注册 DriverUnload
//   - DriverEntry 快速返回，工作线程在后台处理命令
//

#include "Driver.h"
#include "../Common/DumperProtocol.h"

// 全局设备上下文
static DUMPER_DEVICE_CONTEXT g_DeviceContext = { 0 };

// 正常加载时的设备对象
static PDEVICE_OBJECT g_DeviceObject = NULL;

// ============================================================================
// DriverCleanup - 释放所有资源 (可从工作线程或 DriverUnload 调用)
// ============================================================================

VOID
DriverCleanup(VOID)
{
    PKTHREAD currentThread = KeGetCurrentThread();

    DBG_PRINT("DriverCleanup: begin (caller thread=%p, worker=%p)",
              currentThread, g_DeviceContext.WorkerThread);

    // 停止工作线程 (若非从工作线程自身调用)
    if (g_DeviceContext.WorkerThread != NULL)
    {
        if (g_DeviceContext.WorkerThread != currentThread)
        {
            // 从外部调用 (DriverUnload) → 通知并等待工作线程退出
            g_DeviceContext.WorkerShouldStop = TRUE;
            KeSetEvent(&g_DeviceContext.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
            KeWaitForSingleObject(
                g_DeviceContext.WorkerThread,
                Executive,
                KernelMode,
                FALSE,
                NULL
            );
            ObDereferenceObject(g_DeviceContext.WorkerThread);
            g_DeviceContext.WorkerThread = NULL;
            DBG_PRINT("DriverCleanup: worker thread stopped (external)");
        }
        else
        {
            // 从工作线程自身调用 (CMD_SHUTDOWN) → 不能等待自己
            ObDereferenceObject(g_DeviceContext.WorkerThread);
            g_DeviceContext.WorkerThread = NULL;
            DBG_PRINT("DriverCleanup: worker thread self-cleanup");
        }
    }

    // 关闭目标进程引用
    if (g_DeviceContext.TargetProcess != NULL)
    {
        ObDereferenceObject(g_DeviceContext.TargetProcess);
        g_DeviceContext.TargetProcess = NULL;
        DBG_PRINT("DriverCleanup: target process released");
    }

    // 清理共享内存和事件
    CleanupSharedMemory(&g_DeviceContext);
    g_DeviceContext.Initialized = FALSE;

    DBG_PRINT("DriverCleanup: done");
}

// ============================================================================
// DriverUnload - 正常加载时的卸载回调
// ============================================================================

static VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DBG_PRINT("DriverUnload: unloading...");

    DriverCleanup();

    // 删除符号链接和设备 (仅正常加载时存在)
    if (g_DeviceObject != NULL)
    {
        UNICODE_STRING symbolicLink;
        RtlInitUnicodeString(&symbolicLink, DUMPER_SYMBOLIC_LINK);
        IoDeleteSymbolicLink(&symbolicLink);

        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DBG_PRINT("DriverUnload: done");
}

// ============================================================================
// DriverEntry - KDMapper 兼容入口
// ============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    HANDLE   threadHandle = NULL;

    DBG_PRINT("DriverEntry: DriverObject=%p RegistryPath=%p", DriverObject, RegistryPath);

    //
    // 区分加载方式
    //
    if (DriverObject != NULL)
    {
        // 正常加载 (sc create / sc start) → 注册 DriverUnload
        DBG_PRINT("DriverEntry: normal driver load, registering DriverUnload");
        DriverObject->DriverUnload = DriverUnload;
    }
    else
    {
        // KDMapper 手动映射 → DriverObject 为 NULL
        DBG_PRINT("DriverEntry: KDMapper load detected (DriverObject=NULL)");
    }

    //
    // 初始化共享内存 (创建命名 Section + 命名 Event，映射到系统地址空间)
    //
    status = InitSharedMemory(&g_DeviceContext);
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("DriverEntry: InitSharedMemory failed - 0x%X", status);
        return status;
    }

    //
    // 初始化工作线程停止事件
    //
    KeInitializeEvent(&g_DeviceContext.WorkerStopEvent, NotificationEvent, FALSE);
    g_DeviceContext.WorkerShouldStop = FALSE;

    //
    // 启动工作线程 (运行在 System 进程中)
    //
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        WorkerThreadRoutine,
        &g_DeviceContext
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("DriverEntry: PsCreateSystemThread failed - 0x%X", status);
        CleanupSharedMemory(&g_DeviceContext);
        return status;
    }

    // 获取线程对象引用 (用于后续等待/清理)
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&g_DeviceContext.WorkerThread,
        NULL
    );
    ZwClose(threadHandle);

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("DriverEntry: ObReferenceObjectByHandle(thread) failed - 0x%X", status);
        g_DeviceContext.WorkerShouldStop = TRUE;
        CleanupSharedMemory(&g_DeviceContext);
        return status;
    }

    g_DeviceContext.Initialized = TRUE;

    DBG_PRINT("DriverEntry: success, shared memory=%p size=%u, worker=%p",
              g_DeviceContext.SharedMemoryKernelVa,
              g_DeviceContext.SharedMemorySize,
              g_DeviceContext.WorkerThread);

    return STATUS_SUCCESS;
}

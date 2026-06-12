//
// SharedMemory.c - 共享内存初始化与清理
//
// KDMapper 兼容方案：
//   使用 ZwCreateSection 创建命名 Section，MmMapViewInSystemSpace 映射到
//   系统级内核地址空间（所有进程上下文均可访问）。
//   用户态通过 OpenFileMapping 打开同名 Section 实现共享。
//

#include "Driver.h"
#include "../Common/DumperProtocol.h"

// ============================================================================
// InitSharedMemory - 创建命名 Section + 映射到系统空间 + 创建命名事件
// ============================================================================

NTSTATUS
InitSharedMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context
)
{
    NTSTATUS           status;
    UNICODE_STRING     sectionName;
    OBJECT_ATTRIBUTES  oa;
    LARGE_INTEGER      sectionSize;
    PVOID              sectionObject = NULL;

    // 构造允许所有访问的安全描述符 (让用户态进程可以打开命名对象)
    SECURITY_DESCRIPTOR sd;
    status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: RtlCreateSecurityDescriptor failed - 0x%X", status);
        return status;
    }
    // 设置 NULL DACL = 允许所有访问
    status = RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: RtlSetDaclSecurityDescriptor failed - 0x%X", status);
        return status;
    }

    DBG_PRINT("InitSharedMemory: begin");

    // 如果已存在，先清理
    if (Context->SharedMemoryKernelVa != NULL)
    {
        DBG_WARN("InitSharedMemory: previous mapping exists, cleaning up");
        CleanupSharedMemory(Context);
    }

    //
    // 1. 创建命名 Section (用户态可通过 OpenFileMapping 访问)
    //
    RtlInitUnicodeString(&sectionName, DUMPER_SECTION_NAME);
    InitializeObjectAttributes(&oa, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sd);
    sectionSize.QuadPart = DUMPER_SHARED_MEMORY_SIZE;

    status = ZwCreateSection(
        &Context->SectionHandle,
        SECTION_ALL_ACCESS,
        &oa,
        &sectionSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: ZwCreateSection failed - 0x%X", status);
        return status;
    }

    DBG_PRINT("InitSharedMemory: Section created, handle=%p", Context->SectionHandle);

    //
    // 2. 获取 Section 对象指针，用于 MmMapViewInSystemSpace
    //
    status = ObReferenceObjectByHandle(
        Context->SectionHandle,
        SECTION_ALL_ACCESS,
        NULL,
        KernelMode,
        &sectionObject,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: ObReferenceObjectByHandle(Section) failed - 0x%X", status);
        ZwClose(Context->SectionHandle);
        Context->SectionHandle = NULL;
        return status;
    }

    //
    // 3. 映射到系统地址空间 (所有进程上下文均可访问，避免 KDMapper 进程上下文问题)
    //
    Context->SharedMemorySize = DUMPER_SHARED_MEMORY_SIZE;
    SIZE_T viewSize = (SIZE_T)Context->SharedMemorySize;

    status = MmMapViewInSystemSpace(sectionObject, &Context->SharedMemoryKernelVa, &viewSize);
    ObDereferenceObject(sectionObject);

    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: MmMapViewInSystemSpace failed - 0x%X", status);
        ZwClose(Context->SectionHandle);
        Context->SectionHandle = NULL;
        return status;
    }

    DBG_PRINT("InitSharedMemory: mapped to system space VA=%p size=%llu",
              Context->SharedMemoryKernelVa, (ULONGLONG)viewSize);

    //
    // 4. 初始化共享头部
    //
    RtlZeroMemory(Context->SharedMemoryKernelVa, Context->SharedMemorySize);

    PDUMPER_SHARED_HEADER header = (PDUMPER_SHARED_HEADER)Context->SharedMemoryKernelVa;
    header->ProtocolVersion = DUMPER_PROTOCOL_VERSION;
    header->Command = DumperCmdNone;
    header->Status = DumperStatusIdle;

    //
    // 5. 创建命名同步事件 (用户态通过 OpenEvent 访问)
    //
    UNICODE_STRING requestEventName;
    UNICODE_STRING responseEventName;
    RtlInitUnicodeString(&requestEventName, DUMPER_REQUEST_EVENT_NAME);
    RtlInitUnicodeString(&responseEventName, DUMPER_RESPONSE_EVENT_NAME);

    // Request Event
    InitializeObjectAttributes(&oa, &requestEventName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sd);
    status = ZwCreateEvent(
        &Context->RequestEventHandle,
        EVENT_ALL_ACCESS,
        &oa,
        SynchronizationEvent,
        FALSE
    );
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: ZwCreateEvent(Request) failed - 0x%X", status);
        goto cleanup;
    }

    status = ObReferenceObjectByHandle(
        Context->RequestEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        (PVOID*)&Context->RequestEvent,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: ObReferenceObjectByHandle(Request) failed - 0x%X", status);
        ZwClose(Context->RequestEventHandle);
        Context->RequestEventHandle = NULL;
        goto cleanup;
    }

    // Response Event
    InitializeObjectAttributes(&oa, &responseEventName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sd);
    status = ZwCreateEvent(
        &Context->ResponseEventHandle,
        EVENT_ALL_ACCESS,
        &oa,
        SynchronizationEvent,
        FALSE
    );
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: ZwCreateEvent(Response) failed - 0x%X", status);
        goto cleanup;
    }

    status = ObReferenceObjectByHandle(
        Context->ResponseEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        (PVOID*)&Context->ResponseEvent,
        NULL
    );
    if (!NT_SUCCESS(status))
    {
        DBG_ERROR("InitSharedMemory: ObReferenceObjectByHandle(Response) failed - 0x%X", status);
        ZwClose(Context->ResponseEventHandle);
        Context->ResponseEventHandle = NULL;
        goto cleanup;
    }

    DBG_PRINT("InitSharedMemory: success (Section=%p, KernelVA=%p, ReqEvt=%p, RspEvt=%p)",
              Context->SectionHandle, Context->SharedMemoryKernelVa,
              Context->RequestEvent, Context->ResponseEvent);
    return STATUS_SUCCESS;

cleanup:
    CleanupSharedMemory(Context);
    return status;
}

// ============================================================================
// CleanupSharedMemory - 释放 Section、映射、事件
// ============================================================================

VOID
CleanupSharedMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context
)
{
    DBG_PRINT("CleanupSharedMemory: begin");

    // 释放事件对象引用和句柄
    if (Context->ResponseEvent)
    {
        ObDereferenceObject(Context->ResponseEvent);
        Context->ResponseEvent = NULL;
    }
    if (Context->ResponseEventHandle)
    {
        ZwClose(Context->ResponseEventHandle);
        Context->ResponseEventHandle = NULL;
    }
    if (Context->RequestEvent)
    {
        ObDereferenceObject(Context->RequestEvent);
        Context->RequestEvent = NULL;
    }
    if (Context->RequestEventHandle)
    {
        ZwClose(Context->RequestEventHandle);
        Context->RequestEventHandle = NULL;
    }

    // 取消系统空间映射
    if (Context->SharedMemoryKernelVa)
    {
        MmUnmapViewInSystemSpace(Context->SharedMemoryKernelVa);
        Context->SharedMemoryKernelVa = NULL;
    }

    // 关闭 Section 句柄
    if (Context->SectionHandle)
    {
        ZwClose(Context->SectionHandle);
        Context->SectionHandle = NULL;
    }

    Context->SharedMemorySize = 0;

    DBG_PRINT("CleanupSharedMemory: done");
}

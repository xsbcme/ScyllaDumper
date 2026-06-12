//
// Worker.c - 工作线程：等待用户态请求并分发给对应的命令处理函数
//

#include "Driver.h"
#include "../Common/DumperProtocol.h"

static const char*
DumperCommandNameA(
    _In_ DUMPER_COMMAND_TYPE cmd
)
{
    switch (cmd)
    {
    case DumperCmdNone: return "None";
    case DumperCmdOpenProcess: return "OpenProcess";
    case DumperCmdCloseProcess: return "CloseProcess";
    case DumperCmdReadMemory: return "ReadMemory";
    case DumperCmdWriteMemory: return "WriteMemory";
    case DumperCmdQueryMemory: return "QueryMemory";
    case DumperCmdReadMemoryPartial: return "ReadMemoryPartial";
    case DumperCmdProtectMemory: return "ProtectMemory";
    case DumperCmdSuspendProcess: return "SuspendProcess";
    case DumperCmdResumeProcess: return "ResumeProcess";
    case DumperCmdEnumModules: return "EnumModules";
    case DumperCmdEnumThreads: return "EnumThreads";
    case DumperCmdGetThreadContext: return "GetThreadContext";
    case DumperCmdGetProcessInfo: return "GetProcessInfo";
    case DumperCmdEnumProcesses: return "EnumProcesses";
    case DumperCmdShutdown: return "Shutdown";
    default: return "Unknown";
    }
}

// ============================================================================
// WorkerThreadRoutine - 命令分发循环
// ============================================================================

VOID
WorkerThreadRoutine(
    _In_ PVOID StartContext
)
{
    PDUMPER_DEVICE_CONTEXT context = (PDUMPER_DEVICE_CONTEXT)StartContext;
    PDUMPER_SHARED_HEADER  header = (PDUMPER_SHARED_HEADER)context->SharedMemoryKernelVa;
    PUCHAR                 dataBuffer = DUMPER_GET_DATA_BUFFER(header);
    PVOID                  waitObjects[2];
    NTSTATUS               waitStatus;
    BOOLEAN                shouldShutdown = FALSE;

    waitObjects[0] = context->RequestEvent;
    waitObjects[1] = &context->WorkerStopEvent;

    DBG_PRINT("WorkerThread: started, waiting for commands");

    while (!context->WorkerShouldStop)
    {
        // 等待请求事件或停止事件
        waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
        );

        // 停止事件被通知
        if (waitStatus == STATUS_WAIT_1 || context->WorkerShouldStop)
        {
            DBG_PRINT("WorkerThread: stop event signaled");
            break;
        }

        // 请求事件被通知
        if (waitStatus != STATUS_WAIT_0)
        {
            continue;
        }

        // 校验状态
        if (header->Status != DumperStatusPending)
        {
            continue;
        }

        NTSTATUS cmdStatus = STATUS_SUCCESS;

        DBG_PRINT("WorkerThread: command=%s id=%u",
                  DumperCommandNameA(header->Command),
                  header->Command);

        switch (header->Command)
        {
        case DumperCmdOpenProcess:
        {
            DBG_PRINT("Cmd: OpenProcess PID=%u", header->Params.OpenProcess.ProcessId);
            cmdStatus = HandleOpenProcess(context, header->Params.OpenProcess.ProcessId);
            break;
        }

        case DumperCmdCloseProcess:
        {
            DBG_PRINT("Cmd: CloseProcess");
            cmdStatus = HandleCloseProcess(context);
            break;
        }

        case DumperCmdReadMemory:
        {
            ULONG bytesRead = 0;
            ULONG requestSize = header->Params.ReadMemory.Size;

            // 保护：不让读取超过数据缓冲区
            if (requestSize > DUMPER_DATA_BUFFER_SIZE)
                requestSize = DUMPER_DATA_BUFFER_SIZE;

            DBG_PRINT("Cmd: ReadMemory addr=0x%llX size=0x%X",
                      header->Params.ReadMemory.BaseAddress, requestSize);
            cmdStatus = HandleReadMemory(
                context,
                header->Params.ReadMemory.BaseAddress,
                requestSize,
                dataBuffer,
                &bytesRead
            );
            header->Params.ReadMemory.BytesRead = bytesRead;
            DBG_PRINT("Cmd: ReadMemory result=0x%X bytesRead=0x%X", cmdStatus, bytesRead);
            break;
        }

        case DumperCmdReadMemoryPartial:
        {
            ULONG bytesRead = 0;
            ULONG requestSize = header->Params.ReadMemory.Size;

            if (requestSize > DUMPER_DATA_BUFFER_SIZE)
                requestSize = DUMPER_DATA_BUFFER_SIZE;

            DBG_PRINT("Cmd: ReadMemoryPartial addr=0x%llX size=0x%X",
                      header->Params.ReadMemory.BaseAddress, requestSize);
            cmdStatus = HandleReadMemoryPartial(
                context,
                header->Params.ReadMemory.BaseAddress,
                requestSize,
                dataBuffer,
                &bytesRead
            );
            header->Params.ReadMemory.BytesRead = bytesRead;
            DBG_PRINT("Cmd: ReadMemoryPartial result=0x%X bytesRead=0x%X", cmdStatus, bytesRead);
            break;
        }

        case DumperCmdWriteMemory:
        {
            ULONG bytesWritten = 0;
            ULONG requestSize = header->Params.WriteMemory.Size;

            if (requestSize > DUMPER_DATA_BUFFER_SIZE)
                requestSize = DUMPER_DATA_BUFFER_SIZE;

            DBG_PRINT("Cmd: WriteMemory addr=0x%llX size=0x%X",
                      header->Params.WriteMemory.BaseAddress, requestSize);
            cmdStatus = HandleWriteMemory(
                context,
                header->Params.WriteMemory.BaseAddress,
                requestSize,
                dataBuffer,
                &bytesWritten
            );
            header->Params.WriteMemory.BytesWritten = bytesWritten;
            DBG_PRINT("Cmd: WriteMemory result=0x%X bytesWritten=0x%X", cmdStatus, bytesWritten);
            break;
        }

        case DumperCmdQueryMemory:
        {
            DBG_PRINT("Cmd: QueryMemory addr=0x%llX", header->Params.QueryMemory.BaseAddress);
            cmdStatus = HandleQueryMemory(
                context,
                header->Params.QueryMemory.BaseAddress,
                &header->Params.QueryMemory.AllocationBase,
                &header->Params.QueryMemory.RegionSize,
                &header->Params.QueryMemory.State,
                &header->Params.QueryMemory.Protect,
                &header->Params.QueryMemory.Type
            );
            break;
        }

        case DumperCmdProtectMemory:
        {
            DBG_PRINT("Cmd: ProtectMemory addr=0x%llX newProtect=0x%X",
                      header->Params.ProtectMemory.BaseAddress,
                      header->Params.ProtectMemory.NewProtect);
            cmdStatus = HandleProtectMemory(
                context,
                header->Params.ProtectMemory.BaseAddress,
                header->Params.ProtectMemory.Size,
                header->Params.ProtectMemory.NewProtect,
                &header->Params.ProtectMemory.OldProtect
            );
            break;
        }

        case DumperCmdSuspendProcess:
        {
            DBG_PRINT("Cmd: SuspendProcess");
            cmdStatus = HandleSuspendProcess(context);
            break;
        }

        case DumperCmdResumeProcess:
        {
            DBG_PRINT("Cmd: ResumeProcess");
            cmdStatus = HandleResumeProcess(context);
            break;
        }

        case DumperCmdEnumModules:
        {
            DBG_PRINT("Cmd: EnumModules");
            ULONG moduleCount = 0;
            ULONG totalSize = 0;
            cmdStatus = HandleEnumModules(
                context,
                dataBuffer,
                DUMPER_DATA_BUFFER_SIZE,
                &moduleCount,
                &totalSize
            );
            header->Params.EnumModules.ModuleCount = moduleCount;
            header->Params.EnumModules.TotalSize = totalSize;
            DBG_PRINT("Cmd: EnumModules result=0x%X count=%u", cmdStatus, moduleCount);
            break;
        }

        case DumperCmdEnumThreads:
        {
            DBG_PRINT("Cmd: EnumThreads");
            ULONG threadCount = 0;
            ULONG totalSize = 0;
            cmdStatus = HandleEnumThreads(
                context,
                dataBuffer,
                DUMPER_DATA_BUFFER_SIZE,
                &threadCount,
                &totalSize
            );
            header->Params.EnumThreads.ThreadCount = threadCount;
            header->Params.EnumThreads.TotalSize = totalSize;
            DBG_PRINT("Cmd: EnumThreads result=0x%X count=%u", cmdStatus, threadCount);
            break;
        }

        case DumperCmdGetThreadContext:
        {
            DBG_PRINT("Cmd: GetThreadContext TID=%u", header->Params.GetThreadContext.ThreadId);
            PDUMPER_THREAD_CONTEXT outCtx = (PDUMPER_THREAD_CONTEXT)dataBuffer;
            cmdStatus = HandleGetThreadContext(
                context,
                header->Params.GetThreadContext.ThreadId,
                outCtx
            );
            DBG_PRINT("Cmd: GetThreadContext result=0x%X", cmdStatus);
            break;
        }

        case DumperCmdGetProcessInfo:
        {
            DBG_PRINT("Cmd: GetProcessInfo");
            cmdStatus = HandleGetProcessInfo(
                context,
                &header->Params.ProcessInfo.PebAddress,
                &header->Params.ProcessInfo.ImageBase,
                &header->Params.ProcessInfo.EntryPoint,
                &header->Params.ProcessInfo.IsWow64,
                &header->Params.ProcessInfo.ParentProcessId
            );
            DBG_PRINT("Cmd: GetProcessInfo result=0x%X", cmdStatus);
            break;
        }

        case DumperCmdEnumProcesses:
        {
            DBG_PRINT("Cmd: EnumProcesses");
            ULONG processCount = 0;
            ULONG totalSize = 0;
            cmdStatus = HandleEnumProcesses(
                dataBuffer,
                DUMPER_DATA_BUFFER_SIZE,
                &processCount,
                &totalSize
            );
            header->Params.EnumProcesses.ProcessCount = processCount;
            header->Params.EnumProcesses.TotalSize = totalSize;
            DBG_PRINT("Cmd: EnumProcesses result=0x%X count=%u", cmdStatus, processCount);
            break;
        }

        case DumperCmdShutdown:
        {
            DBG_PRINT("Cmd: Shutdown received");
            cmdStatus = STATUS_SUCCESS;
            shouldShutdown = TRUE;
            break;
        }

        default:
            DBG_WARN("WorkerThread: unknown command %u", header->Command);
            cmdStatus = STATUS_INVALID_PARAMETER;
            break;
        }

        // 写入结果
        header->NtStatus = cmdStatus;
        header->Status = NT_SUCCESS(cmdStatus) ? DumperStatusCompleted : DumperStatusError;

        if (!NT_SUCCESS(cmdStatus))
        {
            DBG_ERROR("WorkerThread: command %u failed - 0x%X", header->Command, cmdStatus);
        }

        // 内存屏障确保写入可见
        KeMemoryBarrier();

        // 通知用户态
        KeSetEvent(context->ResponseEvent, IO_NO_INCREMENT, FALSE);

        // Shutdown 命令: 先发送响应再退出循环
        if (shouldShutdown)
        {
            DBG_PRINT("WorkerThread: shutdown acknowledged, exiting loop");
            break;
        }
    }

    DBG_PRINT("WorkerThread: exiting, calling DriverCleanup");
    DriverCleanup();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

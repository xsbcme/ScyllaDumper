//
// ModuleEnum.c - 进程模块枚举
//
// 通过扫描目标进程地址空间的 MEM_IMAGE 区域实现模块枚举。
//

#include "Driver.h"
#include "../Common/DumperProtocol.h"

// 从目标进程内存中读取 PE SizeOfImage
static ULONG ReadSizeOfImageFromProcess(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress
)
{
    SIZE_T bytesRead = 0;
    K_IMAGE_DOS_HEADER dosHeader = { 0 };

    NTSTATUS status = MmCopyVirtualMemory(
        Process, BaseAddress,
        PsGetCurrentProcess(), &dosHeader,
        sizeof(dosHeader), KernelMode, &bytesRead);

    if (!NT_SUCCESS(status) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    K_IMAGE_NT_HEADERS64 ntHeaders = { 0 };
    status = MmCopyVirtualMemory(
        Process, (PVOID)((ULONG_PTR)BaseAddress + dosHeader.e_lfanew),
        PsGetCurrentProcess(), &ntHeaders,
        sizeof(ntHeaders), KernelMode, &bytesRead);

    if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    if (ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return ntHeaders.OptionalHeader.SizeOfImage;
    else
        return ((K_IMAGE_NT_HEADERS32*)&ntHeaders)->OptionalHeader.SizeOfImage;
}

// ============================================================================
// HandleEnumModules - 枚举进程加载的模块
// ============================================================================

NTSTATUS
HandleEnumModules(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ModuleCount,
    _Out_ PULONG TotalSize
)
{
    NTSTATUS status;
    HANDLE   processHandle = NULL;

    *ModuleCount = 0;
    *TotalSize = 0;

    if (Context->TargetProcess == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    // 使用 ZwQueryVirtualMemory 扫描地址空间，找到所有 MEM_IMAGE 类型的区域
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

    PDUMPER_MODULE_ENTRY entries = (PDUMPER_MODULE_ENTRY)Buffer;
    ULONG maxEntries = BufferSize / sizeof(DUMPER_MODULE_ENTRY);
    ULONG count = 0;

    ULONGLONG address = 0;
    ULONGLONG lastBase = (ULONGLONG)-1;

    while (count < maxEntries)
    {
        MEMORY_BASIC_INFORMATION_KERNEL memInfo = { 0 };
        SIZE_T returnLength = 0;

        status = ZwQueryVirtualMemory(
            processHandle,
            (PVOID)(ULONG_PTR)address,
            MemoryBasicInformation,
            &memInfo,
            sizeof(memInfo),
            &returnLength
        );

        if (!NT_SUCCESS(status))
        {
            break;
        }

        // MEM_IMAGE 类型且是 AllocationBase (模块基地址)
        if (memInfo.Type == MEM_IMAGE &&
            (ULONGLONG)(ULONG_PTR)memInfo.AllocationBase != lastBase)
        {
            lastBase = (ULONGLONG)(ULONG_PTR)memInfo.AllocationBase;

            entries[count].BaseAddress = lastBase;
            entries[count].Size = 0;
            entries[count].FullPath[0] = L'\0';

            // 查询映射文件名 (MemoryMappedFilenameInformation = 2)
            {
                // 缓冲区: UNICODE_STRING 头 + 最多 260 WCHAR 的字符串数据
                UCHAR nameBuffer[sizeof(UNICODE_STRING) + 260 * sizeof(WCHAR)];
                SIZE_T nameReturnLength = 0;
                RtlZeroMemory(nameBuffer, sizeof(nameBuffer));

                NTSTATUS nameStatus = ZwQueryVirtualMemory(
                    processHandle,
                    (PVOID)(ULONG_PTR)lastBase,
                    (MEMORY_INFORMATION_CLASS)2,   // MemorySectionName
                    nameBuffer,
                    sizeof(nameBuffer),
                    &nameReturnLength
                );

                if (NT_SUCCESS(nameStatus))
                {
                    PUNICODE_STRING mappedName = (PUNICODE_STRING)nameBuffer;
                    if (mappedName->Length > 0 && mappedName->Buffer != NULL)
                    {
                        USHORT copyLen = mappedName->Length / sizeof(WCHAR);
                        if (copyLen >= 260)
                            copyLen = 259;
                        RtlCopyMemory(entries[count].FullPath, mappedName->Buffer, copyLen * sizeof(WCHAR));
                        entries[count].FullPath[copyLen] = L'\0';
                        DBG_PRINT("EnumModules: [%u] base=0x%llX path=%wZ", count, lastBase, mappedName);
                    }
                }
                else
                {
                    DBG_WARN("EnumModules: [%u] base=0x%llX MemorySectionName failed 0x%X", count, lastBase, nameStatus);
                }
            }

            // 计算模块大小 (连续 MEM_IMAGE 区域)
            ULONGLONG moduleEnd = (ULONGLONG)(ULONG_PTR)memInfo.BaseAddress +
                                  memInfo.RegionSize;

            MEMORY_BASIC_INFORMATION_KERNEL nextInfo = { 0 };
            ULONGLONG scanAddr = moduleEnd;

            while (TRUE)
            {
                status = ZwQueryVirtualMemory(
                    processHandle,
                    (PVOID)(ULONG_PTR)scanAddr,
                    MemoryBasicInformation,
                    &nextInfo,
                    sizeof(nextInfo),
                    &returnLength
                );

                if (!NT_SUCCESS(status) ||
                    nextInfo.Type != MEM_IMAGE ||
                    (ULONGLONG)(ULONG_PTR)nextInfo.AllocationBase != lastBase)
                {
                    break;
                }

                moduleEnd = (ULONGLONG)(ULONG_PTR)nextInfo.BaseAddress +
                            nextInfo.RegionSize;
                scanAddr = moduleEnd;
            }

            entries[count].Size = (ULONG)(moduleEnd - lastBase);
            count++;
        }

        // 前进到下一区域
        ULONGLONG nextAddress = (ULONGLONG)(ULONG_PTR)memInfo.BaseAddress +
                                memInfo.RegionSize;
        if (nextAddress <= address)
        {
            break;  // 溢出保护
        }
        address = nextAddress;
    }

    ZwClose(processHandle);

    // 确保主模块 (EXE) 始终在列表中
    // 某些保护进程的 EXE 内存区域可能不是 MEM_IMAGE 类型, 会被上面的扫描漏掉
    PVOID sectionBase = PsGetProcessSectionBaseAddress(Context->TargetProcess);
    if (sectionBase && count < maxEntries)
    {
        ULONGLONG imageBase = (ULONGLONG)(ULONG_PTR)sectionBase;
        BOOLEAN found = FALSE;
        for (ULONG i = 0; i < count; i++)
        {
            if (entries[i].BaseAddress == imageBase)
            {
                found = TRUE;
                break;
            }
        }

        if (!found)
        {
            DBG_PRINT("EnumModules: main EXE (0x%llX) not in MEM_IMAGE list, adding manually", imageBase);

            // 读取 SizeOfImage 从进程内存 PE 头
            ULONG sizeOfImage = ReadSizeOfImageFromProcess(Context->TargetProcess, sectionBase);
            if (sizeOfImage == 0)
                sizeOfImage = 0x1000;  // 最小回退值

            // 将主模块插入为第一个条目, 其余后移
            if (count > 0)
            {
                RtlMoveMemory(&entries[1], &entries[0], count * sizeof(DUMPER_MODULE_ENTRY));
            }

            entries[0].BaseAddress = imageBase;
            entries[0].Size = sizeOfImage;
            entries[0].FullPath[0] = L'\0';

            // 尝试获取文件路径: 先试 MemorySectionName, 失败则用 SeLocateProcessImageName
            BOOLEAN gotName = FALSE;
            {
                HANDLE hProc = NULL;
                NTSTATUS openStatus = ObOpenObjectByPointer(
                    Context->TargetProcess, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProc);
                if (NT_SUCCESS(openStatus))
                {
                    UCHAR nameBuffer[sizeof(UNICODE_STRING) + 260 * sizeof(WCHAR)];
                    SIZE_T nameRetLen = 0;
                    RtlZeroMemory(nameBuffer, sizeof(nameBuffer));

                    NTSTATUS nameStatus = ZwQueryVirtualMemory(
                        hProc, sectionBase,
                        (MEMORY_INFORMATION_CLASS)2,
                        nameBuffer, sizeof(nameBuffer), &nameRetLen);

                    if (NT_SUCCESS(nameStatus))
                    {
                        PUNICODE_STRING mappedName = (PUNICODE_STRING)nameBuffer;
                        if (mappedName->Length > 0 && mappedName->Buffer != NULL)
                        {
                            USHORT copyLen = mappedName->Length / sizeof(WCHAR);
                            if (copyLen >= 260) copyLen = 259;
                            RtlCopyMemory(entries[0].FullPath, mappedName->Buffer, copyLen * sizeof(WCHAR));
                            entries[0].FullPath[copyLen] = L'\0';
                            gotName = TRUE;
                        }
                    }
                    ZwClose(hProc);
                }
            }

            // 回退: 通过 SeLocateProcessImageName 从 EPROCESS 获取映像路径
            if (!gotName)
            {
                PUNICODE_STRING imageName = NULL;
                NTSTATUS imgStatus = SeLocateProcessImageName(Context->TargetProcess, &imageName);
                if (NT_SUCCESS(imgStatus) && imageName && imageName->Length > 0)
                {
                    USHORT copyLen = imageName->Length / sizeof(WCHAR);
                    if (copyLen >= 260) copyLen = 259;
                    RtlCopyMemory(entries[0].FullPath, imageName->Buffer, copyLen * sizeof(WCHAR));
                    entries[0].FullPath[copyLen] = L'\0';
                    gotName = TRUE;
                    DBG_PRINT("EnumModules: got EXE name via SeLocateProcessImageName: %wZ", imageName);
                }
                if (imageName)
                    ExFreePool(imageName);
            }

            count++;
            DBG_PRINT("EnumModules: added main EXE base=0x%llX size=0x%X", imageBase, entries[0].Size);
        }
    }

    *ModuleCount = count;
    *TotalSize = count * sizeof(DUMPER_MODULE_ENTRY);

    DBG_PRINT("EnumModules: found %u modules", count);

    return STATUS_SUCCESS;
}

#pragma once

//
// ModuleEnum.h - 进程模块枚举
//

#include "Globals.h"

// 枚举目标进程加载的模块 (扫描 MEM_IMAGE 区域)
NTSTATUS HandleEnumModules(
    _In_ PDUMPER_DEVICE_CONTEXT Context,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ModuleCount,
    _Out_ PULONG TotalSize
);

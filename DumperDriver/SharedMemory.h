#pragma once

//
// SharedMemory.h - 共享内存管理
//

#include "Globals.h"

// 初始化共享内存 (分配非分页池、创建 MDL、映射用户态、创建同步事件)
NTSTATUS InitSharedMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context
);

// 清理共享内存及相关资源
VOID CleanupSharedMemory(
    _In_ PDUMPER_DEVICE_CONTEXT Context
);

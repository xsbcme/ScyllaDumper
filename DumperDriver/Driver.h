#pragma once

//
// Driver.h - 内核驱动主头文件 (Master Include)
//
// 所有 .c 文件统一包含此文件，由此汇聚各功能模块的声明。
// 兼容 KDMapper: DriverEntry 检测 DriverObject==NULL 以区分加载方式。
//

// ---- 基础设施 ----
#include "Globals.h"        // 全局上下文、结构体、未导出 NT API 声明 (包含 ntifs.h/ntddk.h/Debug.h)

// ---- 功能模块 ----
#include "SharedMemory.h"   // 共享内存管理
#include "Worker.h"         // 工作线程
#include "ProcessOps.h"     // 进程操作
#include "MemoryOps.h"      // 内存操作
#include "ModuleEnum.h"     // 模块枚举

// ============================================================================
// 驱动框架函数声明 (Driver.c)
// ============================================================================

DRIVER_INITIALIZE DriverEntry;

// 清理所有资源 (可从工作线程或 DriverUnload 调用)
VOID DriverCleanup(VOID);

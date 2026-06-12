#pragma once

//
// Debug.h - 调试日志宏
//
// 使用 DbgPrintEx 输出日志，Release 构建自动编译移除。
// 日志级别: PRINT(Info) / WARN(Warning) / ERROR(Error)
//

#include <ntddk.h>

#define KERNEL_DUMPER_TAG 'virD'  // 'Driv' reversed

#define DUMPER_LOG_PREFIX "[DumperDriver] "

// Debug 构建启用日志，Release 构建编译移除
#if DBG
#define DBG_PRINT(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DUMPER_LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define DBG_ERROR(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DUMPER_LOG_PREFIX "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define DBG_WARN(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DUMPER_LOG_PREFIX "[WARN] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...) ((void)0)
#define DBG_ERROR(fmt, ...) ((void)0)
#define DBG_WARN(fmt, ...)  ((void)0)
#endif

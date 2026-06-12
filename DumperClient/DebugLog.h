#pragma once

//
// DebugLog.h - 客户端调试日志控制
//
// 使用: DBG_LOG(L"格式字符串", 参数...);
// 控制: g_DebugMode 为 true 时输出，false 时静默
//

#include <cstdio>

extern bool g_DebugMode;

#define DBG_LOG(fmt, ...) \
    do { if (g_DebugMode) wprintf(fmt, ##__VA_ARGS__); } while(0)

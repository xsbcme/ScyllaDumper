#pragma once

//
// Worker.h - 工作线程
//

#include "Globals.h"

// 工作线程入口: 等待用户态请求并分发给对应的命令处理函数
VOID WorkerThreadRoutine(
    _In_ PVOID StartContext
);

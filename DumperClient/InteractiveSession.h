#pragma once

//
// InteractiveSession.h - 交互式会话模式
//

#include "DumperClient.h"

// 运行交互式会话
// initialPid: 0 = 无初始附加, >0 = 自动附加指定进程
int RunInteractiveSession(DumperClient& client, DWORD initialPid);

// 尝试加载驱动并重新建立连接 (供会话内 loaddriver 命令调用)
// driverPath: .sys 文件路径
// 成功将通过 client.Connect() 建立连接，返回 true
bool SessionLoadDriver(DumperClient& client, const wchar_t* driverPath);

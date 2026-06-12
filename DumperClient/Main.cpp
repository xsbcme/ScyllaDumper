//
// Main.cpp - ScyllaDumper 客户端入口
//
// 启动后直接进入交互式会话。
// 支持可选参数:
//   DumperClient.exe [--debug] [PID]
//     --debug / -d : 启用调试日志
//     PID          : 启动时直接附加该进程
//

#include <cstdio>
#include <cstdlib>
#include <locale.h>
#include <array>
#include <string>
#include "ClientUtils.h"
#include "InteractiveSession.h"
#include "DumperClient.h"
#include "DebugLog.h"
#include "../DumperLoader/DumperLoader.h"

// 调试模式全局开关 (--debug 参数启用)
bool g_DebugMode = false;

// ============================================================================
// 连接驱动辅助
// ============================================================================

static bool ConnectDriverOptional(DumperClient& client)
{
    if (!client.Connect())
    {
        wprintf(L"[!] 驱动未加载，将使用用户层 API\n");
        return false;
    }
    wprintf(L"[+] 驱动连接成功 (使用驱动层 API)\n");
    return true;
}

// 如果驱动未连接，询问用户是否加载内置驱动，成功后重连
static bool TryPromptLoadEmbeddedDriver(DumperClient& client)
{
    wprintf(L"[?] 是否立即加载内置驱动? [Y/N] ");
    fflush(stdout);

    wint_t ch = getwchar();
    wint_t c;
    while ((c = getwchar()) != L'\n' && c != WEOF); // 清空输入行

    if (ch != L'y' && ch != L'Y')
    {
        wprintf(L"[*] 跳过驱动加载，使用用户层 API\n");
        return false;
    }

    wprintf(L"[*] 正在加载内置驱动...\n");
    if (!DumperLoader::LoadEmbeddedDriver())
    {
        wprintf(L"[-] 内置驱动加载失败，使用用户层 API\n");
        return false;
    }

    if (!client.Connect())
    {
        wprintf(L"[-] 驱动已加载但连接失败，使用用户层 API\n");
        return false;
    }

    wprintf(L"[+] 驱动加载并连接成功\n");
    return true;
}

// ============================================================================
// 入口
// ============================================================================

int wmain(int argc, wchar_t* argv[])
{
    // 设置控制台输出支持中文
    _wsetlocale(LC_ALL, L"");
    SetConsoleOutputCP(CP_UTF8);

    wprintf(L"=== ScyllaDumper - 内核转存工具 ===\n");
    PrintAuthorInfo();
    wprintf(L"\n");

    // 解析 --debug / -d 参数 (可在任意位置)
    int effectiveArgc = 0;
    std::array<wchar_t*, 64> effectiveArgv = {};
    for (int i = 0; i < argc && i < static_cast<int>(effectiveArgv.size()); i++)
    {
        if (_wcsicmp(argv[i], L"--debug") == 0 || _wcsicmp(argv[i], L"-d") == 0)
        {
            g_DebugMode = true;
        }
        else
        {
            effectiveArgv[effectiveArgc++] = argv[i];
        }
    }
    argc = effectiveArgc;
    argv = effectiveArgv.data();

    if (g_DebugMode)
        wprintf(L"[调试模式已启用]\n\n");

    // 解析可选初始 PID (第一个纯数字参数)
    DWORD initialPid = 0;
    if (argc >= 2 && IsNumericArg(argv[1]))
    {
        initialPid = wcstoul(argv[1], NULL, 0);
    }

    // 尝试连接驱动 (可选)；未连接则提示用户是否加载内置驱动
    DumperClient client;
    bool driverConnected = ConnectDriverOptional(client);
    if (!driverConnected)
    {
        driverConnected = TryPromptLoadEmbeddedDriver(client);
    }
    wprintf(L"[*] 当前模式: %s\n\n",
            driverConnected ? L"驱动层 API" : L"用户层 API (回退)");

    int result = RunInteractiveSession(client, initialPid);
    client.Disconnect();
    return result;
}
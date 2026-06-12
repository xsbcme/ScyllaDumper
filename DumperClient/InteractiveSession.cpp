//
// InteractiveSession.cpp - 交互式会话模式
//
// 包含会话状态管理、交互命令处理和命令主循环
//

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include "InteractiveSession.h"
#include "ClientUtils.h"
#include "DumperClient.h"
#include "PeParser.h"
#include "DebugLog.h"
#include "ImportResolver.h"
#include "ImportRebuilder.h"
#include "IATSearch.h"
#include "PeRebuild.h"
#include "../DumperLoader/DumperLoader.h"

// ============================================================================
// 会话状态
// ============================================================================

struct SessionState
{
    DumperClient*       client;
    DWORD               pid;
    bool                attached;          // 是否已附加到进程
    std::vector<DumperModuleInfo> modules;
    std::wstring        processName;       // 主模块文件名 (不含扩展名)
    DWORD_PTR           moduleBase;        // 主模块基址
    DWORD               moduleSize;

    // OEP
    DWORD_PTR           oep;               // OEP RVA
    DWORD_PTR           imageBase;
    bool                isTarget64;        // 目标进程是否64位

    // IAT搜索结果
    bool                iatFound;
    IATSearchResult     iatResult;

    // 导入解析
    ImportResolver*     resolver;
    bool                importsResolved;

    // 最后转存文件路径
    std::wstring        lastDumpPath;
};

// ============================================================================
// 帮助
// ============================================================================

static void PrintSessionHelp()
{
    wprintf(L"\n说明: 启动时已尝试连接驱动。已连接则优先内核 API; 未连接则回退用户态 (部分能力受限)。\n");
    wprintf(L"\n命令:\n");
    wprintf(L"  loaddriver [路径]      加载驱动并连接 (不带路径则加载内置驱动)\n");
    wprintf(L"  ps [关键字] [-n 条数]  进程列表 (有驱动则内核枚举, 否则 Toolhelp)\n");
    wprintf(L"  attach <PID>            附加到目标进程\n");
    wprintf(L"  detach                  脱离当前进程\n");
    wprintf(L"  dump [文件]             转存主模块 (默认: <进程名>_dump_YYYYMMDD_HHMMSS.exe)\n");
    wprintf(L"  dumpmod <模块名> [文件] 转存指定模块\n");
    wprintf(L"  dumpmem <地址> <大小> [文件] 转存指定内存区域 (当前附加进程)\n");
    wprintf(L"  iatsearch               自动搜索IAT\n");
    wprintf(L"  getimports              解析导入表 (需先 iatsearch)\n");
    wprintf(L"  fixdump [文件]          转存并修复导入表 (默认: <进程名>_SCY_YYYYMMDD_HHMMSS.exe)\n");
    wprintf(L"  perebuild <文件>        重建 PE 节对齐\n");
    wprintf(L"  list                    列出模块\n");
    wprintf(L"  threads                 列出线程 (有驱动时内核枚举)\n");
    wprintf(L"  context <TID>           线程寄存器 (有驱动时内核取上下文)\n");
    wprintf(L"  info                    进程信息 PEB/ImageBase 等 (有驱动时内核查询)\n");
    wprintf(L"  oep [地址]              查看/设置 OEP\n");
    wprintf(L"  query <地址>            查询内存信息\n");
    wprintf(L"  help                    显示帮助\n");
    wprintf(L"  debug                   切换调试日志\n");
    wprintf(L"  quit                    退出会话\n");
    wprintf(L"  shutdown                关闭驱动并退出 (需已加载驱动)\n");
    wprintf(L"\n");
}

static std::wstring BuildTimestampSuffix()
{
    SYSTEMTIME st = {};
    GetLocalTime(&st);

    wchar_t ts[32] = {};
    swprintf_s(ts,
               L"_%04u%02u%02u_%02u%02u%02u",
               st.wYear,
               st.wMonth,
               st.wDay,
               st.wHour,
               st.wMinute,
               st.wSecond);
    return ts;
}

static std::wstring BuildTimestampedFileName(
    const std::wstring& prefix,
    const wchar_t* label,
    const wchar_t* extension)
{
    return prefix + label + BuildTimestampSuffix() + extension;
}

// ============================================================================
// 会话命令处理
// ============================================================================

static void CmdDump(SessionState& s, const std::vector<std::wstring>& args)
{
    // dump [输出文件]
    std::wstring outputPath;
    if (args.size() >= 2)
    {
        outputPath = args[1];
    }
    else
    {
        outputPath = BuildTimestampedFileName(s.processName, L"_dump", L".exe");
    }

    PeParser pe(s.client, s.moduleBase);
    if (!pe.IsValid())
    {
        wprintf(L"[-] 无法解析PE头\n");
        return;
    }

    wprintf(L"[*] 转存模块: 基址=0x%llX, SizeOfImage=0x%X\n",
            (unsigned long long)s.moduleBase, pe.GetSizeOfImage());

    if (pe.DumpProcess(s.moduleBase, s.oep, outputPath.c_str()))
    {
        s.lastDumpPath = outputPath;
        wprintf(L"[+] 已保存: %s\n", outputPath.c_str());
    }
    else
    {
        wprintf(L"[-] 转存失败\n");
    }
}

static void CmdDumpMod(SessionState& s, const std::vector<std::wstring>& args)
{
    if (args.size() < 2)
    {
        wprintf(L"用法: dumpmod <模块名> [输出文件]\n");
        return;
    }

    const wchar_t* moduleName = args[1].c_str();

    // 查找模块
    const DumperModuleInfo* target = nullptr;
    for (const auto& mod : s.modules)
    {
        std::wstring fname = GetFileName(mod.FullPath);
        if (_wcsicmp(fname.c_str(), moduleName) == 0)
        {
            target = &mod;
            break;
        }
    }

    if (!target)
    {
        wprintf(L"[-] 未找到模块: %s\n", moduleName);
        return;
    }

    std::wstring outputPath;
    if (args.size() >= 3)
    {
        outputPath = args[2];
    }
    else
    {
        outputPath = BuildTimestampedFileName(
            GetFileNameWithoutExt(target->FullPath), L"_dump", L".dll");
    }

    PeParser pe(s.client, target->BaseAddress);
    if (!pe.IsValid())
    {
        wprintf(L"[-] 无法解析PE头\n");
        return;
    }

    if (pe.DumpProcess(target->BaseAddress, pe.GetEntryPoint(), outputPath.c_str()))
    {
        wprintf(L"[+] 已保存: %s\n", outputPath.c_str());
    }
}

static void CmdDumpMem(SessionState& s, const std::vector<std::wstring>& args)
{
    // dumpmem <地址> <大小> [输出文件]  — 针对当前已附加进程
    if (args.size() < 3)
    {
        wprintf(L"用法: dumpmem <地址> <大小> [输出文件]\n");
        return;
    }

    DWORD_PTR address = (DWORD_PTR)wcstoull(args[1].c_str(), nullptr, 0);
    SIZE_T    size = (SIZE_T)wcstoull(args[2].c_str(), nullptr, 0);
    if (size == 0)
    {
        wprintf(L"[-] 大小无效\n");
        return;
    }

    std::wstring outputPath;
    if (args.size() >= 4)
    {
        outputPath = args[3];
    }
    else
    {
        std::wstring timestamp = BuildTimestampSuffix();
        wchar_t buf[192];
        swprintf_s(buf, L"dumpmem_%u_0x%llX%s.bin",
                   s.pid, (unsigned long long)address, timestamp.c_str());
        outputPath = buf;
    }

    DumpMemoryRegion(*s.client, address, size, outputPath.c_str());
}

static void CmdIATSearch(SessionState& s, const std::vector<std::wstring>& /*args*/)
{
    if (!s.resolver)
    {
        // 自动初始化导出表缓存
        s.resolver = new ImportResolver(s.client);
        if (!s.resolver->Initialize(s.modules))
        {
            wprintf(L"[-] 初始化导出表缓存失败\n");
            return;
        }
    }

    IATSearch search(s.client, s.resolver);
    if (search.SearchIAT(s.moduleBase, s.moduleSize, s.iatResult))
    {
        s.iatFound = true;
        wprintf(L"[+] IAT: VA=0x%llX, RVA=0x%X, 大小=0x%X (%u 字节)\n",
                (unsigned long long)s.iatResult.iatAddress,
                s.iatResult.iatRva,
                s.iatResult.iatSize,
                s.iatResult.iatSize);
    }
    else
    {
        wprintf(L"[-] 未找到IAT, 可手动指定: iatsearch 不可用时请参考PE头\n");
    }
}

static void CmdGetImports(SessionState& s, const std::vector<std::wstring>& /*args*/)
{
    if (!s.iatFound)
    {
        wprintf(L"[-] 请先执行 iatsearch\n");
        return;
    }

    if (!s.resolver)
    {
        s.resolver = new ImportResolver(s.client);
        if (!s.resolver->Initialize(s.modules))
        {
            wprintf(L"[-] 初始化导出表缓存失败\n");
            return;
        }
    }

    if (s.resolver->ReadAndParseIAT(s.iatResult.iatAddress,
                                     s.iatResult.iatSize,
                                     s.moduleBase,
                                     s.isTarget64))
    {
        s.importsResolved = true;
        s.resolver->PrintImports();
    }
    else
    {
        wprintf(L"[-] 导入表解析失败\n");
    }
}

static void CmdFixDump(SessionState& s, const std::vector<std::wstring>& args)
{
    // fixdump [输出文件]
    // 流程: dump → iatsearch → getimports → rebuild imports

    std::wstring outputPath;
    if (args.size() >= 2)
    {
        outputPath = args[1];
    }
    else
    {
        outputPath = BuildTimestampedFileName(s.processName, L"_SCY", L".exe");
    }

    // Step 1: 转存
    wprintf(L"\n[步骤 1/4] 转存进程...\n");
    PeParser pe(s.client, s.moduleBase);
    if (!pe.IsValid())
    {
        wprintf(L"[-] 无法解析PE头\n");
        return;
    }

    if (!pe.DumpProcess(s.moduleBase, s.oep, outputPath.c_str()))
    {
        wprintf(L"[-] 转存失败\n");
        return;
    }
    s.lastDumpPath = outputPath;
    wprintf(L"[+] 转存完成: %s\n", outputPath.c_str());

    // Step 2: IAT搜索 (如果还没做)
    if (!s.iatFound)
    {
        wprintf(L"\n[步骤 2/4] 搜索IAT...\n");
        if (!s.resolver)
        {
            s.resolver = new ImportResolver(s.client);
            if (!s.resolver->Initialize(s.modules))
            {
                wprintf(L"[-] 初始化失败\n");
                return;
            }
        }

        IATSearch search(s.client, s.resolver);
        if (!search.SearchIAT(s.moduleBase, s.moduleSize, s.iatResult))
        {
            wprintf(L"[-] IAT搜索失败\n");
            return;
        }
        s.iatFound = true;
    }
    else
    {
        wprintf(L"\n[步骤 2/4] 使用已有IAT: RVA=0x%X, 大小=0x%X\n",
                s.iatResult.iatRva, s.iatResult.iatSize);
    }

    // Step 3: 解析导入表 (如果还没做)
    if (!s.importsResolved)
    {
        wprintf(L"\n[步骤 3/4] 解析导入表...\n");
        if (!s.resolver)
        {
            s.resolver = new ImportResolver(s.client);
            s.resolver->Initialize(s.modules);
        }

        if (!s.resolver->ReadAndParseIAT(s.iatResult.iatAddress,
                                          s.iatResult.iatSize,
                                          s.moduleBase,
                                          s.isTarget64))
        {
            wprintf(L"[-] 导入表解析失败\n");
            return;
        }
        s.importsResolved = true;
    }
    else
    {
        wprintf(L"\n[步骤 3/4] 使用已解析的导入表 (%u 个函数)\n",
                s.resolver->GetTotalFunctions());
    }

    // Step 4: 重建导入表
    wprintf(L"\n[步骤 4/4] 重建导入表...\n");
    ImportRebuilder rebuilder;
    if (rebuilder.RebuildImportTable(outputPath.c_str(),
                                     s.resolver->GetImports(),
                                     s.iatResult.iatRva,
                                     s.iatResult.iatSize))
    {
        wprintf(L"\n[+] Fix Dump 完成: %s\n", outputPath.c_str());
        wprintf(L"    导入: %u 个函数, %zu 个DLL\n",
                s.resolver->GetResolvedFunctions(),
                s.resolver->GetImports().size());
    }
    else
    {
        wprintf(L"[-] 导入表重建失败\n");
    }
}

static void CmdPeRebuild(SessionState& s, const std::vector<std::wstring>& args)
{
    std::wstring filePath;
    if (args.size() >= 2)
    {
        filePath = args[1];
    }
    else if (!s.lastDumpPath.empty())
    {
        filePath = s.lastDumpPath;
    }
    else
    {
        wprintf(L"用法: perebuild <文件>\n");
        return;
    }

    PeRebuild rebuild;
    rebuild.Rebuild(filePath.c_str());
}

static void CmdOEP(SessionState& s, const std::vector<std::wstring>& args)
{
    if (args.size() >= 2)
    {
        // 设置OEP
        s.oep = (DWORD_PTR)wcstoull(args[1].c_str(), NULL, 0);
        wprintf(L"[*] OEP 设为: 0x%llX (VA: 0x%llX)\n",
                (unsigned long long)s.oep,
                (unsigned long long)(s.moduleBase + s.oep));
    }
    else
    {
        wprintf(L"[*] 当前OEP: 0x%llX (VA: 0x%llX)\n",
                (unsigned long long)s.oep,
                (unsigned long long)(s.moduleBase + s.oep));
    }
}

// ============================================================================
// 清理会话状态 (用于 detach 或 attach 前重置)
// ============================================================================

static void ResetSessionState(SessionState& state)
{
    delete state.resolver;
    state.resolver = nullptr;
    state.modules.clear();
    state.processName.clear();
    state.moduleBase = 0;
    state.moduleSize = 0;
    state.oep = 0;
    state.imageBase = 0;
    state.isTarget64 = true;
    state.iatFound = false;
    state.iatResult = {};
    state.importsResolved = false;
    state.lastDumpPath.clear();
    state.pid = 0;
    state.attached = false;
}

// ============================================================================
// 附加到进程 (设置会话状态)
// ============================================================================

static bool AttachToProcess(SessionState& state, DumperClient& client, DWORD pid)
{
    // 如果已附加, 先脱离
    if (state.attached)
    {
        client.CloseProcess();
        ResetSessionState(state);
    }

    wprintf(L"[*] 打开进程 PID: %u\n", pid);
    if (!client.OpenProcess(pid))
    {
        wprintf(L"[-] 打开进程失败, NTSTATUS: 0x%08X\n", client.GetLastNtStatus());
        return false;
    }

    state.client = &client;
    state.pid = pid;
    state.attached = true;

    // 枚举模块
    if (!client.EnumModules(state.modules) || state.modules.empty())
    {
        wprintf(L"[-] 枚举模块失败\n");
        client.CloseProcess();
        ResetSessionState(state);
        return false;
    }

    state.isTarget64 = true;

    // 通过驱动层获取进程信息
    DumperProcessInfo procInfo = {};
    bool gotProcInfo = client.GetProcessInfo(procInfo);

    // 确定主模块
    int mainModuleIdx = -1;
    if (gotProcInfo && procInfo.ImageBase != 0)
    {
        for (int i = 0; i < (int)state.modules.size(); i++)
        {
            if (state.modules[i].BaseAddress == (DWORD_PTR)procInfo.ImageBase)
            {
                mainModuleIdx = i;
            }
        }
    }
    if (mainModuleIdx < 0)
    {
        mainModuleIdx = 0;
    }

    state.moduleBase = state.modules[mainModuleIdx].BaseAddress;
    state.moduleSize = state.modules[mainModuleIdx].Size;
    state.processName = GetFileNameWithoutExt(state.modules[mainModuleIdx].FullPath);

    if (gotProcInfo)
    {
        state.imageBase = procInfo.ImageBase;
        state.isTarget64 = !procInfo.IsWow64;
        if (procInfo.EntryPoint > state.moduleBase)
            state.oep = procInfo.EntryPoint - state.moduleBase;
        else
            state.oep = procInfo.EntryPoint;
    }
    else
    {
        PeParser pe(&client, state.moduleBase);
        if (pe.IsValid())
        {
            state.oep = pe.GetEntryPoint();
            state.imageBase = pe.GetImageBase();
            state.isTarget64 = pe.Is64Bit();
        }
    }

    // 显示信息
    wprintf(L"\n");
    wprintf(L"  进程:     %s (PID: %u) [%s]\n",
            GetFileName(state.modules[mainModuleIdx].FullPath).c_str(), pid,
            state.isTarget64 ? L"64-bit" : L"32-bit");
    wprintf(L"  基址:     0x%016llX\n", (unsigned long long)state.moduleBase);
    wprintf(L"  ImageBase: 0x%llX\n", (unsigned long long)state.imageBase);
    wprintf(L"  OEP:      0x%llX (VA: 0x%llX)\n",
            (unsigned long long)state.oep,
            (unsigned long long)(state.moduleBase + state.oep));
    if (procInfo.PebAddress)
    {
        wprintf(L"  PEB:      0x%llX\n", (unsigned long long)procInfo.PebAddress);
    }
    wprintf(L"  模块数:   %zu\n", state.modules.size());

    return true;
}

// ============================================================================
// 加载驱动辅助 (供 loaddriver 命令和外部调用)
// ============================================================================

bool SessionLoadDriver(DumperClient& client, const wchar_t* driverPath)
{
    // 1. 如果已经连接，说明驱动已加载
    if (client.IsConnected())
    {
        wprintf(L"[*] 驱动已加载并连接，无需重复加载\n");
        return true;
    }

    // 2. 尝试直接连接 (驱动可能已加载但尚未连接)
    if (client.Connect())
    {
        wprintf(L"[+] 驱动已加载，连接成功\n");
        return true;
    }

    // 3. 驱动未加载，决定加载来源
    bool loaded = false;
    if (!driverPath || driverPath[0] == L'\0')
    {
        // 无路径参数 → 加载内置驱动
        wprintf(L"[*] 正在加载内置驱动...\n");
        loaded = DumperLoader::LoadEmbeddedDriver();
    }
    else
    {
        // 指定路径 → 从文件加载
        wprintf(L"[*] 正在加载驱动: %s\n", driverPath);
        loaded = DumperLoader::LoadDriver(driverPath);
    }

    if (!loaded)
    {
        wprintf(L"[-] 驱动加载失败，继续使用用户层 API\n");
        return false;
    }

    // 4. 加载成功，建立连接
    wprintf(L"[+] 驱动加载成功，正在连接...\n");
    Sleep(500);
    if (!client.Connect())
    {
        wprintf(L"[-] 驱动已映射但无法连接共享内存，可能初始化未完成\n");
        return false;
    }

    wprintf(L"[+] 驱动连接成功，已切换到驱动层 API\n");
    return true;
}

// ============================================================================
// 交互式会话主循环
// ============================================================================

int RunInteractiveSession(DumperClient& client, DWORD initialPid)
{
    SessionState state = {};
    state.client = &client;

    // 如果指定了初始 PID, 自动附加
    if (initialPid != 0)
    {
        if (!AttachToProcess(state, client, initialPid))
        {
            return 1;
        }
    }
    else
    {
        wprintf(L"\n[*] 交互式会话已启动 (未附加进程)\n");
        wprintf(L"[*] 使用 ps 查询进程, attach <PID> 附加目标进程\n");
    }

    wprintf(L"\n输入 help 查看命令列表\n");

    // 命令循环
    wchar_t lineBuffer[1024];

    while (true)
    {
        // 动态提示符: 显示当前进程
        if (state.attached)
            wprintf(L"\nScyllaDumper[%s:%u]> ", state.processName.c_str(), state.pid);
        else
            wprintf(L"\nScyllaDumper> ");
        fflush(stdout);

        if (!fgetws(lineBuffer, _countof(lineBuffer), stdin))
            break;

        // 去除换行
        size_t len = wcslen(lineBuffer);
        while (len > 0 && (lineBuffer[len - 1] == L'\n' || lineBuffer[len - 1] == L'\r'))
            lineBuffer[--len] = L'\0';

        if (len == 0)
            continue;

        auto tokens = TokenizeLine(lineBuffer);
        if (tokens.empty())
            continue;

        const std::wstring& cmd = tokens[0];

        // ---- 不需要附加进程的命令 ----

        if (_wcsicmp(cmd.c_str(), L"quit") == 0 || _wcsicmp(cmd.c_str(), L"exit") == 0)
        {
            break;
        }
        else if (_wcsicmp(cmd.c_str(), L"help") == 0 || cmd == L"?")
        {
            PrintSessionHelp();
        }
        else if (_wcsicmp(cmd.c_str(), L"loaddriver") == 0)
        {
            const wchar_t* path = tokens.size() >= 2 ? tokens[1].c_str() : L"";
            SessionLoadDriver(client, path);
        }
        else if (_wcsicmp(cmd.c_str(), L"ps") == 0)
        {
            CmdProcessSearch(client, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"attach") == 0)
        {
            if (tokens.size() < 2)
            {
                wprintf(L"用法: attach <PID>\n");
            }
            else
            {
                DWORD newPid = wcstoul(tokens[1].c_str(), NULL, 0);
                if (newPid == 0)
                {
                    wprintf(L"[-] 无效的 PID\n");
                }
                else
                {
                    AttachToProcess(state, client, newPid);
                }
            }
        }
        else if (_wcsicmp(cmd.c_str(), L"detach") == 0)
        {
            if (!state.attached)
            {
                wprintf(L"[-] 当前未附加任何进程\n");
            }
            else
            {
                wprintf(L"[*] 正在脱离进程 %s (PID: %u)...\n",
                        state.processName.c_str(), state.pid);
                client.CloseProcess();
                ResetSessionState(state);
                wprintf(L"[+] 已脱离\n");
            }
        }
        else if (_wcsicmp(cmd.c_str(), L"shutdown") == 0)
        {
            wprintf(L"[*] 正在通知驱动关闭...\n");
            client.Shutdown();
            wprintf(L"[*] 驱动已关闭\n");
            break;
        }
        else if (_wcsicmp(cmd.c_str(), L"debug") == 0)
        {
            g_DebugMode = !g_DebugMode;
            wprintf(L"[*] 调试模式: %s\n", g_DebugMode ? L"开" : L"关");
        }

        // ---- 需要附加进程的命令 ----

        else if (!state.attached)
        {
            wprintf(L"[-] 未附加进程。使用 ps 查询进程, attach <PID> 附加\n");
        }
        else if (_wcsicmp(cmd.c_str(), L"dump") == 0)
        {
            CmdDump(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"dumpmod") == 0)
        {
            CmdDumpMod(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"dumpmem") == 0)
        {
            CmdDumpMem(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"iatsearch") == 0)
        {
            CmdIATSearch(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"getimports") == 0)
        {
            CmdGetImports(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"fixdump") == 0)
        {
            CmdFixDump(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"perebuild") == 0)
        {
            CmdPeRebuild(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"list") == 0)
        {
            ListModules(client);
        }
        else if (_wcsicmp(cmd.c_str(), L"threads") == 0)
        {
            std::vector<DumperThreadInfo> threads;
            if (client.EnumThreads(threads))
            {
                wprintf(L"[+] 找到 %zu 个线程:\n\n", threads.size());
                wprintf(L"  %-8s  %-18s  %-8s  %-6s  %s\n",
                        L"TID", L"起始地址", L"状态", L"优先级", L"等待原因");
                wprintf(L"  %-8s  %-18s  %-8s  %-6s  %s\n",
                        L"--------", L"------------------", L"--------", L"------", L"--------");

                static const wchar_t* threadStates[] = {
                    L"Init", L"Ready", L"Running", L"Standby",
                    L"Term", L"Waiting", L"Trans", L"DeferReady"
                };

                for (const auto& t : threads)
                {
                    const wchar_t* stateStr = (t.State < 8) ? threadStates[t.State] : L"???";
                    wprintf(L"  %-8u  0x%016llX  %-8s  %-6d  %u\n",
                            t.ThreadId,
                            (unsigned long long)t.StartAddress,
                            stateStr,
                            t.Priority,
                            t.WaitReason);
                }
            }
            else
            {
                wprintf(L"[-] 枚举线程失败, NTSTATUS: 0x%08X\n", client.GetLastNtStatus());
            }
        }
        else if (_wcsicmp(cmd.c_str(), L"context") == 0)
        {
            if (tokens.size() < 2)
            {
                wprintf(L"用法: context <TID>\n");
            }
            else
            {
                DWORD tid = wcstoul(tokens[1].c_str(), NULL, 0);
                DumperThreadContext ctx = {};
                if (client.GetThreadContext(tid, ctx))
                {
                    wprintf(L"[+] 线程 %u 寄存器:\n", tid);
                    wprintf(L"  RIP = 0x%016llX    RSP = 0x%016llX\n",
                            (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rsp);
                    wprintf(L"  RAX = 0x%016llX    RBX = 0x%016llX\n",
                            (unsigned long long)ctx.Rax, (unsigned long long)ctx.Rbx);
                    wprintf(L"  RCX = 0x%016llX    RDX = 0x%016llX\n",
                            (unsigned long long)ctx.Rcx, (unsigned long long)ctx.Rdx);
                    wprintf(L"  RSI = 0x%016llX    RDI = 0x%016llX\n",
                            (unsigned long long)ctx.Rsi, (unsigned long long)ctx.Rdi);
                    wprintf(L"  RBP = 0x%016llX    R8  = 0x%016llX\n",
                            (unsigned long long)ctx.Rbp, (unsigned long long)ctx.R8);
                    wprintf(L"  R9  = 0x%016llX    R10 = 0x%016llX\n",
                            (unsigned long long)ctx.R9, (unsigned long long)ctx.R10);
                    wprintf(L"  R11 = 0x%016llX    R12 = 0x%016llX\n",
                            (unsigned long long)ctx.R11, (unsigned long long)ctx.R12);
                    wprintf(L"  R13 = 0x%016llX    R14 = 0x%016llX\n",
                            (unsigned long long)ctx.R13, (unsigned long long)ctx.R14);
                    wprintf(L"  R15 = 0x%016llX    EFlags = 0x%08X\n",
                            (unsigned long long)ctx.R15, ctx.EFlags);

                    if (ctx.Rip >= state.moduleBase &&
                        ctx.Rip < state.moduleBase + state.moduleSize)
                    {
                        DWORD_PTR rva = ctx.Rip - state.moduleBase;
                        wprintf(L"\n  [提示] RIP 在主模块内, RVA=0x%llX\n",
                                (unsigned long long)rva);
                        wprintf(L"  使用 'oep 0x%llX' 设为 OEP\n",
                                (unsigned long long)rva);
                    }
                }
                else
                {
                    wprintf(L"[-] 获取线程上下文失败, NTSTATUS: 0x%08X\n",
                            client.GetLastNtStatus());
                }
            }
        }
        else if (_wcsicmp(cmd.c_str(), L"info") == 0)
        {
            DumperProcessInfo pInfo = {};
            if (client.GetProcessInfo(pInfo))
            {
                wprintf(L"[+] 进程信息 (驱动层获取):\n");
                wprintf(L"  PEB:        0x%016llX\n", (unsigned long long)pInfo.PebAddress);
                wprintf(L"  ImageBase:  0x%016llX\n", (unsigned long long)pInfo.ImageBase);
                wprintf(L"  EntryPoint: 0x%016llX", (unsigned long long)pInfo.EntryPoint);
                if (pInfo.EntryPoint > pInfo.ImageBase)
                    wprintf(L" (RVA: 0x%llX)",
                            (unsigned long long)(pInfo.EntryPoint - pInfo.ImageBase));
                wprintf(L"\n");
                wprintf(L"  WoW64:      %s\n", pInfo.IsWow64 ? L"是 (32位进程)" : L"否 (64位进程)");
            }
            else
            {
                wprintf(L"[-] 获取进程信息失败, NTSTATUS: 0x%08X\n",
                        client.GetLastNtStatus());
            }
        }
        else if (_wcsicmp(cmd.c_str(), L"oep") == 0)
        {
            CmdOEP(state, tokens);
        }
        else if (_wcsicmp(cmd.c_str(), L"query") == 0)
        {
            if (tokens.size() < 2)
            {
                wprintf(L"用法: query <地址>\n");
            }
            else
            {
                DWORD_PTR addr = (DWORD_PTR)wcstoull(tokens[1].c_str(), NULL, 0);
                QueryMemoryInfo(client, addr);
            }
        }
        else
        {
            wprintf(L"[-] 未知命令: %s (输入 help 查看帮助)\n", cmd.c_str());
        }
    }

    // 清理
    delete state.resolver;
    if (state.attached)
        client.CloseProcess();
    return 0;
}

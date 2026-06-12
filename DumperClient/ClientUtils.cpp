//
// ClientUtils.cpp - 共享工具函数与通用操作
//

#include <cstdio>
#include <cstdlib>
#include <conio.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include "ClientUtils.h"
#include "DumperClient.h"

// ============================================================================
// 作者信息
// ============================================================================

void PrintAuthorInfo()
{
    wprintf(L"作者: xsbcme\n");
    wprintf(L"邮箱: 2974550071@qq.com\n");
}

// ============================================================================
// 路径工具
// ============================================================================

std::wstring GetFileNameWithoutExt(const std::wstring& path)
{
    const wchar_t* slash = wcsrchr(path.c_str(), L'\\');
    std::wstring name = slash ? (slash + 1) : path;
    size_t dot = name.rfind(L'.');
    if (dot != std::wstring::npos)
        name = name.substr(0, dot);
    return name;
}

std::wstring GetFileName(const std::wstring& path)
{
    const wchar_t* slash = wcsrchr(path.c_str(), L'\\');
    return slash ? (slash + 1) : path;
}

// ============================================================================
// 命令行工具
// ============================================================================

std::vector<std::wstring> TokenizeLine(const wchar_t* line)
{
    std::vector<std::wstring> tokens;
    std::wistringstream ss(line);
    std::wstring token;
    while (ss >> token)
        tokens.push_back(token);
    return tokens;
}

bool IsNumericArg(const wchar_t* arg)
{
    if (!arg || !*arg)
        return false;

    // 支持十进制和十六进制 (0x...)
    const wchar_t* p = arg;
    if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X'))
        p += 2;

    while (*p)
    {
        if (!iswxdigit(*p))
            return false;
        p++;
    }
    return true;
}

bool WcsContainsCaseInsensitive(const std::wstring& haystack, const std::wstring& needle)
{
    if (needle.empty()) return true;
    std::wstring h = haystack, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), towlower);
    std::transform(n.begin(), n.end(), n.begin(), towlower);
    return h.find(n) != std::wstring::npos;
}

int PauseAndExit(int code)
{
    wprintf(L"\n按任意键退出...\n");
    _getwch();
    return code;
}

// ============================================================================
// 通用进程/内存操作
// ============================================================================

bool DumpMemoryRegion(DumperClient& client, DWORD_PTR address, SIZE_T size,
                      const wchar_t* outputPath)
{
    std::vector<BYTE> buffer(size);
    SIZE_T bytesRead = 0;

    wprintf(L"[*] 正在读取内存: 0x%llX, 大小: 0x%llX\n",
            (unsigned long long)address, (unsigned long long)size);

    // Scylla 兼容: 先尝试完整读取，失败再用部分读取
    if (!client.ReadMemory(address, size, buffer.data(), &bytesRead)
        || bytesRead != size)
    {
        // 完整读取失败，重置后尝试部分读取
        memset(buffer.data(), 0, size);
        bytesRead = 0;
        if (!client.ReadMemoryPartial(address, size, buffer.data(), &bytesRead))
        {
            wprintf(L"[-] 读取内存失败, NTSTATUS: 0x%08X\n", client.GetLastNtStatus());
            return false;
        }
    }

    wprintf(L"[+] 成功读取 0x%llX / 0x%llX 字节\n", (unsigned long long)bytesRead, (unsigned long long)size);

    // 写入文件 (写入完整缓冲区，未读取区域保持零填充)
    HANDLE hFile = CreateFileW(
        outputPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] 无法创建输出文件: %s\n", outputPath);
        return false;
    }

    DWORD bytesWritten = 0;
    WriteFile(hFile, buffer.data(), static_cast<DWORD>(size), &bytesWritten, NULL);
    CloseHandle(hFile);

    wprintf(L"[+] 已保存到: %s (%u 字节)\n", outputPath, bytesWritten);
    return true;
}

DWORD GetSizeOfImageFromPE(DumperClient& client, DWORD_PTR baseAddress)
{
    // 读取 DOS 头
    BYTE dosHeader[0x40] = {};
    SIZE_T read = 0;
    if (!client.ReadMemory(baseAddress, sizeof(dosHeader), dosHeader, &read) || read < sizeof(dosHeader))
        return 0;

    // 检查 MZ 签名
    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z')
        return 0;

    LONG e_lfanew = *(LONG*)(dosHeader + 0x3C);
    if (e_lfanew <= 0 || e_lfanew > 0x1000)
        return 0;

    // 读取 PE 头 (PE signature + FileHeader + OptionalHeader 起始)
    BYTE peHeader[0x120] = {};
    if (!client.ReadMemory(baseAddress + e_lfanew, sizeof(peHeader), peHeader, &read) || read < 0x78)
        return 0;

    // 检查 PE 签名
    if (peHeader[0] != 'P' || peHeader[1] != 'E' || peHeader[2] != 0 || peHeader[3] != 0)
        return 0;

    // OptionalHeader 在偏移 24 (PE sig 4 + FileHeader 20)
    WORD magic = *(WORD*)(peHeader + 24);
    DWORD sizeOfImage = 0;

    if (magic == 0x20B)  // PE32+ (64-bit)
        sizeOfImage = *(DWORD*)(peHeader + 24 + 56);  // OptionalHeader64.SizeOfImage
    else if (magic == 0x10B)  // PE32 (32-bit)
        sizeOfImage = *(DWORD*)(peHeader + 24 + 56);  // OptionalHeader32.SizeOfImage

    return sizeOfImage;
}

bool DumpModule(DumperClient& client, DWORD_PTR baseAddress, const wchar_t* outputPath)
{
    DWORD sizeOfImage = GetSizeOfImageFromPE(client, baseAddress);
    if (sizeOfImage == 0)
    {
        wprintf(L"[-] 无法从 PE 头读取 SizeOfImage (基址: 0x%llX)\n",
                (unsigned long long)baseAddress);
        return false;
    }

    wprintf(L"[*] 模块基址: 0x%llX, SizeOfImage: 0x%X (%u KB)\n",
            (unsigned long long)baseAddress, sizeOfImage, sizeOfImage / 1024);

    return DumpMemoryRegion(client, baseAddress, sizeOfImage, outputPath);
}

bool ListModules(DumperClient& client)
{
    std::vector<DumperModuleInfo> modules;

    if (!client.EnumModules(modules))
    {
        wprintf(L"[-] 枚举模块失败, NTSTATUS: 0x%08X\n", client.GetLastNtStatus());
        return false;
    }

    wprintf(L"[+] 找到 %zu 个模块:\n\n", modules.size());
    wprintf(L"  %-18s  %-10s  %s\n", L"基址", L"大小", L"路径");
    wprintf(L"  %-18s  %-10s  %s\n", L"------------------", L"----------", L"----");

    for (const auto& mod : modules)
    {
        wprintf(L"  0x%016llX  0x%08X  %s\n",
                (unsigned long long)mod.BaseAddress,
                mod.Size,
                mod.FullPath.c_str());
    }

    return true;
}

bool QueryMemoryInfo(DumperClient& client, DWORD_PTR address)
{
    DumperMemoryInfo info = {};

    if (!client.QueryMemory(address, info))
    {
        wprintf(L"[-] 查询内存失败, NTSTATUS: 0x%08X\n", client.GetLastNtStatus());
        return false;
    }

    wprintf(L"[+] 内存信息:\n");
    wprintf(L"  基址:         0x%016llX\n", (unsigned long long)info.BaseAddress);
    wprintf(L"  AllocationBase: 0x%016llX\n", (unsigned long long)info.AllocationBase);
    wprintf(L"  区域大小:     0x%llX\n", (unsigned long long)info.RegionSize);

    const wchar_t* stateStr = L"未知";
    if (info.State == MEM_COMMIT)  stateStr = L"MEM_COMMIT";
    if (info.State == MEM_FREE)    stateStr = L"MEM_FREE";
    if (info.State == MEM_RESERVE) stateStr = L"MEM_RESERVE";
    wprintf(L"  状态:         %s (0x%X)\n", stateStr, info.State);

    wprintf(L"  保护:         0x%X\n", info.Protect);

    const wchar_t* typeStr = L"未知";
    if (info.Type == MEM_IMAGE)    typeStr = L"MEM_IMAGE";
    if (info.Type == MEM_MAPPED)   typeStr = L"MEM_MAPPED";
    if (info.Type == MEM_PRIVATE)  typeStr = L"MEM_PRIVATE";
    wprintf(L"  类型:         %s (0x%X)\n", typeStr, info.Type);

    return true;
}

// ============================================================================
// 进程查询命令: ps [关键字] [-n 最大条数]
// ============================================================================

void CmdProcessSearch(DumperClient& client, const std::vector<std::wstring>& args)
{
    std::vector<DumperProcessEntry> processes;
    if (!client.EnumProcesses(processes))
    {
        wprintf(L"[-] 枚举进程失败, NTSTATUS: 0x%08X\n", client.GetLastNtStatus());
        return;
    }

    // 解析参数: ps [关键字] [-n 最大条数]
    std::wstring filter;
    size_t maxDisplay = 0;  // 0 = 不限制

    for (size_t i = 1; i < args.size(); i++)
    {
        if ((_wcsicmp(args[i].c_str(), L"-n") == 0) && i + 1 < args.size())
        {
            maxDisplay = (size_t)wcstoul(args[i + 1].c_str(), NULL, 0);
            i++;  // 跳过数字参数
        }
        else
        {
            if (!filter.empty()) filter += L" ";
            filter += args[i];
        }
    }

    // 过滤并显示
    std::vector<const DumperProcessEntry*> matched;
    for (const auto& proc : processes)
    {
        if (filter.empty())
        {
            matched.push_back(&proc);
        }
        else
        {
            // 模糊匹配: 进程名或 PID 字符串
            wchar_t pidStr[16];
            swprintf_s(pidStr, L"%u", proc.ProcessId);

            if (WcsContainsCaseInsensitive(proc.ImageName, filter) ||
                WcsContainsCaseInsensitive(pidStr, filter))
            {
                matched.push_back(&proc);
            }
        }
    }

    if (matched.empty())
    {
        wprintf(L"[-] 未找到匹配的进程: %s\n", filter.c_str());
        return;
    }

    wprintf(L"[+] 找到 %zu 个进程", matched.size());
    if (!filter.empty())
        wprintf(L" (过滤: \"%s\")", filter.c_str());
    if (maxDisplay > 0 && matched.size() > maxDisplay)
        wprintf(L" (显示前 %zu 条)", maxDisplay);
    wprintf(L":\n\n");
    wprintf(L"  %-8s  %-8s  %-6s  %-12s  %s\n",
            L"PID", L"PPID", L"线程", L"内存(KB)", L"进程名");
    wprintf(L"  %-8s  %-8s  %-6s  %-12s  %s\n",
            L"--------", L"--------", L"------", L"------------", L"----");

    size_t displayCount = (maxDisplay > 0) ? (std::min)(maxDisplay, matched.size()) : matched.size();
    for (size_t i = 0; i < displayCount; i++)
    {
        const auto* proc = matched[i];
        wprintf(L"  %-8u  %-8u  %-6u  %-12llu  %s\n",
                proc->ProcessId,
                proc->ParentProcessId,
                proc->ThreadCount,
                proc->WorkingSetSize / 1024,
                proc->ImageName.c_str());
    }

    if (maxDisplay > 0 && matched.size() > maxDisplay)
    {
        wprintf(L"\n  ... 还有 %zu 个进程未显示 (使用 -n 增大显示数量)\n",
                matched.size() - maxDisplay);
    }
}

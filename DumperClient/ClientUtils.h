#pragma once

//
// ClientUtils.h - 共享工具函数与通用操作
//

#include <cstdio>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include "DumperClient.h"

// 路径工具
std::wstring GetFileNameWithoutExt(const std::wstring& path);
std::wstring GetFileName(const std::wstring& path);

// 命令行工具
std::vector<std::wstring> TokenizeLine(const wchar_t* line);
bool IsNumericArg(const wchar_t* arg);

// 宽字符大小写不敏感子串搜索 (模糊匹配)
bool WcsContainsCaseInsensitive(const std::wstring& haystack, const std::wstring& needle);

// 控制台工具
int PauseAndExit(int code);

// 作者信息（启动横幅 / 帮助）
void PrintAuthorInfo();

// 通用进程/内存操作
bool DumpMemoryRegion(DumperClient& client, DWORD_PTR address, SIZE_T size, const wchar_t* outputPath);
DWORD GetSizeOfImageFromPE(DumperClient& client, DWORD_PTR baseAddress);
bool DumpModule(DumperClient& client, DWORD_PTR baseAddress, const wchar_t* outputPath);
bool ListModules(DumperClient& client);
bool QueryMemoryInfo(DumperClient& client, DWORD_PTR address);

// 进程查询命令 (交互+单次共用)
void CmdProcessSearch(DumperClient& client, const std::vector<std::wstring>& args);

#pragma once

//
// IATSearch.h - IAT自动搜索
//
// 在目标进程内存中自动定位IAT的位置和大小。
// 使用两种策略:
//   1. 从PE头的导入目录直接读取 (未被擦除时)
//   2. 内存扫描: 寻找连续的API地址指针区域
//

#include <Windows.h>
#include <vector>

class DumperClient;
class ImportResolver;
struct DumperModuleInfo;

struct IATSearchResult
{
    DWORD_PTR   iatAddress;     // IAT虚拟地址
    DWORD       iatSize;        // IAT大小 (字节)
    DWORD       iatRva;         // IAT RVA
};

class IATSearch
{
public:
    IATSearch(DumperClient* client, ImportResolver* resolver);
    ~IATSearch() = default;

    // 搜索IAT
    // moduleBase: 目标模块基址
    // moduleSize: 模块大小
    // 返回: 是否找到IAT
    bool SearchIAT(DWORD_PTR moduleBase, DWORD moduleSize, IATSearchResult& result);

private:
    // 策略1: 从PE导入目录读取IAT位置
    bool SearchFromImportDirectory(DWORD_PTR moduleBase, IATSearchResult& result);

    // 策略2: 扫描内存寻找API指针聚集区域
    bool SearchByMemoryScan(DWORD_PTR moduleBase, DWORD moduleSize, IATSearchResult& result);

    // 检查一个地址值是否像API地址 (位于已知模块范围内)
    bool IsLikelyApiPointer(DWORD_PTR value) const;

    // 在给定范围内统计连续API指针
    DWORD CountConsecutiveApiPointers(const BYTE* data, DWORD dataSize,
                                      DWORD startOffset, bool is64) const;

    DumperClient*       m_Client;
    ImportResolver*     m_Resolver;
};

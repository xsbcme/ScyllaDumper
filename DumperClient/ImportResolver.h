#pragma once

//
// ImportResolver.h - IAT读取与导入表解析
//
// 从目标进程内存读取IAT，解析每个DLL的导出表来匹配函数名。
// 功能对应Scylla的 ApiReader + Get Imports。
//

#include <Windows.h>
#include <string>
#include <vector>
#include <map>

class DumperClient;
struct DumperModuleInfo;

// 单个导入函数
struct ImportFunction
{
    DWORD_PTR   iatRva;         // 在IAT中的RVA
    DWORD_PTR   apiAddress;     // 运行时API地址
    std::string name;           // 函数名 (空=按序号导入)
    WORD        ordinal;        // 序号
    WORD        hint;           // PE hint
    bool        valid;          // 是否成功解析
};

// 导入模块 (一个DLL)
struct ImportModule
{
    std::wstring    moduleName;         // DLL文件名
    std::wstring    modulePath;         // 完整路径
    DWORD_PTR       firstThunkRva;      // 第一个thunk的RVA
    std::vector<ImportFunction> functions;
};

// 导出表缓存 (已解析的DLL导出表)
struct ExportEntry
{
    std::string name;
    WORD        ordinal;
    DWORD       rva;
};

struct ExportCache
{
    std::wstring    moduleName;
    DWORD_PTR       moduleBase;
    DWORD           moduleSize;
    std::vector<ExportEntry> exports;
};

class ImportResolver
{
public:
    ImportResolver(DumperClient* client);
    ~ImportResolver() = default;

    // 初始化: 加载目标进程所有模块信息 + 解析导出表
    bool Initialize(const std::vector<DumperModuleInfo>& modules);

    // 读取并解析IAT
    // iatAddress: IAT在目标进程中的虚拟地址
    // iatSize: IAT大小 (字节)
    // imageBase: 目标模块基址 (用于计算RVA)
    // isTarget64: 目标进程是否为64位 (决定IAT条目大小: 8字节 vs 4字节)
    bool ReadAndParseIAT(DWORD_PTR iatAddress, DWORD iatSize, DWORD_PTR imageBase, bool isTarget64 = true);

    // 获取解析结果
    const std::vector<ImportModule>& GetImports() const { return m_Imports; }

    // 获取统计信息
    DWORD GetTotalFunctions() const;
    DWORD GetResolvedFunctions() const;

    // 打印导入表
    void PrintImports() const;

    // 检查地址是否为有效API
    bool IsApiAddress(DWORD_PTR address) const;

    // 解析单个API地址 -> 模块名 + 函数名
    bool ResolveApiAddress(DWORD_PTR address, std::wstring& moduleName,
                           std::string& functionName, WORD& ordinal) const;

private:
    // 解析单个DLL的导出表 (从进程内存读取)
    bool ParseExportTable(DWORD_PTR moduleBase, DWORD moduleSize,
                          const std::wstring& moduleName);

    // 通过地址查找导出函数
    bool FindExportByAddress(DWORD_PTR address, const ExportCache& cache,
                             std::string& name, WORD& ordinal) const;

    DumperClient*   m_Client;

    // 模块列表
    std::vector<DumperModuleInfo> m_Modules;

    // 导出表缓存 (每个DLL一个)
    std::vector<ExportCache> m_ExportCaches;

    // 解析后的导入列表
    std::vector<ImportModule> m_Imports;
};

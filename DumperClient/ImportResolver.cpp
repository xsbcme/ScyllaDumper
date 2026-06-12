//
// ImportResolver.cpp - IAT读取与导入表解析实现
//
// 通过驱动读取目标进程中已加载DLL的导出表，
// 建立 API地址→(模块名, 函数名) 映射，
// 然后读取IAT中的每个条目进行查找匹配。
//

#include "ImportResolver.h"
#include "DumperClient.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

// ============================================================================
// 构造函数
// ============================================================================

ImportResolver::ImportResolver(DumperClient* client)
    : m_Client(client)
{
}

// ============================================================================
// Initialize - 加载模块列表并解析所有导出表
// ============================================================================

bool ImportResolver::Initialize(const std::vector<DumperModuleInfo>& modules)
{
    m_Modules = modules;
    m_ExportCaches.clear();
    m_Imports.clear();

    if (!m_Client || modules.empty())
        return false;

    wprintf(L"[*] 正在解析 %zu 个模块的导出表...\n", modules.size());

    int parsed = 0;
    for (const auto& mod : modules)
    {
        if (ParseExportTable(mod.BaseAddress, mod.Size, mod.FullPath))
        {
            parsed++;
        }
    }

    wprintf(L"[+] 成功解析 %d/%zu 个模块的导出表, 共 %zu 个导出缓存\n",
            parsed, modules.size(), m_ExportCaches.size());
    return parsed > 0;
}

// ============================================================================
// ParseExportTable - 从进程内存解析单个DLL的导出表
// ============================================================================

bool ImportResolver::ParseExportTable(DWORD_PTR moduleBase, DWORD moduleSize,
                                      const std::wstring& modulePath)
{
    // 读取 DOS 头
    IMAGE_DOS_HEADER dosHeader = {};
    SIZE_T bytesRead = 0;
    if (!m_Client->ReadMemory(moduleBase, sizeof(dosHeader), &dosHeader, &bytesRead))
        return false;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (dosHeader.e_lfanew <= 0 || (DWORD)dosHeader.e_lfanew > 0x1000)
        return false;

    // 读取 NT headers (先读够 PE32+ 的大小)
    BYTE ntBuf[sizeof(IMAGE_NT_HEADERS64)] = {};
    if (!m_Client->ReadMemory(moduleBase + dosHeader.e_lfanew, sizeof(ntBuf), ntBuf, &bytesRead))
        return false;

    auto* pNt32 = (IMAGE_NT_HEADERS32*)ntBuf;
    if (pNt32->Signature != IMAGE_NT_SIGNATURE)
        return false;

    // 获取导出目录 RVA 和 大小
    DWORD exportDirRva = 0;
    DWORD exportDirSize = 0;
    bool is64 = false;

    if (pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto* pNt64 = (IMAGE_NT_HEADERS64*)ntBuf;
        if (pNt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
            return false;
        exportDirRva = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        is64 = true;
    }
    else if (pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (pNt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
            return false;
        exportDirRva = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else
    {
        return false;
    }

    if (exportDirRva == 0 || exportDirSize == 0)
        return false;  // 没有导出表

    // 读取导出目录结构
    IMAGE_EXPORT_DIRECTORY exportDir = {};
    if (!m_Client->ReadMemory(moduleBase + exportDirRva, sizeof(exportDir), &exportDir, &bytesRead))
        return false;

    if (exportDir.NumberOfFunctions == 0)
        return false;

    // 限制导出数量 (防止损坏数据)
    if (exportDir.NumberOfFunctions > 100000)
        return false;

    // 读取地址表 (AddressOfFunctions)
    DWORD funcCount = exportDir.NumberOfFunctions;
    std::vector<DWORD> addressTable(funcCount);
    if (!m_Client->ReadMemory(moduleBase + exportDir.AddressOfFunctions,
                              funcCount * sizeof(DWORD), addressTable.data(), &bytesRead))
        return false;

    // 读取名称表和序号表
    DWORD nameCount = exportDir.NumberOfNames;
    std::vector<DWORD> nameRvaTable;
    std::vector<WORD> ordinalTable;

    if (nameCount > 0 && nameCount <= 100000)
    {
        nameRvaTable.resize(nameCount);
        ordinalTable.resize(nameCount);

        if (!m_Client->ReadMemory(moduleBase + exportDir.AddressOfNames,
                                  nameCount * sizeof(DWORD), nameRvaTable.data(), &bytesRead))
        {
            nameRvaTable.clear();
        }

        if (!m_Client->ReadMemory(moduleBase + exportDir.AddressOfNameOrdinals,
                                  nameCount * sizeof(WORD), ordinalTable.data(), &bytesRead))
        {
            ordinalTable.clear();
        }
    }

    // 创建导出缓存
    ExportCache cache;
    cache.moduleBase = moduleBase;
    cache.moduleSize = moduleSize;

    // 从路径提取文件名作为模块名
    const wchar_t* slash = wcsrchr(modulePath.c_str(), L'\\');
    cache.moduleName = slash ? (slash + 1) : modulePath;

    // 遍历所有导出函数
    for (DWORD i = 0; i < funcCount; i++)
    {
        DWORD funcRva = addressTable[i];
        if (funcRva == 0)
            continue;

        // 检查是否为转发导出 (RVA在导出目录范围内)
        if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize)
            continue;  // 跳过转发导出, 暂不处理

        ExportEntry entry;
        entry.rva = funcRva;
        entry.ordinal = (WORD)(i + exportDir.Base);
        entry.name.clear();

        // 查找名称
        if (!nameRvaTable.empty() && !ordinalTable.empty())
        {
            for (DWORD j = 0; j < nameCount; j++)
            {
                if (ordinalTable[j] == i)
                {
                    // 读取函数名
                    char nameBuf[512] = {};
                    if (m_Client->ReadMemory(moduleBase + nameRvaTable[j],
                                             sizeof(nameBuf) - 1, nameBuf, &bytesRead))
                    {
                        nameBuf[sizeof(nameBuf) - 1] = '\0';
                        entry.name = nameBuf;
                    }
                    break;
                }
            }
        }

        cache.exports.push_back(entry);
    }

    if (!cache.exports.empty())
    {
        m_ExportCaches.push_back(std::move(cache));
    }

    return true;
}

// ============================================================================
// ReadAndParseIAT - 读取IAT并解析所有导入
// ============================================================================

bool ImportResolver::ReadAndParseIAT(DWORD_PTR iatAddress, DWORD iatSize, DWORD_PTR imageBase, bool isTarget64)
{
    m_Imports.clear();

    if (!m_Client || iatAddress == 0 || iatSize == 0)
        return false;

    // 读取IAT数据
    std::vector<BYTE> iatData(iatSize);
    SIZE_T bytesRead = 0;
    if (!m_Client->ReadMemory(iatAddress, iatSize, iatData.data(), &bytesRead))
    {
        wprintf(L"[-] 读取IAT失败 (地址: 0x%llX, 大小: 0x%X)\n",
                (unsigned long long)iatAddress, iatSize);
        return false;
    }

    // 临时映射: 模块名 → ImportModule索引
    std::map<std::wstring, size_t> moduleMap;

    // 逐条解析IAT条目 (64位: 每条8字节, 32位: 每条4字节)
    DWORD_PTR iatRva = (DWORD)(iatAddress - imageBase);
    size_t entrySize = isTarget64 ? 8 : 4;
    size_t entryCount = iatSize / entrySize;

    DWORD_PTR currentThunkStart = iatRva;
    bool inModule = false;
    std::wstring currentModuleName;

    for (size_t i = 0; i < entryCount; i++)
    {
        DWORD_PTR apiAddr = 0;
        if (isTarget64)
            memcpy(&apiAddr, iatData.data() + i * entrySize, 8);
        else
        {
            DWORD addr32 = 0;
            memcpy(&addr32, iatData.data() + i * entrySize, 4);
            apiAddr = (DWORD_PTR)addr32;
        }

        DWORD_PTR entryRva = iatRva + (DWORD)(i * entrySize);

        if (apiAddr == 0)
        {
            // NULL 终止符 — 一个DLL的thunk数组结束
            if (inModule)
            {
                inModule = false;
            }
            currentThunkStart = iatRva + (DWORD)((i + 1) * entrySize);
            continue;
        }

        // 尝试解析这个地址
        std::wstring moduleName;
        std::string funcName;
        WORD ordinal = 0;

        ImportFunction func;
        func.iatRva = entryRva;
        func.apiAddress = apiAddr;
        func.ordinal = 0;
        func.hint = 0;
        func.valid = false;

        if (ResolveApiAddress(apiAddr, moduleName, funcName, ordinal))
        {
            func.name = funcName;
            func.ordinal = ordinal;
            func.valid = true;

            // 如果模块切换了，开始新模块
            if (!inModule || moduleName != currentModuleName)
            {
                // 查找或创建模块
                auto it = moduleMap.find(moduleName);
                if (it == moduleMap.end())
                {
                    ImportModule mod;
                    mod.moduleName = moduleName;
                    mod.firstThunkRva = currentThunkStart;

                    // 查找完整路径
                    for (const auto& cache : m_ExportCaches)
                    {
                        if (_wcsicmp(cache.moduleName.c_str(), moduleName.c_str()) == 0)
                        {
                            for (const auto& m : m_Modules)
                            {
                                if (m.BaseAddress == cache.moduleBase)
                                {
                                    mod.modulePath = m.FullPath;
                                    break;
                                }
                            }
                            break;
                        }
                    }

                    moduleMap[moduleName] = m_Imports.size();
                    m_Imports.push_back(std::move(mod));
                }

                currentModuleName = moduleName;
                inModule = true;
            }

            // 添加到当前模块
            auto it = moduleMap.find(currentModuleName);
            if (it != moduleMap.end())
            {
                m_Imports[it->second].functions.push_back(func);
            }
        }
        else
        {
            // 未解析的地址 — 仍然记录
            func.valid = false;

            if (inModule && !currentModuleName.empty())
            {
                auto it = moduleMap.find(currentModuleName);
                if (it != moduleMap.end())
                {
                    m_Imports[it->second].functions.push_back(func);
                }
            }
            else
            {
                // 无法确定所属模块, 创建占位
                if (moduleMap.find(L"<unknown>") == moduleMap.end())
                {
                    ImportModule mod;
                    mod.moduleName = L"<unknown>";
                    mod.firstThunkRva = currentThunkStart;
                    moduleMap[L"<unknown>"] = m_Imports.size();
                    m_Imports.push_back(std::move(mod));
                }
                auto it = moduleMap.find(L"<unknown>");
                m_Imports[it->second].functions.push_back(func);
            }
        }
    }

    return !m_Imports.empty();
}

// ============================================================================
// IsApiAddress - 检查地址是否落在某个模块的导出范围内
// ============================================================================

bool ImportResolver::IsApiAddress(DWORD_PTR address) const
{
    for (const auto& cache : m_ExportCaches)
    {
        if (address >= cache.moduleBase &&
            address < cache.moduleBase + cache.moduleSize)
        {
            return true;
        }
    }
    return false;
}

// ============================================================================
// ResolveApiAddress - 解析单个API地址
// ============================================================================

bool ImportResolver::ResolveApiAddress(DWORD_PTR address,
                                       std::wstring& moduleName,
                                       std::string& functionName,
                                       WORD& ordinal) const
{
    for (const auto& cache : m_ExportCaches)
    {
        if (address >= cache.moduleBase &&
            address < cache.moduleBase + cache.moduleSize)
        {
            std::string name;
            WORD ord = 0;
            if (FindExportByAddress(address, cache, name, ord))
            {
                moduleName = cache.moduleName;
                functionName = name;
                ordinal = ord;
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// FindExportByAddress - 在导出缓存中按地址查找
// ============================================================================

bool ImportResolver::FindExportByAddress(DWORD_PTR address, const ExportCache& cache,
                                         std::string& name, WORD& ordinal) const
{
    DWORD targetRva = (DWORD)(address - cache.moduleBase);

    for (const auto& exp : cache.exports)
    {
        if (exp.rva == targetRva)
        {
            name = exp.name;
            ordinal = exp.ordinal;
            return true;
        }
    }
    return false;
}

// ============================================================================
// GetTotalFunctions / GetResolvedFunctions
// ============================================================================

DWORD ImportResolver::GetTotalFunctions() const
{
    DWORD total = 0;
    for (const auto& mod : m_Imports)
        total += (DWORD)mod.functions.size();
    return total;
}

DWORD ImportResolver::GetResolvedFunctions() const
{
    DWORD resolved = 0;
    for (const auto& mod : m_Imports)
    {
        for (const auto& func : mod.functions)
        {
            if (func.valid)
                resolved++;
        }
    }
    return resolved;
}

// ============================================================================
// PrintImports - 打印导入表
// ============================================================================

void ImportResolver::PrintImports() const
{
    wprintf(L"\n[+] 导入表解析结果:\n");
    wprintf(L"    模块: %zu, 函数: %u (已解析: %u)\n\n",
            m_Imports.size(), GetTotalFunctions(), GetResolvedFunctions());

    for (const auto& mod : m_Imports)
    {
        wprintf(L"  [%s]  (%zu 个函数, FirstThunk RVA: 0x%llX)\n",
                mod.moduleName.c_str(),
                mod.functions.size(),
                (unsigned long long)mod.firstThunkRva);

        for (const auto& func : mod.functions)
        {
            if (func.valid)
            {
                if (!func.name.empty())
                {
                    wprintf(L"    0x%llX  %hs  (ord: %u)\n",
                            (unsigned long long)func.iatRva,
                            func.name.c_str(),
                            func.ordinal);
                }
                else
                {
                    wprintf(L"    0x%llX  #%u  (按序号)\n",
                            (unsigned long long)func.iatRva,
                            func.ordinal);
                }
            }
            else
            {
                wprintf(L"    0x%llX  ??? (0x%llX)\n",
                        (unsigned long long)func.iatRva,
                        (unsigned long long)func.apiAddress);
            }
        }
        wprintf(L"\n");
    }
}

//
// ImportRebuilder.cpp - 重建PE导入表实现
//
// 在已转存的PE文件末尾添加 .SCY 节，包含:
//   1. IMAGE_IMPORT_DESCRIPTOR 数组 (每个DLL一条 + NULL终止)
//   2. OriginalFirstThunk 数组 (IMAGE_THUNK_DATA)
//   3. DLL名称字符串
//   4. IMAGE_IMPORT_BY_NAME 结构 (hint + 函数名)
// 同时修补IAT (FirstThunk) 指向正确位置。
//

#include "ImportRebuilder.h"
#include "ImportResolver.h"
#include "PeParser.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// ============================================================================
// CalculateImportSectionSize - 计算导入节大小
// ============================================================================

DWORD ImportRebuilder::CalculateImportSectionSize(const std::vector<ImportModule>& imports) const
{
    if (imports.empty())
        return 0;

    DWORD size = 0;

    // 1. IMAGE_IMPORT_DESCRIPTOR 数组 (N + 1 个, 最后一个全零终止)
    size += (DWORD)((imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    for (const auto& mod : imports)
    {
        // 2. OriginalFirstThunk 数组 (函数数 + 1 个NULL终止)
        //    每条 IMAGE_THUNK_DATA64 = 8字节 (64位)
        //    这里按64位计算最大值, 32位时实际更小
        size += (DWORD)((mod.functions.size() + 1) * sizeof(IMAGE_THUNK_DATA64));

        // 3. DLL名称
        //    宽字符转窄字符 + 对齐
        int nameLen = WideCharToMultiByte(CP_ACP, 0, mod.moduleName.c_str(), -1,
                                          NULL, 0, NULL, NULL);
        size += (DWORD)nameLen;
        // 对齐到2字节
        if (size % 2) size++;

        // 4. 每个函数的 IMAGE_IMPORT_BY_NAME (hint + 名称)
        for (const auto& func : mod.functions)
        {
            if (!func.valid)
                continue;
            if (func.name.empty())
                continue;  // 按序号导入不需要名称

            size += sizeof(WORD);  // hint
            size += (DWORD)(func.name.length() + 1);  // 名称 + NUL
            if (size % 2) size++;  // 对齐
        }
    }

    // 加一些余量
    size += 0x100;

    return size;
}

// ============================================================================
// BuildImportSectionData - 构建导入节二进制数据
// ============================================================================

bool ImportRebuilder::BuildImportSectionData(BYTE* sectionData, DWORD sectionRva,
                                              const std::vector<ImportModule>& imports,
                                              bool is64Bit)
{
    DWORD offset = 0;
    size_t thunkSize = is64Bit ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    // ---- Phase 1: 计算各区域起始偏移 ----

    // IMAGE_IMPORT_DESCRIPTOR 数组
    DWORD descriptorOffset = offset;
    DWORD descriptorCount = (DWORD)(imports.size() + 1);
    offset += descriptorCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // OriginalFirstThunk 数组区域
    DWORD oftAreaOffset = offset;
    for (const auto& mod : imports)
    {
        offset += (DWORD)((mod.functions.size() + 1) * thunkSize);
    }

    // DLL名称 + 函数名称区域
    DWORD nameAreaOffset = offset;

    // ---- Phase 2: 填充数据 ----

    DWORD currentOftOffset = oftAreaOffset;
    DWORD currentNameOffset = nameAreaOffset;

    for (size_t i = 0; i < imports.size(); i++)
    {
        const auto& mod = imports[i];

        // 填充 IMAGE_IMPORT_DESCRIPTOR
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(sectionData + descriptorOffset +
                      i * sizeof(IMAGE_IMPORT_DESCRIPTOR));

        desc->OriginalFirstThunk = sectionRva + currentOftOffset;
        desc->TimeDateStamp = 0;
        desc->ForwarderChain = 0;
        desc->FirstThunk = (DWORD)mod.firstThunkRva;

        // 写入DLL名称
        desc->Name = sectionRva + currentNameOffset;
        char dllName[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, mod.moduleName.c_str(), -1,
                            dllName, sizeof(dllName), NULL, NULL);
        size_t dllNameLen = strlen(dllName) + 1;
        memcpy(sectionData + currentNameOffset, dllName, dllNameLen);
        currentNameOffset += (DWORD)dllNameLen;
        if (currentNameOffset % 2) currentNameOffset++;  // 2字节对齐

        // 填充 OriginalFirstThunk 数组
        for (size_t j = 0; j < mod.functions.size(); j++)
        {
            const auto& func = mod.functions[j];

            if (func.valid && !func.name.empty())
            {
                // 按名称导入: thunk指向 IMAGE_IMPORT_BY_NAME
                DWORD importByNameRva = sectionRva + currentNameOffset;

                if (is64Bit)
                {
                    auto* thunk = (IMAGE_THUNK_DATA64*)(sectionData + currentOftOffset +
                                   j * sizeof(IMAGE_THUNK_DATA64));
                    thunk->u1.AddressOfData = importByNameRva;
                }
                else
                {
                    auto* thunk = (IMAGE_THUNK_DATA32*)(sectionData + currentOftOffset +
                                   j * sizeof(IMAGE_THUNK_DATA32));
                    thunk->u1.AddressOfData = importByNameRva;
                }

                // 写入 IMAGE_IMPORT_BY_NAME
                auto* importByName = (IMAGE_IMPORT_BY_NAME*)(sectionData + currentNameOffset);
                importByName->Hint = func.hint;
                memcpy(importByName->Name, func.name.c_str(), func.name.length() + 1);
                currentNameOffset += sizeof(WORD) + (DWORD)(func.name.length() + 1);
                if (currentNameOffset % 2) currentNameOffset++;
            }
            else if (func.valid)
            {
                // 按序号导入
                if (is64Bit)
                {
                    auto* thunk = (IMAGE_THUNK_DATA64*)(sectionData + currentOftOffset +
                                   j * sizeof(IMAGE_THUNK_DATA64));
                    thunk->u1.Ordinal = IMAGE_ORDINAL_FLAG64 | func.ordinal;
                }
                else
                {
                    auto* thunk = (IMAGE_THUNK_DATA32*)(sectionData + currentOftOffset +
                                   j * sizeof(IMAGE_THUNK_DATA32));
                    thunk->u1.Ordinal = IMAGE_ORDINAL_FLAG32 | func.ordinal;
                }
            }
            // 无效条目保持为0 (NULL thunk)
        }

        // NULL终止OFT数组 (已memset为0)
        currentOftOffset += (DWORD)((mod.functions.size() + 1) * thunkSize);
    }

    // NULL终止 IMAGE_IMPORT_DESCRIPTOR (已memset为0)

    return true;
}

// ============================================================================
// RebuildImportTable - 主入口
// ============================================================================

bool ImportRebuilder::RebuildImportTable(const WCHAR* dumpedFilePath,
                                         const std::vector<ImportModule>& imports,
                                         DWORD iatRva, DWORD iatSize)
{
    if (!dumpedFilePath || imports.empty())
    {
        wprintf(L"[-] 无效参数\n");
        return false;
    }

    // 1. 打开已转存的PE文件
    PeParser pe(dumpedFilePath);
    if (!pe.IsValid())
    {
        wprintf(L"[-] 无法解析PE文件: %s\n", dumpedFilePath);
        return false;
    }

    if (!pe.ReadSectionsFromFile())
    {
        wprintf(L"[-] 无法读取PE节数据\n");
        return false;
    }

    bool is64 = pe.Is64Bit();

    // 2. 计算新导入节大小
    DWORD sectionSize = CalculateImportSectionSize(imports);
    wprintf(L"[*] 新导入节大小: 0x%X\n", sectionSize);

    // 3. 添加 .SCY 节
    if (!pe.AddSection(".SCY", sectionSize,
                       IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA))
    {
        wprintf(L"[-] 添加 .SCY 节失败\n");
        return false;
    }

    // 获取新节信息
    const auto& sections = pe.GetSections();
    const auto& scySec = sections.back();
    DWORD scyRva = scySec.header.VirtualAddress;

    wprintf(L"[*] .SCY 节 RVA: 0x%X, 大小: 0x%X\n", scyRva, scySec.header.SizeOfRawData);

    // 4. 填充导入节数据
    memset(scySec.data, 0, scySec.dataSize);
    if (!BuildImportSectionData(scySec.data, scyRva, imports, is64))
    {
        wprintf(L"[-] 构建导入节数据失败\n");
        return false;
    }

    // 5. 更新PE头中的导入表目录和IAT目录
    pe.SetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT, scyRva,
                        (DWORD)((imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
    pe.SetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT, iatRva, iatSize);

    // 清除绑定导入
    pe.SetDataDirectory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0, 0);

    // 6. 对齐节和修复头
    pe.AlignAllSectionHeaders();
    pe.FixPeHeader();

    // 7. 保存
    if (!pe.SaveToFile(dumpedFilePath))
    {
        wprintf(L"[-] 保存PE文件失败\n");
        return false;
    }

    wprintf(L"[+] 导入表重建成功, 已写入 %zu 个模块\n", imports.size());
    return true;
}

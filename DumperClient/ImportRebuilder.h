#pragma once

//
// ImportRebuilder.h - 重建PE导入表
//
// 将解析后的导入信息写入新的PE节 (.SCY)，
// 生成完整的 IMAGE_IMPORT_DESCRIPTOR 数组 + thunk + 名称字符串。
// 对应Scylla的ImportRebuilder功能。
//

#include <Windows.h>
#include <vector>
#include <string>

struct ImportModule;  // ImportResolver.h

class ImportRebuilder
{
public:
    ImportRebuilder() = default;
    ~ImportRebuilder() = default;

    // 将导入表写入已转存的PE文件
    // dumpedFilePath: 已转存的PE文件路径
    // imports: 解析后的导入列表 (来自ImportResolver)
    // iatRva: IAT在PE中的RVA
    // iatSize: IAT大小
    // 返回: 是否成功
    bool RebuildImportTable(const WCHAR* dumpedFilePath,
                            const std::vector<ImportModule>& imports,
                            DWORD iatRva, DWORD iatSize);

private:
    // 计算新导入节需要的总大小
    DWORD CalculateImportSectionSize(const std::vector<ImportModule>& imports) const;

    // 构建导入节数据
    bool BuildImportSectionData(BYTE* sectionData, DWORD sectionRva,
                                const std::vector<ImportModule>& imports,
                                bool is64Bit);
};

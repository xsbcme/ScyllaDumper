//
// PeRebuild.cpp - PE重建与优化实现
//
// 读取PE文件, 重新对齐节表, 修复头信息, 可选清除重定位。
//

#include "PeRebuild.h"
#include "PeParser.h"
#include <cstdio>

// ============================================================================
// Rebuild - 重建PE文件
// ============================================================================

bool PeRebuild::Rebuild(const WCHAR* filePath)
{
    if (!filePath)
        return false;

    PeParser pe(filePath);
    if (!pe.IsValid())
    {
        wprintf(L"[-] 无法解析PE文件: %s\n", filePath);
        return false;
    }

    if (!pe.ReadSectionsFromFile())
    {
        wprintf(L"[-] 无法读取PE节数据\n");
        return false;
    }

    wprintf(L"[*] PE重建: %s\n", filePath);
    wprintf(L"    节数: %u, SizeOfImage: 0x%X\n",
            pe.GetNumberOfSections(), pe.GetSizeOfImage());

    // 清除重定位目录 (可选)
    if (m_RemoveReloc)
    {
        pe.SetDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0);
        wprintf(L"    已清除重定位目录\n");
    }

    // 对齐所有节
    pe.AlignAllSectionHeaders();

    // 修复PE头 (SizeOfImage, 绑定导入等)
    pe.FixPeHeader();

    wprintf(L"    新 SizeOfImage: 0x%X\n", pe.GetSizeOfImage());

    // 保存
    if (!pe.SaveToFile(filePath))
    {
        wprintf(L"[-] 保存PE文件失败\n");
        return false;
    }

    wprintf(L"[+] PE重建完成\n");
    return true;
}

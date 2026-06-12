#pragma once

//
// PeRebuild.h - PE重建与优化
//
// 对已转存的PE文件进行节对齐、头修复、重定位清除等操作。
// 对应Scylla的PeRebuild功能。
//

#include <Windows.h>

class PeRebuild
{
public:
    PeRebuild() = default;
    ~PeRebuild() = default;

    // 重建PE文件 (就地修改)
    // filePath: 要重建的PE文件
    // 返回: 是否成功
    bool Rebuild(const WCHAR* filePath);

    // 选项
    void SetRemoveRelocation(bool remove) { m_RemoveReloc = remove; }
    void SetUpdateChecksum(bool update) { m_UpdateChecksum = update; }

private:
    bool m_RemoveReloc = false;
    bool m_UpdateChecksum = false;
};

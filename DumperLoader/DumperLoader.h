#pragma once

//
// DumperLoader.h - DumperDriver 内核驱动加载器 (基于 kdmapper)
//
// 使用方法:
//   1. 调用 DumperLoader::LoadEmbeddedDriver() 加载 exe 内嵌驱动
//      或调用 DumperLoader::LoadDriver(path)  从文件路径加载
//   2. 驱动成功加载后，通过 DumperClient::Connect() 建立共享内存通信
//

#include <Windows.h>

namespace DumperLoader
{
    // 从当前 exe 内嵌的 RCDATA 资源 (IDR_DUMPER_DRIVER=101) 提取并映射驱动。
    // 提取到临时文件 → MapDriver → 删除临时文件。成功返回 true。
    bool LoadEmbeddedDriver();

    // 将驱动 (.sys) 通过 kdmapper 映射到内核。成功返回 true。
    bool LoadDriver(const wchar_t* driverPath);

    // 卸载用于映射驱动的 vulnerable driver (intel network adapter driver)。
    // LoadDriver/LoadEmbeddedDriver 内部在成功后会自动卸载，通常无需手动调用。
    bool UnloadVulnDriver();
}

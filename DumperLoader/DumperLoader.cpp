//
// DumperLoader.cpp - DumperDriver 内核驱动加载器实现
//

#include "DumperLoader.h"
#include "include/kdmapper.hpp"
#include "include/intel_driver.hpp"
#include "include/utils.hpp"
#include <iostream>
#include <vector>
#include <filesystem>

// IDR_DUMPER_DRIVER: 与 DumperClient.rc 中的 #define 保持一致
static constexpr WORD kDumperDriverResId = 101;

namespace DumperLoader
{

bool LoadDriver(const wchar_t* driverPath)
{
    if (!driverPath || !std::filesystem::exists(driverPath))
    {
        std::wcout << L"[-] DumperLoader: 驱动文件不存在: "
                   << (driverPath ? driverPath : L"(null)") << std::endl;
        return false;
    }

    if (!NT_SUCCESS(intel_driver::Load()))
    {
        std::wcout << L"[-] DumperLoader: 加载 vulnerable driver 失败" << std::endl;
        return false;
    }

    std::vector<uint8_t> rawImage;
    if (!kdmUtils::ReadFileToMemory(driverPath, &rawImage))
    {
        std::wcout << L"[-] DumperLoader: 读取驱动文件失败" << std::endl;
        intel_driver::Unload();
        return false;
    }

    NTSTATUS exitCode = 0;
    const bool mapped = kdmapper::MapDriver(
        rawImage.data(),
        0, 0,
        false,          // free
        true,           // destroyHeader
        kdmapper::AllocationMode::AllocatePool,
        false,          // PassAllocationAddressAsFirstParam
        nullptr,        // callback
        &exitCode);

    if (!mapped)
    {
        std::wcout << L"[-] DumperLoader: MapDriver 失败，驱动路径: " << driverPath << std::endl;
        intel_driver::Unload();
        return false;
    }

    if (!NT_SUCCESS(intel_driver::Unload()))
    {
        std::wcout << L"[!] DumperLoader: 警告 — vulnerable driver 未能完全卸载" << std::endl;
    }

    if (!NT_SUCCESS(exitCode))
    {
        std::wcout << L"[-] DumperLoader: 驱动 DriverEntry 返回错误: 0x"
                   << std::hex << (unsigned long)exitCode << std::dec << std::endl;
        return false;
    }

    return true;
}

bool UnloadVulnDriver()
{
    return NT_SUCCESS(intel_driver::Unload());
}

bool LoadEmbeddedDriver()
{
    // 从当前 exe 的资源段提取 DumperDriver.sys 到临时文件, 再调用 LoadDriver
    HMODULE hSelf = GetModuleHandleW(NULL);
    HRSRC hRes = FindResourceW(hSelf, MAKEINTRESOURCEW(kDumperDriverResId), RT_RCDATA);
    if (!hRes)
    {
        std::wcout << L"[-] DumperLoader: 未找到内嵌驱动资源 (IDR_DUMPER_DRIVER="
                   << kDumperDriverResId << L")" << std::endl;
        return false;
    }

    HGLOBAL hGlobal = LoadResource(hSelf, hRes);
    if (!hGlobal)
    {
        std::wcout << L"[-] DumperLoader: LoadResource 失败" << std::endl;
        return false;
    }

    const void* pData = LockResource(hGlobal);
    DWORD dataSize = SizeofResource(hSelf, hRes);
    if (!pData || dataSize == 0)
    {
        std::wcout << L"[-] DumperLoader: 资源数据无效" << std::endl;
        return false;
    }

    // 写入临时文件
    wchar_t tempDir[MAX_PATH] = {};
    wchar_t tempPath[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    if (GetTempFileNameW(tempDir, L"ddr", 0, tempPath) == 0)
    {
        std::wcout << L"[-] DumperLoader: 无法创建临时文件" << std::endl;
        return false;
    }

    // GetTempFileName 已创建了一个文件，使用 TRUNCATE_EXISTING 覆写
    HANDLE hFile = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
                               TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"[-] DumperLoader: 无法写临时文件: " << tempPath << std::endl;
        DeleteFileW(tempPath);
        return false;
    }

    DWORD written = 0;
    const bool writeOk = WriteFile(hFile, pData, dataSize, &written, nullptr)
                         && written == dataSize;
    CloseHandle(hFile);

    if (!writeOk)
    {
        std::wcout << L"[-] DumperLoader: 写临时文件失败" << std::endl;
        DeleteFileW(tempPath);
        return false;
    }

    const bool loaded = LoadDriver(tempPath);
    DeleteFileW(tempPath);   // 无论成败都删除临时文件
    return loaded;
}

} // namespace DumperLoader

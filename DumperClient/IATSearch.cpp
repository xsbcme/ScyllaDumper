//
// IATSearch.cpp - IAT自动搜索实现
//
// 策略1: 读取PE的 IMAGE_DIRECTORY_ENTRY_IAT 数据目录
// 策略2: 扫描 .rdata/.idata 节中的连续API指针区域
//

#include "IATSearch.h"
#include "ImportResolver.h"
#include "DumperClient.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// 至少连续N个API指针才认为找到IAT
static const DWORD MIN_IAT_POINTERS = 3;

// ============================================================================
// 构造函数
// ============================================================================

IATSearch::IATSearch(DumperClient* client, ImportResolver* resolver)
    : m_Client(client)
    , m_Resolver(resolver)
{
}

// ============================================================================
// SearchIAT - 主搜索入口
// ============================================================================

bool IATSearch::SearchIAT(DWORD_PTR moduleBase, DWORD moduleSize, IATSearchResult& result)
{
    memset(&result, 0, sizeof(result));

    // 策略1: 从PE导入目录
    if (SearchFromImportDirectory(moduleBase, result))
    {
        wprintf(L"[+] IAT found via Import Directory: VA=0x%llX, RVA=0x%X, Size=0x%X\n",
                (unsigned long long)result.iatAddress, result.iatRva, result.iatSize);
        return true;
    }

    wprintf(L"[*] 导入目录无效, 尝试内存扫描...\n");

    // 策略2: 内存扫描
    if (SearchByMemoryScan(moduleBase, moduleSize, result))
    {
        wprintf(L"[+] IAT found via memory scan: VA=0x%llX, RVA=0x%X, Size=0x%X\n",
                (unsigned long long)result.iatAddress, result.iatRva, result.iatSize);
        return true;
    }

    wprintf(L"[-] 未能找到IAT\n");
    return false;
}

// ============================================================================
// SearchFromImportDirectory - 从PE头读取IAT信息
// ============================================================================

bool IATSearch::SearchFromImportDirectory(DWORD_PTR moduleBase, IATSearchResult& result)
{
    if (!m_Client)
        return false;

    // 读取DOS头
    IMAGE_DOS_HEADER dosHeader = {};
    SIZE_T bytesRead = 0;
    if (!m_Client->ReadMemory(moduleBase, sizeof(dosHeader), &dosHeader, &bytesRead))
        return false;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (dosHeader.e_lfanew <= 0 || (DWORD)dosHeader.e_lfanew > 0x1000)
        return false;

    // 读取NT头
    BYTE ntBuf[sizeof(IMAGE_NT_HEADERS64)] = {};
    if (!m_Client->ReadMemory(moduleBase + dosHeader.e_lfanew, sizeof(ntBuf), ntBuf, &bytesRead))
        return false;

    auto* pNt32 = (IMAGE_NT_HEADERS32*)ntBuf;
    if (pNt32->Signature != IMAGE_NT_SIGNATURE)
        return false;

    DWORD iatRva = 0, iatSize = 0;
    bool is64 = false;

    if (pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto* pNt64 = (IMAGE_NT_HEADERS64*)ntBuf;
        if (pNt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
        {
            iatRva = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            iatSize = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }
        is64 = true;
    }
    else if (pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (pNt32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
        {
            iatRva = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            iatSize = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }
    }
    else
    {
        return false;
    }

    if (iatRva == 0 || iatSize == 0)
        return false;

    // 验证: 读取IAT区域, 检查是否包含有效的API指针
    DWORD verifySize = (std::min)(iatSize, (DWORD)0x1000);
    std::vector<BYTE> verifyBuf(verifySize);
    if (!m_Client->ReadMemory(moduleBase + iatRva, verifySize, verifyBuf.data(), &bytesRead))
        return false;

    DWORD apiCount = CountConsecutiveApiPointers(verifyBuf.data(), (DWORD)bytesRead, 0, is64);
    if (apiCount < MIN_IAT_POINTERS)
        return false;

    result.iatAddress = moduleBase + iatRva;
    result.iatRva = iatRva;
    result.iatSize = iatSize;
    return true;
}

// ============================================================================
// SearchByMemoryScan - 扫描内存中的API指针聚集区域
// ============================================================================

bool IATSearch::SearchByMemoryScan(DWORD_PTR moduleBase, DWORD moduleSize, IATSearchResult& result)
{
    if (!m_Client || !m_Resolver)
        return false;

    // 读取PE节头来确定扫描范围
    IMAGE_DOS_HEADER dosHeader = {};
    SIZE_T bytesRead = 0;
    m_Client->ReadMemory(moduleBase, sizeof(dosHeader), &dosHeader, &bytesRead);

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    BYTE ntBuf[sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * 64] = {};
    DWORD ntReadSize = (DWORD)(std::min)((DWORD)sizeof(ntBuf),
                                          moduleSize - (DWORD)dosHeader.e_lfanew);

    if (!m_Client->ReadMemory(moduleBase + dosHeader.e_lfanew, ntReadSize, ntBuf, &bytesRead))
        return false;

    auto* pNt32 = (IMAGE_NT_HEADERS32*)ntBuf;
    if (pNt32->Signature != IMAGE_NT_SIGNATURE)
        return false;

    bool is64 = (pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // 定位节头
    IMAGE_SECTION_HEADER* sections = nullptr;
    WORD numSections = 0;

    if (is64)
    {
        auto* pNt64 = (IMAGE_NT_HEADERS64*)ntBuf;
        sections = (IMAGE_SECTION_HEADER*)((BYTE*)&pNt64->OptionalHeader +
                    pNt64->FileHeader.SizeOfOptionalHeader);
        numSections = pNt64->FileHeader.NumberOfSections;
    }
    else
    {
        sections = (IMAGE_SECTION_HEADER*)((BYTE*)&pNt32->OptionalHeader +
                    pNt32->FileHeader.SizeOfOptionalHeader);
        numSections = pNt32->FileHeader.NumberOfSections;
    }

    if (numSections > 64)
        numSections = 64;

    // 在只读数据节中搜索 (.rdata, .idata等)
    DWORD_PTR bestIatAddr = 0;
    DWORD bestIatSize = 0;
    DWORD bestApiCount = 0;

    size_t ptrSize = is64 ? 8 : 4;

    for (WORD i = 0; i < numSections; i++)
    {
        DWORD secVirtualSize = sections[i].Misc.VirtualSize;
        if (secVirtualSize == 0)
            secVirtualSize = sections[i].SizeOfRawData;
        if (secVirtualSize == 0 || secVirtualSize > 0x2000000)  // 32MB上限
            continue;

        // 只扫描可读不可执行的节 (IAT通常在 .rdata/.idata)
        DWORD chars = sections[i].Characteristics;
        if (chars & IMAGE_SCN_MEM_EXECUTE)
            continue;
        if (!(chars & IMAGE_SCN_MEM_READ))
            continue;

        // 读取整个节
        std::vector<BYTE> secData(secVirtualSize);
        if (!m_Client->ReadMemoryPartial(moduleBase + sections[i].VirtualAddress,
                                         secVirtualSize, secData.data(), &bytesRead))
            continue;

        // 扫描: 在节中找连续的API指针区域
        DWORD offset = 0;
        while (offset + ptrSize <= (DWORD)bytesRead)
        {
            DWORD_PTR value = 0;
            memcpy(&value, secData.data() + offset, ptrSize);

            if (value != 0 && IsLikelyApiPointer(value))
            {
                // 找到一个可能的API指针, 向后扫描看连续长度
                DWORD startOffset = offset;
                DWORD apiCount = 0;
                DWORD scanPos = startOffset;

                while (scanPos + ptrSize <= (DWORD)bytesRead)
                {
                    DWORD_PTR ptr = 0;
                    memcpy(&ptr, secData.data() + scanPos, ptrSize);

                    if (ptr == 0)
                    {
                        // NULL分隔符 — 可能是DLL间的分界
                        apiCount++;  // 算作IAT的一部分
                        scanPos += (DWORD)ptrSize;
                        continue;
                    }

                    if (IsLikelyApiPointer(ptr))
                    {
                        apiCount++;
                        scanPos += (DWORD)ptrSize;
                    }
                    else
                    {
                        break;  // 非API指针, IAT结束
                    }
                }

                if (apiCount > bestApiCount && apiCount >= MIN_IAT_POINTERS)
                {
                    bestApiCount = apiCount;
                    bestIatAddr = moduleBase + sections[i].VirtualAddress + startOffset;
                    bestIatSize = scanPos - startOffset;
                }

                // 跳过已扫描的区域
                offset = scanPos;
            }
            else
            {
                offset += (DWORD)ptrSize;
            }
        }
    }

    if (bestApiCount >= MIN_IAT_POINTERS && bestIatSize > 0)
    {
        result.iatAddress = bestIatAddr;
        result.iatRva = (DWORD)(bestIatAddr - moduleBase);
        result.iatSize = bestIatSize;
        return true;
    }

    return false;
}

// ============================================================================
// IsLikelyApiPointer - 检查值是否像API地址
// ============================================================================

bool IATSearch::IsLikelyApiPointer(DWORD_PTR value) const
{
    if (m_Resolver)
        return m_Resolver->IsApiAddress(value);

    // 没有resolver时用启发式: 检查是否在常见DLL地址范围
    // 64位: 系统DLL通常在 0x7FF*_****_**** 范围
    // 32位: 系统DLL通常在 0x7***_**** 范围
#ifdef _WIN64
    if (value >= 0x00007FF000000000ULL && value < 0x00007FFFFFFEFFFFULL)
        return true;
    // 也检查低于4GB的范围 (某些DLL)
    if (value >= 0x0000000010000000ULL && value < 0x0000000080000000ULL)
        return true;
#else
    if (value >= 0x10000000 && value < 0x80000000)
        return true;
#endif

    return false;
}

// ============================================================================
// CountConsecutiveApiPointers
// ============================================================================

DWORD IATSearch::CountConsecutiveApiPointers(const BYTE* data, DWORD dataSize,
                                              DWORD startOffset, bool is64) const
{
    DWORD count = 0;
    size_t ptrSize = is64 ? 8 : 4;
    DWORD offset = startOffset;

    while (offset + ptrSize <= dataSize)
    {
        DWORD_PTR value = 0;
        memcpy(&value, data + offset, ptrSize);

        if (value == 0)
        {
            offset += (DWORD)ptrSize;
            continue;  // NULL分隔符
        }

        if (IsLikelyApiPointer(value))
        {
            count++;
            offset += (DWORD)ptrSize;
        }
        else
        {
            break;
        }
    }

    return count;
}

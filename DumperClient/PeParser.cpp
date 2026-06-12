//
// PeParser.cpp - PE文件解析与操作实现
//

#include "PeParser.h"
#include "DumperClient.h"
#include "DebugLog.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// ============================================================================
// 构造函数 - 从进程内存
// ============================================================================

PeParser::PeParser(DumperClient* client, DWORD_PTR moduleBase)
    : m_Client(client)
    , m_ModuleBase(moduleBase)
    , m_Valid(false)
    , m_Is64(false)
    , m_FromFile(false)
    , m_pDosHeader(nullptr)
    , m_pNtHeader32(nullptr)
    , m_pNtHeader64(nullptr)
    , m_pSectionHeaders(nullptr)
{
    memset(m_HeaderBuffer, 0, sizeof(m_HeaderBuffer));

    if (!client || !moduleBase)
        return;

    // 从进程内存读取PE头
    SIZE_T bytesRead = 0;
    if (!client->ReadMemory(moduleBase, sizeof(m_HeaderBuffer), m_HeaderBuffer, &bytesRead))
        return;

    if (bytesRead < sizeof(IMAGE_DOS_HEADER))
        return;

    ParseHeaders(m_HeaderBuffer, (DWORD)bytesRead);
}

// ============================================================================
// 构造函数 - 从磁盘文件
// ============================================================================

PeParser::PeParser(const WCHAR* filePath)
    : m_Client(nullptr)
    , m_ModuleBase(0)
    , m_Valid(false)
    , m_Is64(false)
    , m_FromFile(true)
    , m_pDosHeader(nullptr)
    , m_pNtHeader32(nullptr)
    , m_pNtHeader64(nullptr)
    , m_pSectionHeaders(nullptr)
    , m_FilePath(filePath)
{
    memset(m_HeaderBuffer, 0, sizeof(m_HeaderBuffer));

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD bytesRead = 0;
    ReadFile(hFile, m_HeaderBuffer, sizeof(m_HeaderBuffer), &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead < sizeof(IMAGE_DOS_HEADER))
        return;

    ParseHeaders(m_HeaderBuffer, bytesRead);
}

// ============================================================================
// 析构
// ============================================================================

PeParser::~PeParser()
{
    for (auto& sec : m_Sections)
    {
        delete[] sec.data;
        sec.data = nullptr;
    }
}

// ============================================================================
// ParseHeaders - 解析PE头
// ============================================================================

bool PeParser::ParseHeaders(const BYTE* /*headerData*/, DWORD headerSize)
{
    m_pDosHeader = (IMAGE_DOS_HEADER*)m_HeaderBuffer;

    if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if ((DWORD)m_pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > headerSize)
        return false;

    m_pNtHeader32 = (IMAGE_NT_HEADERS32*)(m_HeaderBuffer + m_pDosHeader->e_lfanew);
    m_pNtHeader64 = (IMAGE_NT_HEADERS64*)(m_HeaderBuffer + m_pDosHeader->e_lfanew);

    if (m_pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
        return false;

    WORD magic = m_pNtHeader32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        m_Is64 = true;
        m_pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&m_pNtHeader64->OptionalHeader +
            m_pNtHeader64->FileHeader.SizeOfOptionalHeader);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        m_Is64 = false;
        m_pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&m_pNtHeader32->OptionalHeader +
            m_pNtHeader32->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        return false;
    }

    // 初始化节列表 (只有头信息，数据还没读)
    // 注意: 直接从 FileHeader 读取，不用 GetNumberOfSections() (此时 m_Valid 尚未设置)
    WORD numSections = m_pNtHeader32->FileHeader.NumberOfSections;
    m_Sections.resize(numSections);
    for (WORD i = 0; i < numSections; i++)
    {
        m_Sections[i].header = m_pSectionHeaders[i];
        m_Sections[i].data = nullptr;
        m_Sections[i].dataSize = 0;
    }

    m_Valid = true;
    return true;
}

// ============================================================================
// PE头信息访问器
// ============================================================================

DWORD PeParser::GetSizeOfImage() const
{
    if (!m_Valid) return 0;
    return m_Is64 ? m_pNtHeader64->OptionalHeader.SizeOfImage
                  : m_pNtHeader32->OptionalHeader.SizeOfImage;
}

DWORD PeParser::GetSizeOfHeaders() const
{
    if (!m_Valid) return 0;
    return m_Is64 ? m_pNtHeader64->OptionalHeader.SizeOfHeaders
                  : m_pNtHeader32->OptionalHeader.SizeOfHeaders;
}

DWORD_PTR PeParser::GetEntryPoint() const
{
    if (!m_Valid) return 0;
    return m_Is64 ? m_pNtHeader64->OptionalHeader.AddressOfEntryPoint
                  : m_pNtHeader32->OptionalHeader.AddressOfEntryPoint;
}

DWORD_PTR PeParser::GetImageBase() const
{
    if (!m_Valid) return 0;
    return m_Is64 ? (DWORD_PTR)m_pNtHeader64->OptionalHeader.ImageBase
                  : (DWORD_PTR)m_pNtHeader32->OptionalHeader.ImageBase;
}

DWORD PeParser::GetFileAlignment() const
{
    if (!m_Valid) return 0x200;
    return m_Is64 ? m_pNtHeader64->OptionalHeader.FileAlignment
                  : m_pNtHeader32->OptionalHeader.FileAlignment;
}

DWORD PeParser::GetSectionAlignment() const
{
    if (!m_Valid) return 0x1000;
    return m_Is64 ? m_pNtHeader64->OptionalHeader.SectionAlignment
                  : m_pNtHeader32->OptionalHeader.SectionAlignment;
}

WORD PeParser::GetNumberOfSections() const
{
    if (!m_Valid) return 0;
    return m_pNtHeader32->FileHeader.NumberOfSections;  // 相同偏移
}

IMAGE_DATA_DIRECTORY PeParser::GetDataDirectory(DWORD index) const
{
    IMAGE_DATA_DIRECTORY empty = { 0, 0 };
    if (!m_Valid || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return empty;
    return m_Is64 ? m_pNtHeader64->OptionalHeader.DataDirectory[index]
                  : m_pNtHeader32->OptionalHeader.DataDirectory[index];
}

void PeParser::SetDataDirectory(DWORD index, DWORD rva, DWORD size)
{
    if (!m_Valid || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return;
    if (m_Is64)
    {
        m_pNtHeader64->OptionalHeader.DataDirectory[index].VirtualAddress = rva;
        m_pNtHeader64->OptionalHeader.DataDirectory[index].Size = size;
    }
    else
    {
        m_pNtHeader32->OptionalHeader.DataDirectory[index].VirtualAddress = rva;
        m_pNtHeader32->OptionalHeader.DataDirectory[index].Size = size;
    }
}

// ============================================================================
// RVA/偏移转换
// ============================================================================

int PeParser::RvaToSectionIndex(DWORD rva) const
{
    for (int i = 0; i < (int)m_Sections.size(); i++)
    {
        DWORD secStart = m_Sections[i].header.VirtualAddress;
        DWORD secEnd = secStart + (std::max)(m_Sections[i].header.Misc.VirtualSize,
                                              m_Sections[i].header.SizeOfRawData);
        if (rva >= secStart && rva < secEnd)
            return i;
    }
    return -1;
}

DWORD PeParser::RvaToFileOffset(DWORD rva) const
{
    int idx = RvaToSectionIndex(rva);
    if (idx < 0)
        return rva;  // 头部区域
    return rva - m_Sections[idx].header.VirtualAddress + m_Sections[idx].header.PointerToRawData;
}

DWORD PeParser::FileOffsetToRva(DWORD offset) const
{
    for (const auto& sec : m_Sections)
    {
        if (offset >= sec.header.PointerToRawData &&
            offset < sec.header.PointerToRawData + sec.header.SizeOfRawData)
        {
            return offset - sec.header.PointerToRawData + sec.header.VirtualAddress;
        }
    }
    return offset;
}

BYTE* PeParser::GetPtrFromRva(DWORD rva)
{
    int idx = RvaToSectionIndex(rva);
    if (idx < 0 || !m_Sections[idx].data)
        return nullptr;

    DWORD offset = rva - m_Sections[idx].header.VirtualAddress;
    if (offset >= m_Sections[idx].dataSize)
        return nullptr;

    return m_Sections[idx].data + offset;
}

// ============================================================================
// 从进程内存读取所有节数据
// ============================================================================

bool PeParser::ReadSectionsFromProcess()
{
    if (!m_Valid || !m_Client)
        return false;

    DBG_LOG(L"[DBG] ReadSections: %u 个节, 基址=0x%llX\n",
            (unsigned)m_Sections.size(), (unsigned long long)m_ModuleBase);

    int secIdx = 0;
    for (auto& sec : m_Sections)
    {
        delete[] sec.data;
        sec.data = nullptr;
        sec.dataSize = 0;

        DWORD readSize = sec.header.Misc.VirtualSize;
        if (readSize == 0)
            readSize = sec.header.SizeOfRawData;
        if (readSize == 0)
        {
            DBG_LOG(L"[DBG]   节[%d] %-8.8S: VirtSize=0, RawSize=0, 跳过\n",
                    secIdx++, sec.header.Name);
            continue;
        }

        // 限制单节大小
        if (readSize > 100000000)
            readSize = 100000000;

        sec.data = new BYTE[readSize];
        memset(sec.data, 0, readSize);
        sec.dataSize = readSize;

        SIZE_T bytesRead = 0;
        DWORD_PTR sectionVa = m_ModuleBase + sec.header.VirtualAddress;

        // Scylla 兼容: 先尝试完整读取 (MmCopyVirtualMemory 直接读取),
        // 失败则回退到按区域部分读取 (ZwQueryVirtualMemory + MmCopyVirtualMemory)
        bool readOk = m_Client->ReadMemory(sectionVa, readSize, sec.data, &bytesRead);
        if (!readOk || bytesRead != readSize)
        {
            DBG_LOG(L"[DBG]   节[%d] %-8.8S: ReadMemory %s (read=0x%llX/0x%X), 回退Partial\n",
                    secIdx, sec.header.Name,
                    readOk ? L"短读" : L"失败",
                    (unsigned long long)bytesRead, readSize);
            // 完整读取失败 (可能有未提交页面), 重置缓冲区后用 Partial 读取
            memset(sec.data, 0, readSize);
            bytesRead = 0;
            bool partialOk = m_Client->ReadMemoryPartial(sectionVa, readSize, sec.data, &bytesRead);
            DBG_LOG(L"[DBG]   节[%d] %-8.8S: Partial %s (read=0x%llX/0x%X)\n",
                    secIdx, sec.header.Name,
                    partialOk ? L"成功" : L"失败",
                    (unsigned long long)bytesRead, readSize);
        }
        else
        {
            DBG_LOG(L"[DBG]   节[%d] %-8.8S: VA=0x%X 读取成功 0x%X 字节\n",
                    secIdx, sec.header.Name,
                    sec.header.VirtualAddress, readSize);
        }
        secIdx++;
    }

    return true;
}

// ============================================================================
// 从文件读取所有节数据
// ============================================================================

bool PeParser::ReadSectionsFromFile()
{
    if (!m_Valid || m_FilePath.empty())
        return false;

    HANDLE hFile = CreateFileW(m_FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    for (auto& sec : m_Sections)
    {
        delete[] sec.data;
        sec.data = nullptr;
        sec.dataSize = 0;

        if (sec.header.SizeOfRawData == 0 || sec.header.PointerToRawData == 0)
            continue;

        DWORD readSize = sec.header.SizeOfRawData;
        if (readSize > 100000000)
            readSize = 100000000;

        sec.data = new BYTE[readSize];
        memset(sec.data, 0, readSize);
        sec.dataSize = readSize;

        SetFilePointer(hFile, sec.header.PointerToRawData, NULL, FILE_BEGIN);
        DWORD bytesRead = 0;
        ReadFile(hFile, sec.data, readSize, &bytesRead, NULL);
    }

    CloseHandle(hFile);
    return true;
}

// ============================================================================
// 添加新节
// ============================================================================

bool PeParser::AddSection(const char* name, DWORD virtualSize, DWORD characteristics)
{
    if (!m_Valid)
        return false;

    PeSection newSec = {};
    memset(&newSec.header, 0, sizeof(IMAGE_SECTION_HEADER));

    // 节名
    size_t nameLen = strlen(name);
    if (nameLen > IMAGE_SIZEOF_SHORT_NAME)
        nameLen = IMAGE_SIZEOF_SHORT_NAME;
    memcpy(newSec.header.Name, name, nameLen);

    // 计算VirtualAddress: 紧接最后一个节之后
    DWORD sectionAlignment = GetSectionAlignment();
    if (!m_Sections.empty())
    {
        const auto& lastSec = m_Sections.back();
        DWORD lastEnd = lastSec.header.VirtualAddress +
            AlignValue((std::max)(lastSec.header.Misc.VirtualSize, lastSec.header.SizeOfRawData),
                       sectionAlignment);
        newSec.header.VirtualAddress = lastEnd;
    }
    else
    {
        newSec.header.VirtualAddress = AlignValue(GetSizeOfHeaders(), sectionAlignment);
    }

    newSec.header.Misc.VirtualSize = virtualSize;
    newSec.header.SizeOfRawData = AlignValue(virtualSize, GetFileAlignment());
    newSec.header.Characteristics = characteristics;

    // 分配数据
    newSec.data = new BYTE[newSec.header.SizeOfRawData];
    memset(newSec.data, 0, newSec.header.SizeOfRawData);
    newSec.dataSize = newSec.header.SizeOfRawData;

    m_Sections.push_back(newSec);

    // 更新FileHeader.NumberOfSections
    m_pNtHeader32->FileHeader.NumberOfSections = (WORD)m_Sections.size();

    // 更新SizeOfImage
    DWORD newSizeOfImage = newSec.header.VirtualAddress +
        AlignValue(virtualSize, sectionAlignment);
    SetSizeOfImage(newSizeOfImage);

    return true;
}

// ============================================================================
// 修改PE头
// ============================================================================

void PeParser::SetEntryPoint(DWORD_PTR rva)
{
    if (!m_Valid) return;
    if (m_Is64)
        m_pNtHeader64->OptionalHeader.AddressOfEntryPoint = (DWORD)rva;
    else
        m_pNtHeader32->OptionalHeader.AddressOfEntryPoint = (DWORD)rva;
}

void PeParser::SetSizeOfImage(DWORD size)
{
    if (!m_Valid) return;
    if (m_Is64)
        m_pNtHeader64->OptionalHeader.SizeOfImage = size;
    else
        m_pNtHeader32->OptionalHeader.SizeOfImage = size;
}

// ============================================================================
// 对齐
// ============================================================================

DWORD PeParser::AlignValue(DWORD value, DWORD alignment) const
{
    if (alignment == 0) return value;
    DWORD remainder = value % alignment;
    if (remainder == 0) return value;
    return value + alignment - remainder;
}

void PeParser::AlignAllSectionHeaders()
{
    if (!m_Valid) return;

    DWORD fileAlignment = GetFileAlignment();

    // 设置默认文件对齐
    if (fileAlignment == 0) fileAlignment = 0x200;

    DWORD fileOffset = AlignValue(GetSizeOfHeaders(), fileAlignment);

    for (auto& sec : m_Sections)
    {
        sec.header.PointerToRawData = fileOffset;

        if (sec.dataSize > 0)
        {
            sec.header.SizeOfRawData = AlignValue(sec.dataSize, fileAlignment);
        }

        fileOffset += sec.header.SizeOfRawData;
    }
}

void PeParser::FixPeHeader()
{
    if (!m_Valid) return;

    // 更新SizeOfImage
    if (!m_Sections.empty())
    {
        const auto& lastSec = m_Sections.back();
        DWORD sectionAlignment = GetSectionAlignment();
        DWORD newSizeOfImage = lastSec.header.VirtualAddress +
            AlignValue((std::max)(lastSec.header.Misc.VirtualSize, lastSec.header.SizeOfRawData),
                       sectionAlignment);
        SetSizeOfImage(newSizeOfImage);
    }

    // 清除绑定导入目录
    SetDataDirectory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0, 0);
}

// ============================================================================
// 保存到文件
// ============================================================================

bool PeParser::SaveToFile(const WCHAR* filePath)
{
    if (!m_Valid) return false;

    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] SaveToFile: CreateFile 失败, error=%lu\n", GetLastError());
        return false;
    }

    DWORD written = 0;

    // 同步m_Sections回pSectionHeaders (因为可能添加了新节)
    WORD numSections = (WORD)m_Sections.size();
    DWORD headerSize = GetSizeOfHeaders();
    DWORD fileAlignment = GetFileAlignment();
    DWORD alignedHeaderSize = AlignValue(headerSize, fileAlignment);

    DBG_LOG(L"[DBG] SaveToFile: numSections=%u, SizeOfHeaders=0x%X, FileAlign=0x%X, alignedHeaders=0x%X\n",
            numSections, headerSize, fileAlignment, alignedHeaderSize);

    // 将节头写回HeaderBuffer
    BYTE* secHeaderPos = (BYTE*)m_pSectionHeaders;
    for (WORD i = 0; i < numSections; i++)
    {
        memcpy(secHeaderPos + i * sizeof(IMAGE_SECTION_HEADER),
               &m_Sections[i].header, sizeof(IMAGE_SECTION_HEADER));
    }

    // 写PE头 (对齐到文件对齐)
    DWORD headersToWrite = (std::min)((DWORD)sizeof(m_HeaderBuffer), alignedHeaderSize);
    BOOL writeOk = WriteFile(hFile, m_HeaderBuffer, headersToWrite, &written, NULL);
    DBG_LOG(L"[DBG] SaveToFile: 写PE头 %u 字节, written=%u, ok=%d\n",
            headersToWrite, written, writeOk);

    // 如果对齐后头更大，填充零
    if (alignedHeaderSize > headersToWrite)
    {
        DWORD padSize = alignedHeaderSize - headersToWrite;
        BYTE* pad = new BYTE[padSize];
        memset(pad, 0, padSize);
        WriteFile(hFile, pad, padSize, &written, NULL);
        delete[] pad;
    }

    // 写所有节数据
    DWORD totalFileSize = alignedHeaderSize;
    for (int si = 0; si < (int)m_Sections.size(); si++)
    {
        const auto& sec = m_Sections[si];
        DWORD fileOffset = sec.header.PointerToRawData;
        SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

        if (sec.data && sec.dataSize > 0)
        {
            writeOk = WriteFile(hFile, sec.data, sec.dataSize, &written, NULL);
            DBG_LOG(L"[DBG]   写节[%d] %-8.8S: offset=0x%X, dataSize=0x%X, written=%u, ok=%d\n",
                    si, sec.header.Name, fileOffset, sec.dataSize, written, writeOk);
            if (!writeOk)
            {
                wprintf(L"[-] WriteFile 失败! error=%lu\n", GetLastError());
            }

            DWORD secFileEnd = fileOffset + sec.header.SizeOfRawData;
            if (secFileEnd > totalFileSize) totalFileSize = secFileEnd;

            // 填充到SizeOfRawData
            if (sec.header.SizeOfRawData > sec.dataSize)
            {
                DWORD padSize = sec.header.SizeOfRawData - sec.dataSize;
                BYTE* pad = new BYTE[padSize];
                memset(pad, 0, padSize);
                WriteFile(hFile, pad, padSize, &written, NULL);
                delete[] pad;
            }
        }
        else if (sec.header.SizeOfRawData > 0)
        {
            // 空节，写零
            BYTE* pad = new BYTE[sec.header.SizeOfRawData];
            memset(pad, 0, sec.header.SizeOfRawData);
            writeOk = WriteFile(hFile, pad, sec.header.SizeOfRawData, &written, NULL);
            DBG_LOG(L"[DBG]   写节[%d] %-8.8S: offset=0x%X, zeroFill=0x%X, written=%u, ok=%d\n",
                    si, sec.header.Name, fileOffset, sec.header.SizeOfRawData, written, writeOk);
            delete[] pad;

            DWORD secFileEnd = fileOffset + sec.header.SizeOfRawData;
            if (secFileEnd > totalFileSize) totalFileSize = secFileEnd;
        }
        else
        {
            DBG_LOG(L"[DBG]   节[%d] %-8.8S: data=%p, dataSize=%u, rawSize=0x%X, 无数据\n",
                    si, sec.header.Name, sec.data, sec.dataSize, sec.header.SizeOfRawData);
        }
    }

    // 验证最终文件大小
    DWORD actualSize = GetFileSize(hFile, NULL);
    DBG_LOG(L"[DBG] SaveToFile: 期望大小=0x%X (%u KB), 实际大小=0x%X (%u KB)\n",
            totalFileSize, totalFileSize / 1024, actualSize, actualSize / 1024);

    CloseHandle(hFile);
    return true;
}

// ============================================================================
// DumpProcess - 完整进程模块转存
// ============================================================================

bool PeParser::DumpProcess(DWORD_PTR /*moduleBase*/, DWORD_PTR entryPoint, const WCHAR* outputPath)
{
    if (!m_Valid || !m_Client)
        return false;

    // 读取所有节
    if (!ReadSectionsFromProcess())
        return false;

    // 设置入口点
    SetEntryPoint(entryPoint);

    // 对齐节头
    AlignAllSectionHeaders();

    // 修复PE头
    FixPeHeader();

    // 保存
    return SaveToFile(outputPath);
}

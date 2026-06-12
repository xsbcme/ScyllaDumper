#pragma once

//
// PeParser.h - PE文件解析与操作
//
// 支持从进程内存和磁盘文件两种方式解析PE。
// 提供节表操作、RVA转换、数据目录解析等功能。
//

#include <Windows.h>
#include <vector>
#include <string>

// PE节信息
struct PeSection
{
    IMAGE_SECTION_HEADER    header;
    BYTE*                   data;       // 节数据 (堆分配)
    DWORD                   dataSize;   // 实际数据大小
};

class DumperClient;  // 前向声明

class PeParser
{
public:
    // 从进程内存解析 (通过DumperClient读取)
    PeParser(DumperClient* client, DWORD_PTR moduleBase);

    // 从磁盘文件解析
    PeParser(const WCHAR* filePath);

    ~PeParser();

    // 禁止拷贝
    PeParser(const PeParser&) = delete;
    PeParser& operator=(const PeParser&) = delete;

    // ---- 基本信息 ----
    bool IsValid() const { return m_Valid; }
    bool Is64Bit() const { return m_Is64; }
    DWORD_PTR GetModuleBase() const { return m_ModuleBase; }

    // PE头信息
    DWORD GetSizeOfImage() const;
    DWORD GetSizeOfHeaders() const;
    DWORD_PTR GetEntryPoint() const;        // RVA
    DWORD_PTR GetImageBase() const;
    DWORD GetFileAlignment() const;
    DWORD GetSectionAlignment() const;
    WORD GetNumberOfSections() const;

    // ---- 数据目录 ----
    IMAGE_DATA_DIRECTORY GetDataDirectory(DWORD index) const;
    void SetDataDirectory(DWORD index, DWORD rva, DWORD size);

    // ---- 节操作 ----
    const std::vector<PeSection>& GetSections() const { return m_Sections; }

    // 从进程内存读取所有节数据
    bool ReadSectionsFromProcess();

    // 从文件读取所有节数据
    bool ReadSectionsFromFile();

    // 添加新节
    bool AddSection(const char* name, DWORD virtualSize, DWORD characteristics);

    // ---- RVA/偏移转换 ----
    int RvaToSectionIndex(DWORD rva) const;
    DWORD RvaToFileOffset(DWORD rva) const;
    DWORD FileOffsetToRva(DWORD offset) const;

    // 获取节数据中的指针 (通过RVA)
    BYTE* GetPtrFromRva(DWORD rva);

    // ---- 修改PE头 ----
    void SetEntryPoint(DWORD_PTR rva);
    void SetSizeOfImage(DWORD size);

    // ---- 保存/对齐 ----
    void AlignAllSectionHeaders();
    void FixPeHeader();
    bool SaveToFile(const WCHAR* filePath);

    // ---- 转存 ----
    // 完整的进程模块转存
    bool DumpProcess(DWORD_PTR moduleBase, DWORD_PTR entryPoint, const WCHAR* outputPath);

    // PE头原始数据 (供外部使用)
    PIMAGE_NT_HEADERS32 GetNtHeaders32() const { return m_pNtHeader32; }
    PIMAGE_NT_HEADERS64 GetNtHeaders64() const { return m_pNtHeader64; }

private:
    bool ParseHeaders(const BYTE* headerData, DWORD headerSize);
    DWORD AlignValue(DWORD value, DWORD alignment) const;

    DumperClient*   m_Client;           // 进程内存读取 (可为null)
    DWORD_PTR       m_ModuleBase;       // 模块基址
    bool            m_Valid;
    bool            m_Is64;
    bool            m_FromFile;         // 是否从文件加载

    // PE头数据
    BYTE            m_HeaderBuffer[0x1000];  // 足够容纳大多数PE头
    IMAGE_DOS_HEADER*       m_pDosHeader;
    IMAGE_NT_HEADERS32*     m_pNtHeader32;
    IMAGE_NT_HEADERS64*     m_pNtHeader64;
    IMAGE_SECTION_HEADER*   m_pSectionHeaders;

    // 节数据
    std::vector<PeSection>  m_Sections;

    // 文件路径 (磁盘模式)
    std::wstring    m_FilePath;
};

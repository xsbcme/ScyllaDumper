#pragma once

//
// DumperClientDetail.h - 仅实现文件使用：驱动/用户层共享的类型与工具
//

#include <Windows.h>
#include <winternl.h>

#ifndef ProcessBasicInformation
#define ProcessBasicInformation static_cast<PROCESSINFOCLASS>(0)
#endif

typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);

typedef struct _PEB_PARTIAL_X64
{
    BYTE        Reserved0[0x10];
    ULONGLONG   ImageBaseAddress;
} PEB_PARTIAL_X64;

typedef struct _PROCESS_BASIC_INFORMATION_TINY
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_TINY;

inline NTSTATUS Win32ToPseudoNtStatus(DWORD err)
{
    if (err == ERROR_SUCCESS)
    {
        return 0;
    }
    return static_cast<NTSTATUS>(0xC0000000u | (err & 0xFFFFu));
}

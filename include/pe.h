#pragma once

#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>

LPBYTE OpenReadFile(LPCWSTR lpFileName, PDWORD pdwFileSize) {
    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening a file" << std::endl;
        ExitProcess(-1);
    }

    *pdwFileSize = GetFileSize(hFile, nullptr);
    if (*pdwFileSize == INVALID_FILE_SIZE) {
        std::cerr << "Failed to get file size" << std::endl;
        CloseHandle(hFile);
        ExitProcess(-1);
    }

    LPVOID lpFileBuf = VirtualAlloc(NULL, *pdwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (ReadFile(hFile, lpFileBuf, *pdwFileSize, NULL, NULL) == NULL) {
        std::cerr << "Failed to read a file" << std::endl;
        CloseHandle(hFile);
        ExitProcess(-1);
    }

    return (LPBYTE)lpFileBuf;
}

LPBYTE OpenReadFileA(LPCSTR lpFileName, PDWORD pdwFileSize) {
    HANDLE hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening a file" << std::endl;
        ExitProcess(-1);
    }

    *pdwFileSize = GetFileSize(hFile, nullptr);
    if (*pdwFileSize == INVALID_FILE_SIZE) {
        std::cerr << "Failed to get file size" << std::endl;
        CloseHandle(hFile);
        ExitProcess(-1);
    }

    LPVOID lpFileBuf = VirtualAlloc(NULL, *pdwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (ReadFile(hFile, lpFileBuf, *pdwFileSize, NULL, NULL) == NULL) {
        std::cerr << "Failed to read a file" << std::endl;
        CloseHandle(hFile);
        ExitProcess(-1);
    }

    return (LPBYTE)lpFileBuf;
}

PPEB GetLocalPeb()
{
    HANDLE hProcess = GetCurrentProcess();

    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    DWORD dwReturnLength = 0;

    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return 0;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");

    if (!fpNtQueryInformationProcess)
        return 0;

    typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
        );

    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

    ntQueryInformationProcess(hProcess, ProcessBasicInformation, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    return pBasicInfo->PebBaseAddress;
}

PPEB GetRemotePeb(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    DWORD dwReturnLength = 0;

    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return 0;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");

    if (!fpNtQueryInformationProcess)
        return 0;

    typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
        );

    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

    ntQueryInformationProcess(hProcess, ProcessBasicInformation, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    return pBasicInfo->PebBaseAddress;
}

VOID GetPeHeaders(LPBYTE lpImage
    , PIMAGE_DOS_HEADER* ppDOSHeader
    , PIMAGE_NT_HEADERS64* ppNTHeaders
    , PIMAGE_FILE_HEADER* ppFileHeader
    , PIMAGE_OPTIONAL_HEADER64* ppOptHeader
    , PIMAGE_SECTION_HEADER* paSecHeaders
) {
    PIMAGE_DOS_HEADER        pDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS64      pNTHeaders = (PIMAGE_NT_HEADERS64)(lpImage + pDOSHeader->e_lfanew);
    PIMAGE_FILE_HEADER       pFileHeader = &pNTHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER64 pOptHeader = &pNTHeaders->OptionalHeader;
    // Note: section headers reside right after an optional header
    PIMAGE_SECTION_HEADER    aSecHeaders = (PIMAGE_SECTION_HEADER)((DWORDLONG)pOptHeader + pFileHeader->SizeOfOptionalHeader);

    if (ppDOSHeader)  *ppDOSHeader = pDOSHeader;
    if (ppNTHeaders)  *ppNTHeaders = pNTHeaders;
    if (ppFileHeader) *ppFileHeader = pFileHeader;
    if (ppOptHeader)  *ppOptHeader = pOptHeader;
    if (paSecHeaders) *paSecHeaders = aSecHeaders;
}

VOID GetRemotePeHeaders(
    HANDLE hProcess,
    LPBYTE lpImage,
    PIMAGE_DOS_HEADER* ppDosHeader,
    PIMAGE_NT_HEADERS64* ppNtHeaders,
    PIMAGE_FILE_HEADER* ppFileHeader,
    PIMAGE_OPTIONAL_HEADER64* ppOptHeader,
    PIMAGE_SECTION_HEADER* paSecHeaders
) {
    PIMAGE_DOS_HEADER        pDosHeader  = (PIMAGE_DOS_HEADER)lpImage;

    PIMAGE_NT_HEADERS64      pNtHeaders  = (PIMAGE_NT_HEADERS64)(lpImage + pDosHeader->e_lfanew);

    PIMAGE_FILE_HEADER       pFileHeader = (PIMAGE_FILE_HEADER)((LPBYTE)pNtHeaders + offsetof(IMAGE_NT_HEADERS64, FileHeader));
    PIMAGE_OPTIONAL_HEADER64 pOptHeader = &pNtHeaders->OptionalHeader;
    // Note: section headers reside right after an optional header
    PIMAGE_SECTION_HEADER    aSecHeaders = (PIMAGE_SECTION_HEADER)((DWORDLONG)pOptHeader + pFileHeader->SizeOfOptionalHeader);

    if (ppDosHeader)  *ppDosHeader  = pDosHeader;
    if (ppNtHeaders)  *ppNtHeaders  = pNtHeaders;
    if (ppFileHeader) *ppFileHeader = pFileHeader;
    if (ppOptHeader)  *ppOptHeader = pOptHeader;
    if (paSecHeaders) *paSecHeaders = aSecHeaders;
}

// Calculate how much space is needed to align a section by 'ceil'ing it
DWORD align(DWORD cbSection, DWORD step) {
    return cbSection % step == 0 ? cbSection : (cbSection / step + 1) * step;
}

PIMAGE_SECTION_HEADER GetAvailableSectionHeaderEntry(PIMAGE_SECTION_HEADER pSecHeaders) {
    PIMAGE_SECTION_HEADER p = pSecHeaders;
    // TODO: Add range check against SizeOfHeaders
    while (*(p->Name) == '.') p++;
    return p;
}

PIMAGE_SECTION_HEADER GetSectionHeaderPointerByName(PIMAGE_SECTION_HEADER pSecHeaders, LPCSTR sSectionName) {
    for (PIMAGE_SECTION_HEADER p = pSecHeaders; *(p->Name); p++) {
        if (strcmp((char*)p->Name, sSectionName) == 0) {
            return p;
        }
    }
    return nullptr;
}

/**
 * Add a new section to a given PE file image
 * Returns a pointer to the PE file
 *
 * TODO: Handle the case where availble slots in section headers exhaust
 */
DWORD AddSection(HANDLE  hPE      /* Handle to the heap */
    , LPBYTE lpPe      /* Pointer to a PE file */
    , DWORD  cbPe
    , LPVOID lpSection
    , DWORD  cbSection /* The size of section about to be written */
    , PCHAR pszSecName
    , DWORD  Character
) {
    PIMAGE_DOS_HEADER        pDOSHeader;
    PIMAGE_NT_HEADERS64      pNTHeaders;
    PIMAGE_FILE_HEADER       pFileHeader;
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    PIMAGE_SECTION_HEADER    aSecHeaders;
    GetPeHeaders(lpPe, &pDOSHeader, &pNTHeaders, &pFileHeader, &pOptHeader, &aSecHeaders);

    pFileHeader->NumberOfSections++;

    PIMAGE_SECTION_HEADER pSecHeader = GetAvailableSectionHeaderEntry(aSecHeaders);
    strcpy_s((char*)pSecHeader->Name, 8, pszSecName);
    // ???: Still unknown what should be written here
    pSecHeader->Misc.VirtualSize = cbSection;
    pSecHeader->VirtualAddress = align(pOptHeader->SizeOfImage, pOptHeader->SectionAlignment);
    pSecHeader->SizeOfRawData = align(cbSection, pOptHeader->FileAlignment);
    pSecHeader->PointerToRawData = cbPe;
    pSecHeader->PointerToRelocations = 0;
    pSecHeader->PointerToLinenumbers = 0;
    pSecHeader->NumberOfRelocations = 0;
    pSecHeader->NumberOfLinenumbers = 0;
    pSecHeader->Characteristics = Character;

    HeapReAlloc(hPE, HEAP_GENERATE_EXCEPTIONS | HEAP_REALLOC_IN_PLACE_ONLY | HEAP_ZERO_MEMORY, lpPe, cbPe + align(cbSection, pOptHeader->FileAlignment));
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORDLONG)lpPe + cbPe), lpSection, cbPe + align(cbSection, pOptHeader->FileAlignment), 0);

    pOptHeader->NumberOfRvaAndSizes++;
    pOptHeader->SizeOfImage += align(cbSection, pOptHeader->SectionAlignment);

    return cbPe + align(cbSection, pOptHeader->FileAlignment);
}

PIMAGE_SECTION_HEADER FindSectionHeaderFromVA(LPBYTE lpPe, PIMAGE_SECTION_HEADER aSecHeaders, DWORD dwVA) {
    for (PIMAGE_SECTION_HEADER p = aSecHeaders; *(p->Name); p++) {
        if (p->VirtualAddress <= dwVA and dwVA < p->VirtualAddress + p->SizeOfRawData) {
            return p;
        }
    }
    return nullptr;
}

PIMAGE_IMPORT_DESCRIPTOR GetImportDirectoryTable(LPBYTE lpPe, PIMAGE_OPTIONAL_HEADER64 pOptHeader, LONG lpad = 0) {
    PIMAGE_IMPORT_DESCRIPTOR pIDT = (PIMAGE_IMPORT_DESCRIPTOR)(lpPe + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - lpad);
    return pIDT;
}

PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptorByDLLName(PIMAGE_IMPORT_DESCRIPTOR pIDT, LPCSTR szName) {
    PIMAGE_IMPORT_DESCRIPTOR pd = pIDT;

    while (pd->OriginalFirstThunk) {
        if (strcmp((char*)pd->Name, szName) == 0) return pd;

        pd++;
    }

    return nullptr;
}

/**
 * Read IAT of an imported DLL in a map
 * Import Address Table (IAT) contains addresses of functions.
 * To determine whose address each is, we need to read Import Lookup Table (ILT),
 * solve and seek for a name and calculate the offset from the first thunk.
 * As this offset is common with IAT and ILT, we can successfully correlate
 * a function name and its address
 */
std::map</* DLL name */ std::string, std::map</* name */ std::string, /* address */ ULONGLONG>>
ReadImportAddressTable(
    LPBYTE lpPe
) {
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    GetPeHeaders(lpPe, 0, 0, 0, &pOptHeader, 0);

    PIMAGE_IMPORT_DESCRIPTOR pIdt = GetImportDirectoryTable(lpPe, pOptHeader);

    // PIMAGE_IMPORT_DESCRIPTOR pd = GetImportDescriptorByDLLName(pIdt, szName);

    // Result
    std::map</* DLL name */ std::string, std::map</* name */ std::string, /* address */ ULONGLONG>> mIat;

    // Iterate through DLLs
    PIMAGE_IMPORT_DESCRIPTOR pd = pIdt;
    while (pd->OriginalFirstThunk) {
        LPSTR szDllName = (LPSTR)(lpPe + pd->Name);

        mIat[szDllName] = std::map<std::string, ULONGLONG>();

        PIMAGE_THUNK_DATA64 pIlt = (PIMAGE_THUNK_DATA64)(lpPe + pd->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 pIat = (PIMAGE_THUNK_DATA64)(lpPe + pd->FirstThunk);

        // Iterate through functions
        while (pIlt->u1.AddressOfData and pIat->u1.AddressOfData) {
            ULONGLONG lpFunctionAddr = pIat->u1.AddressOfData;

            // std::cout << "Ordinal: " << std::bitset<64>(pIlt->u1.Ordinal) << std::endl;
            // Use ordinal
            if (pIlt->u1.Ordinal >> 63 == 1) {
                DWORD dwOrdinal = pIlt->u1.Ordinal & 0xffff;
                // std::cout << "  Ordinal_" << dwOrdinal << std::endl;
                mIat[szDllName]["Ordinal_" + std::to_string(dwOrdinal)] = lpFunctionAddr;

                pIlt++;
                pIat++;
                continue;
            }

            LPCSTR szFunctionName = ((PIMAGE_IMPORT_BY_NAME)(lpPe + pIlt->u1.AddressOfData))->Name;

            mIat[szDllName][szFunctionName] = lpFunctionAddr;

            pIlt++;
            pIat++;
        }

        pd++;
    }

    return mIat;
}

std::map</* DLL name */ std::string, std::map</* name */ std::string, /* address */ ULONGLONG>>
ReadRemoteImportAddressTable(
    HANDLE hProcess,
    LPBYTE lpImage,
    LPBYTE lpBuf)
{
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    GetPeHeaders(lpBuf, 0, 0, 0, &pOptHeader, 0);

    PIMAGE_IMPORT_DESCRIPTOR pIdt = GetImportDirectoryTable(lpBuf, pOptHeader);

    // Result
    std::map</* DLL name */ std::string, std::map</* name */ std::string, /* address */ ULONGLONG>> table;

    // Iterate through DLLs
    PIMAGE_IMPORT_DESCRIPTOR pd = pIdt;
    while (pd->OriginalFirstThunk) {
        LPSTR szDllName = (LPSTR)(lpBuf + pd->Name);

        PIMAGE_THUNK_DATA64 pIlt = (PIMAGE_THUNK_DATA64)(lpBuf + pd->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 pIat = (PIMAGE_THUNK_DATA64)(lpBuf + pd->FirstThunk);

        // Iterate through functions
        while (pIlt->u1.AddressOfData and pIat->u1.AddressOfData) {
            ULONGLONG lpFunctionAddr = pIat->u1.AddressOfData;

            LPSTR szFunctionName;

            // Ordinal
            if (pIlt->u1.Ordinal >> 63 == 1) {
                DWORD dwOrdinal = pIlt->u1.Ordinal & 0xffff;
                szFunctionName = (LPSTR)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                strcpy_s(szFunctionName, 8, "Ordinal_");
                sprintf_s(szFunctionName, 10, "%u", dwOrdinal);
            }
            else {
                szFunctionName = ((PIMAGE_IMPORT_BY_NAME)(lpBuf + pIlt->u1.AddressOfData))->Name;
            }

            table[szDllName][szFunctionName] = lpFunctionAddr;

            pIlt++;
            pIat++;
        }

        pd++;
    }

    return table;
}

// https://0xrick.github.io/win-internals/pe6/
std::map</* DLL name */ std::string, std::map</* name */ std::string, /* address */ ULONGLONG>>
ReadImportLookupTableFromRaw(
    LPBYTE lpPe
) {
    // Read these headers
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    PIMAGE_SECTION_HEADER aSecHeaders;
    GetPeHeaders(lpPe, NULL, NULL, NULL, &pOptHeader, &aSecHeaders);

    DWORD dwDirVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    // Find which section contains the address of the import directory
    PIMAGE_SECTION_HEADER pHeader = FindSectionHeaderFromVA(lpPe, aSecHeaders, dwDirVA);
    if (not pHeader) {
        return std::map<std::string, std::map<std::string, ULONGLONG>>();
    }
    // FIXME: We assume SectionAlignment was 0x1000 here
    LONG ipad = 0x1000;
    ipad = pHeader->VirtualAddress - pHeader->PointerToRawData;

    //PIMAGE_SECTION_HEADER pTextHeader = GetSectionHeaderPointerByName(aSecHeaders, ".text");
    //if (pTextHeader) {
    //  ipad = pTextHeader->VirtualAddress - pTextHeader->PointerToRawData;
    //}
    //PIMAGE_SECTION_HEADER pRdataHeader = GetSectionHeaderPointerByName(aSecHeaders, ".rdata");
    //if (pRdataHeader) {
    //  ipad = pRdataHeader->VirtualAddress - pRdataHeader->PointerToRawData;
    //}
    //PIMAGE_SECTION_HEADER pIdataHeader = GetSectionHeaderPointerByName(aSecHeaders, ".idata");
    //if (pIdataHeader) {
    //  ipad = pIdataHeader->VirtualAddress - pIdataHeader->PointerToRawData;
    //}

    // Result
    std::map<std::string, std::map<std::string, ULONGLONG>> table;

    PIMAGE_IMPORT_DESCRIPTOR pIdt = GetImportDirectoryTable(lpPe, pOptHeader, ipad);

    // Iterate through DLLs
    PIMAGE_IMPORT_DESCRIPTOR pd = pIdt;
    while (pd->OriginalFirstThunk) {
        LPSTR szDllName = (LPSTR)(lpPe + pd->Name - ipad);

        table[szDllName] = std::map<std::string, ULONGLONG>();

        PIMAGE_THUNK_DATA64 pIlt = (PIMAGE_THUNK_DATA64)(lpPe + pd->OriginalFirstThunk - ipad);
        PIMAGE_THUNK_DATA64 pIat = (PIMAGE_THUNK_DATA64)(lpPe + pd->FirstThunk - ipad);

        // Iterate through functions
        while (pIlt->u1.AddressOfData and pIat->u1.AddressOfData) {
            // NOTICE: The contents of IAT are just same as ILT in a raw data
            ULONGLONG lpFunctionAddr = pIat->u1.AddressOfData;

            // std::cout << "Ordinal: " << std::bitset<64>(pIlt->u1.Ordinal) << std::endl;
            // Use ordinal
            if (pIlt->u1.Ordinal >> 63 == 1) {
                DWORD dwOrdinal = pIlt->u1.Ordinal & 0xffff;
                // std::cout << "  Ordinal_" << dwOrdinal << std::endl;
                table[szDllName]["Ordinal_" + std::to_string(dwOrdinal)] = lpFunctionAddr;

                pIlt++;
                pIat++;
                continue;
            }

            LPCSTR szFunctionName = ((PIMAGE_IMPORT_BY_NAME)(lpPe + pIlt->u1.AddressOfData - ipad))->Name;
            // std::cout << "  " << szFunctionName << std::endl;

            table[szDllName][szFunctionName] = lpFunctionAddr;

            pIlt++;
            pIat++;
        }

        pd++;
    }

    return table;
}

// Patch an IAT entry of a remote process
// This can be implemented with ReadProcessMemory and offsetof
// but it'd require huge refactoring effort
VOID PatchRemoteIatEntryByName(
    HANDLE hProcess,
    LPBYTE lpImage,
    LPBYTE lpBuf,
    LPCSTR szTargetName,
    LPBYTE lpTramp)
{
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    GetPeHeaders(lpBuf, 0, 0, 0, &pOptHeader, 0);

    PIMAGE_IMPORT_DESCRIPTOR pIdt = GetImportDirectoryTable(lpBuf, pOptHeader);

    // Iterate through DLLs
    PIMAGE_IMPORT_DESCRIPTOR pd = pIdt;
    while (pd->OriginalFirstThunk) {
        LPSTR szDllName = (LPSTR)(lpBuf + pd->Name);

        PIMAGE_THUNK_DATA64 pIlt = (PIMAGE_THUNK_DATA64)(lpBuf + pd->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 pIat = (PIMAGE_THUNK_DATA64)(lpBuf + pd->FirstThunk);

        // Iterate through functions
        while (pIlt->u1.AddressOfData and pIat->u1.AddressOfData) {
            ULONGLONG lpFunctionAddr = pIat->u1.AddressOfData;

            LPSTR szFunctionName;

            // Ordinal
            if (pIlt->u1.Ordinal >> 63 == 1) {
                DWORD dwOrdinal = pIlt->u1.Ordinal & 0xffff;
                szFunctionName = (LPSTR)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                strcpy_s(szFunctionName, 8, "Ordinal_");
                sprintf_s(szFunctionName, 10, "%u", dwOrdinal);
            }
            else {
                szFunctionName = ((PIMAGE_IMPORT_BY_NAME)(lpBuf + pIlt->u1.AddressOfData))->Name;
            }

            if (strcmp(szFunctionName, szTargetName) == 0) {
                std::cout << szTargetName << " found!" << std::endl;

                // The address of the IAT entry in the remote process
                PIMAGE_THUNK_DATA64 pImageIat = (PIMAGE_THUNK_DATA64)(lpImage + ((LPBYTE)pIat - lpBuf));

                std::cout << "Now patching 0x" << std::hex << pImageIat << std::endl;

                ULONGLONG addr;
                ReadProcessMemory(hProcess, (LPBYTE)pImageIat, &addr, 8, NULL);
                std::cout << "Original address: 0x" << std::hex << (ULONGLONG)addr << std::endl;

                DWORD oldProtect = 0;
                VirtualProtectEx(hProcess, (LPVOID)pImageIat, 8, PAGE_READWRITE, &oldProtect);

                // Patch
                if (WriteProcessMemory(hProcess, (LPBYTE)pImageIat, &lpTramp, 8, NULL) == 0) {
                    std::cout << "WriteProcessMemory failed" << std::endl;
                }

                return;
            }

            pIlt++;
            pIat++;
        }

        pd++;
    }
}

VOID PatchLocalIatEntryByHash(
    LPBYTE lpImage,
    DWORD  dwTargetHash,
    LPBYTE lpTramp)
{
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    GetPeHeaders(lpImage, 0, 0, 0, &pOptHeader, 0);

    PIMAGE_IMPORT_DESCRIPTOR pIdt = GetImportDirectoryTable(lpImage, pOptHeader);

    // Iterate through DLLs
    PIMAGE_IMPORT_DESCRIPTOR pd = pIdt;
    while (pd->OriginalFirstThunk) {
        LPSTR szDllName = (LPSTR)(lpImage + pd->Name);

        PIMAGE_THUNK_DATA64 pIlt = (PIMAGE_THUNK_DATA64)(lpImage + pd->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 pIat = (PIMAGE_THUNK_DATA64)(lpImage + pd->FirstThunk);

        // Iterate through functions
        while (pIlt->u1.AddressOfData and pIat->u1.AddressOfData) {
            ULONGLONG lpFunctionAddr = pIat->u1.AddressOfData;

            LPSTR szFunctionName;

            // Ordinal
            if (pIlt->u1.Ordinal >> 63 == 1) {
                DWORD dwOrdinal = pIlt->u1.Ordinal & 0xffff;
                szFunctionName = (LPSTR)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                strcpy_s(szFunctionName, 8, "Ordinal_");
                sprintf_s(szFunctionName, 10, "%u", dwOrdinal);
            }
            else {
                szFunctionName = ((PIMAGE_IMPORT_BY_NAME)(lpImage + pIlt->u1.AddressOfData))->Name;
            }

            DWORD dwHash = 0;
            for (DWORD i=0; szFunctionName[i]; i++) {
                dwHash = (dwHash << 13) | (dwHash >> 19);
                dwHash += szFunctionName[i];
                // std::cout << std::hex << dwHash << std::endl;
            }

            // std::cout << szFunctionName << ": "  << std::hex << dwHash << std::endl;

            if (dwHash == dwTargetHash) {
                // std::cout << szFunctionName << " found!" << std::endl;

                // The address of the IAT entry in the remote process
                // PIMAGE_THUNK_DATA64 pImageIat = (PIMAGE_THUNK_DATA64)(lpImage + ((LPBYTE)pIat - lpBuf));

                // std::cout << "Now patching 0x" << std::hex << pIat << std::endl;

                // std::cout << "Original address: 0x" << std::hex << lpFunctionAddr << std::endl;

                DWORD oldProtect = 0;
                VirtualProtect((LPVOID)pIat, 8, PAGE_READWRITE, &oldProtect);

                // Patch
                pIat->u1.AddressOfData = (ULONGLONG)lpTramp;

                return;
            }

            pIlt++;
            pIat++;
        }

        pd++;
    }
}



PIMAGE_EXPORT_DIRECTORY GetExportDirectoryTable(LPBYTE lpPe, PIMAGE_OPTIONAL_HEADER64 pOptHeader, LONG lpad = 0) {
    PIMAGE_EXPORT_DIRECTORY pEDT = (PIMAGE_EXPORT_DIRECTORY)(lpPe + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - lpad);
    return pEDT;
}

std::map</* name */ std::string, /* address */ LPBYTE>
ReadExportAddressTableFromFile(
    LPBYTE lpPe
) {
    // Read these headers
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    PIMAGE_SECTION_HEADER aSecHeaders;
    GetPeHeaders(lpPe, NULL, NULL, NULL, &pOptHeader, &aSecHeaders);

    // Base -----------
    // 
    // .edata raw -----
    // 
    // .edata virt ----
    // 
    // The RVA is an address after the relocation
    // When we want to spot an RVA in a file without the relocation, we need to 'derelocate' it first.
    // 
    // The calculation is Base + RVA - (VirtualAddress - PointerToRawData)
    // We transform it to Base + RVA - lpad for simplicity
    // FIXME: We assume SectionAlignment was 0x1000 here
    LONG epad = 0x1000;
    PIMAGE_SECTION_HEADER pEdataHeader = GetSectionHeaderPointerByName(aSecHeaders, ".edata");
    if (pEdataHeader) {
        epad = pEdataHeader->VirtualAddress - pEdataHeader->PointerToRawData;
    }
    else {
        // .edata sometimes overlaps with .rdata
        // We can apply .rdata's padding offset to .edata
        PIMAGE_SECTION_HEADER pRdataHeader = GetSectionHeaderPointerByName(aSecHeaders, ".rdata");
        epad = pRdataHeader->VirtualAddress - pRdataHeader->PointerToRawData;
    }

    // FIXME: We assume SectionAlignment was 0x1000 here
    LONG tpad = 0x1000;
    PIMAGE_SECTION_HEADER pTextHeader = GetSectionHeaderPointerByName(aSecHeaders, ".text");
    if (pTextHeader) {
        tpad = pTextHeader->VirtualAddress - pTextHeader->PointerToRawData;
    }

    PIMAGE_EXPORT_DIRECTORY pEDT = GetExportDirectoryTable(lpPe, pOptHeader, epad);
    std::cout << "[ReadExportAddressTable] Reading EAT of " << lpPe + pEDT->Name - epad
        << " (" << pEDT->NumberOfFunctions << " functions exported)" << std::endl;

    std::map<std::string, LPBYTE> mEAT;

    // https://ferreirasc.github.io/PE-Export-Address-Table/
    // NOTE: This can miss functions without names
    for (DWORD i = 0; i < pEDT->NumberOfNames; i++) {
        WORD j = *(WORD*)(lpPe + pEDT->AddressOfNameOrdinals + i * 2 - epad);
        LPCSTR szName = (LPCSTR)lpPe + *(DWORD*)(lpPe + pEDT->AddressOfNames + i * 4 - epad) - epad;
        mEAT[szName] = lpPe + *(DWORD*)(lpPe + pEDT->AddressOfFunctions + j * 4 - epad) - tpad;
    }

    return mEAT;
}

LPBYTE GetFirstTextPtrFromFile(
    LPBYTE lpPe,
    PIMAGE_OPTIONAL_HEADER64 pOptHeader,
    PIMAGE_SECTION_HEADER aSecHeaders,
    LPDWORD length)
{
    // Get .text section
    PIMAGE_SECTION_HEADER pTextHeader = GetSectionHeaderPointerByName(aSecHeaders, ".text");

    if (!pTextHeader) {
        return NULL;
    }

    *length = pTextHeader->SizeOfRawData;

    // Return base + raw addr
    return lpPe + pTextHeader->PointerToRawData;
}

LPBYTE GetFirstSectionPtrFromFile(
    LPBYTE lpPe,
    LPCSTR lpSecName,
    PIMAGE_OPTIONAL_HEADER64 pOptHeader,
    PIMAGE_SECTION_HEADER aSecHeaders,
    LPDWORD length)
{
    // Get .text section
    PIMAGE_SECTION_HEADER pTextHeader = GetSectionHeaderPointerByName(aSecHeaders, lpSecName);

    if (!pTextHeader) {
        return NULL;
    }

    *length = pTextHeader->SizeOfRawData;

    // Return base + raw addr
    return lpPe + pTextHeader->PointerToRawData;
}

//LPVOID HeapAppend() {
//      HeapReAlloc(hPE, HEAP_GENERATE_EXCEPTIONS | HEAP_REALLOC_IN_PLACE_ONLY | HEAP_ZERO_MEMORY, lpPe, cbPe + align(cbSection, pOptHeader->FileAlignment));
//      WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORDLONG)lpPe + cbPe), lpSection, cbPe + align(cbSection, pOptHeader->FileAlignment), 0);
//}

// Build a new .idata section using abstracted data sources
//VOID* BuildIdata( std::vector<IMAGE_IMPORT_DESCRIPTOR>& aIDT
//                    , std::map<DWORD, IMAGE_THUNK_DATA64>& mILT
//                    , std::map<DWORD, IMAGE_THUNK_DATA64>& mIAT
//                    , std::map<DWORD, PIMAGE_IMPORT_BY_NAME>& mHNT
//                , DWORDLONG lpIdataBase
//                , DWORDLONG lpIdata2Base) {
//      DWORD  cbIdata2 = 0;
//      HANDLE  hIdata2 = HeapCreate(HEAP_GENERATE_EXCEPTIONS, cbIdata2, 0);
//      LPVOID lpIdata2; // = HeapAlloc(hIdata, HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, cbIdata);
//
//      // Build IAT
//      // DWORDLONG lpIdata2Base; // Virtual Address of .idata2
//      for (auto pit = mIAT.begin(); pit != mIAT.end(); pit++) {
//              if (not pit->second.u1.AddressOfData) {
//
//              }
//      }
//
//      for (IMAGE_IMPORT_DESCRIPTOR desc : aIDT) {
//
//              std::cout << mHNT[desc.Name]->Name << std::endl;
//
//              // {RVA, entry in table}
//              for (DWORD i = 0, pIlt = desc.OriginalFirstThunk, pIat = desc.FirstThunk;
//                         mILT.count(pIlt) and mIAT.count(pIat);
//                         i++, pIlt += sizeof(IMAGE_THUNK_DATA64) * i, pIat += sizeof(IMAGE_THUNK_DATA64) * i) {
//                      std::cout << "  " << mHNT[mILT[pIlt].u1.AddressOfData]->Name << std::endl;
//                      mIAT[pIat].u1.AddressOfData;
//              }
//      }
//
//      return nullptr;
//}
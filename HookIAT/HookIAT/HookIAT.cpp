// IATHooking.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include "pe.h"

unsigned char shellcode[] = "\x48\x89\xE5\x48\x81\xEC\x08\x06\x00\x00\xE8\xD6\x00\x00\x00\x41\xBA\x8E\x4E\x0E\xEC\xE8\xF1\x00\x00\x00\x48\x89\x45\x00\xC6\x04\x24\x55\xC6\x44\x24\x01\x73\xC6\x44\x24\x02\x65\xC6\x44\x24\x03\x72\xC6\x44\x24\x04\x33\xC6\x44\x24\x05\x32\xC6\x44\x24\x06\x2E\xC6\x44\x24\x07\x64\xC6\x44\x24\x08\x6C\xC6\x44\x24\x09\x6C\xC6\x44\x24\x0A\x00\x48\x89\xE1\x48\x83\xEC\x10\xFF\x55\x00\x48\x89\xC3\x41\xBA\xA8\xA2\x4D\xBC\xE8\x9F\x00\x00\x00\x48\x89\x45\xF0\x48\x31\xC9\xC6\x04\x24\x57\xC6\x44\x24\x01\x68\xC6\x44\x24\x02\x65\xC6\x44\x24\x03\x72\xC6\x44\x24\x04\x65\xC6\x44\x24\x05\x20\xC6\x44\x24\x06\x61\xC6\x44\x24\x07\x6D\xC6\x44\x24\x08\x20\xC6\x44\x24\x09\x49\xC6\x44\x24\x0A\x3F\xC6\x44\x24\x0B\x00\x48\x89\xE2\x48\x83\xEC\x20\xC6\x04\x24\x48\xC6\x44\x24\x01\x6F\xC6\x44\x24\x02\x6F\xC6\x44\x24\x03\x6B\xC6\x44\x24\x04\x65\xC6\x44\x24\x05\x64\xC6\x44\x24\x06\x21\xC6\x44\x24\x07\x00\x49\x89\xE0\x4D\x31\xC9\xFF\x55\xF0\x65\x48\x8B\x34\x25\x60\x00\x00\x00\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\x8B\x5E\x30\x48\x8B\x7E\x60\x48\x8B\x36\x66\x31\xC9\x66\x39\x4F\x18\x75\xEC\xC3\x48\x31\xC0\x48\x31\xC9\x48\x31\xFF\x48\x31\xF6\x8B\x43\x3C\x8B\xBC\x03\x88\x00\x00\x00\x48\x01\xDF\x8B\x4F\x18\x8B\x47\x20\x48\x01\xD8\x48\x89\x45\xF8\x67\xE3\x3A\xFF\xC9\x48\x8B\x45\xF8\x8B\x34\x88\x48\x01\xDE\x48\x31\xC0\x48\x31\xD2\xFC\xAC\x84\xC0\x74\x07\xC1\xCA\x0D\x01\xC2\xEB\xF4\x44\x39\xD2\x75\xD9\x8B\x57\x24\x48\x01\xDA\x66\x8B\x0C\x4A\x8B\x57\x1C\x48\x01\xDA\x8B\x04\x8A\x48\x01\xD8\xC3";

int main(int argc, char** argv)
{
    std::cout << "Debugging " << argv[1] << std::endl;

    LPSTARTUPINFOA si = new STARTUPINFOA();
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

    // Create a victim process
    CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, si, pi);

    // DWORD waitResult = WaitForSingleObject(pi->hProcess, 30000);

    std::cout << "PID: " << pi->dwProcessId << std::endl;

    std::cout << "---------- PRESS ENTER ----------" << std::endl;
    getchar();

    ResumeThread(pi->hThread);

    // Wait until the thread to be loaded
    DWORD waitResult = WaitForSingleObject(pi->hProcess, 100);

    // Peb of the remote process
    PPEB pPeb = GetRemotePeb(pi->hProcess);
    std::cout << "PEB: 0x" <<  std::hex << pPeb << std::endl;

    // Image base
    LPVOID lpImage;
    ReadProcessMemory(pi->hProcess, (LPBYTE)pPeb + 0x10, &lpImage, 8, NULL);
    std::cout << "Image Base: 0x" << std::hex << lpImage << std::endl;

    LPBYTE lpBuf = NULL;

    HMODULE hMod[1024];
    DWORD cbNeeded;
    MODULEINFO modInfo;

    if (EnumProcessModulesEx(pi->hProcess, hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL)) {
        // Victim process
        if (GetModuleInformation(pi->hProcess, hMod[0], &modInfo, sizeof(modInfo))) {
            printf("Victim size: %lu bytes\n", modInfo.SizeOfImage);

            // Copy the entire image on memory for later use
            lpBuf = (LPBYTE)VirtualAlloc(NULL, modInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            ReadProcessMemory(pi->hProcess, lpImage, lpBuf, modInfo.SizeOfImage, NULL);
        }

        // Kernel32
        //if (GetModuleInformation(pi->hProcess, hMod[1], &modInfo, sizeof(modInfo))) {
        //    // The size of the first module
        //    printf("Image size: %lu bytes\n", modInfo.SizeOfImage);
        //}
    }

    // Prepare a trampoline
    LPBYTE lpTramp = (LPBYTE)VirtualAllocEx(pi->hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy shellcode into the trampoline
    WriteProcessMemory(pi->hProcess, lpTramp, shellcode, sizeof(shellcode), NULL);

    // Hook an IAT entry
    PatchRemoteIatEntryByName(pi->hProcess, (LPBYTE)lpImage, lpBuf, argv[2], lpTramp);

    WaitForSingleObject(pi->hProcess, 1000);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

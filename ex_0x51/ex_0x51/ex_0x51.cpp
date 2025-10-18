// ex_0x51.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <winternl.h>

#include "pe.h"

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
    std::cout << "PEB: 0x" << std::hex << pPeb << std::endl;

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
        // ???: Can we assume that kernel32 is the third module? Idk:(
        if (GetModuleInformation(pi->hProcess, hMod[2], &modInfo, sizeof(modInfo))) {
            printf("Kernel32 base address: 0x%llX\n", modInfo.lpBaseOfDll);
            printf("Kernel32 size: %lu bytes\n", modInfo.SizeOfImage);
        }
    }

    std::cout << std::hex << "kernel32: [0x" << modInfo.lpBaseOfDll << ", 0x" << (LPVOID)((LPBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage) << ')' << std::endl;

    auto table = ReadRemoteImportAddressTable(pi->hProcess, (LPBYTE)lpImage, lpBuf);

    // TODO: Add your code here
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

// DetectIATHooks.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <winternl.h>

int main()
{
    HMODULE hMod[1024];
    DWORD cbNeeded;
    MODULEINFO modInfo;

    if (EnumProcessModulesEx(GetCurrentProcess(), hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL)) {
        // Kernel32
        // ???: Can we assume that kernel32 is the third module? Idk:(
        if (GetModuleInformation(GetCurrentProcess(), hMod[2], &modInfo, sizeof(modInfo))) {
            printf("Kernel32 base address: 0x%llX\n", modInfo.lpBaseOfDll);
            printf("Kernel32 size: %lu bytes\n", modInfo.SizeOfImage);
        }
    }

    LPBYTE lpFunc = (LPBYTE)VirtualAlloc;

    std::cout << std::hex << "kernel32: [0x" << modInfo.lpBaseOfDll << ", 0x" << (LPVOID)((LPBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage) << ')' << std::endl;

    while (1) {
        std::cout << "Function: 0x" << std::hex << (ULONGLONG)lpFunc << std::endl;

        if (lpFunc < modInfo.lpBaseOfDll or
            (LPBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage <= lpFunc) {
            std::cout << "The function 0x" << std::hex << (LPVOID)lpFunc << " is out of the kernel32 range!" << std::endl;
            break;
        }

        Sleep(1000);
    }
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

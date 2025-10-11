// ex_0x23.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "pe.h"

int main(int argc, char** argv)
{
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(L"C:\\Windows\\System32\\*.exe", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "FindFirstFile failed (" << GetLastError() << ")\n";
        return -1;
    }

    do
    {
        // Check if it's a file (not a directory)
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        std::wstring cFilePath = L"C:\\Windows\\System32\\";
        cFilePath += findFileData.cFileName;
        // std::wcout << cFilePath << std::endl;

        DWORD dwPESize;
        LPBYTE lpPE = OpenReadFile(cFilePath.c_str(), &dwPESize);
        auto table = ReadImportLookupTableFromRaw(lpPE);

        // for each DLL
        for (auto& [dllName, dllData] : table) {
            // TODO: Write your code here
            // Keys in dllData are function names
        }

    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
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

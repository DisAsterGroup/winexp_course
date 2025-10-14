// ex_0x62.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <iostream>
#include <inttypes.h>

#include "pe.h"
#include "Zydis/Zydis.h"

int main(int argc, char** argv)
{
    // Open and read a PE file
    DWORD dwPeSize;
    LPBYTE lpPe = OpenReadFileA(argv[1], &dwPeSize);

    // Get PE headers
    PIMAGE_OPTIONAL_HEADER64 pOptHeader;
    PIMAGE_SECTION_HEADER aSecHeaders;
    GetPeHeaders(lpPe, 0, 0, 0, &pOptHeader, &aSecHeaders);

    // Get .text section
    PIMAGE_SECTION_HEADER pTextHeader = GetSectionHeaderPointerByName(aSecHeaders, ".text");

    // First byte in .text header
    DWORD length;
    LPBYTE lpText = GetFirstTextPtrFromFile(lpPe, pOptHeader, aSecHeaders, &length);

    // Initialize decoder context 
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // Initialize formatter. Only required when you actually plan to do instruction
    // formatting ("disassembling"), like we do here
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions in our buffer.
    // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
    // visualize relative addressing
    ZyanU64 runtime_address = pOptHeader->ImageBase + pTextHeader->VirtualAddress;
    ZyanUSize offset = 0;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, lpText + offset, length - offset, &instruction, operands)))
    {
        // Format & print the binary instruction structure to human-readable format
        char buffer[256];
        ZydisFormatterFormatInstruction(
            &formatter,
            &instruction,
            operands,
            instruction.operand_count_visible,
            buffer,
            sizeof(buffer),
            runtime_address,
            ZYAN_NULL
        );

        // Add your code here

        offset += instruction.length;
        runtime_address += instruction.length;
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

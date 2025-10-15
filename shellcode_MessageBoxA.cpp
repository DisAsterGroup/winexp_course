// g++ shellcode_MessageBoxA.cpp -masm=intel

#include <iostream>

extern unsigned char shellcode[];
extern unsigned char find_function_finished[];

int main()
{
    for (int i=0; i < find_function_finished-shellcode+1; i++) {
        printf("\\x%02hhX", shellcode[i]);
    }

    __asm__ __volatile__ (
    ".intel_syntax noprefix;"
    "shellcode:"
        " mov rbp, rsp;"
        " sub rsp, 0x600;"
        " call find_kernel32;"
    "resolve_symbols_kernel32:"
        " mov r10d, 0x3b8ff745;"             // LoadLibraryA hash
        " call find_function;"
        " mov [rbp], rax;"                   // LoadLibraryA address
    "load_user32:"
        " mov byte ptr [rsp],    0x55;"      // U
        " mov byte ptr [rsp+1],  0x73;"      // s
        " mov byte ptr [rsp+2],  0x65;"      // e
        " mov byte ptr [rsp+3],  0x72;"      // r
        " mov byte ptr [rsp+4],  0x33;"      // 3
        " mov byte ptr [rsp+5],  0x32;"      // 2
        " mov byte ptr [rsp+6],  0x2e;"      // .
        " mov byte ptr [rsp+7],  0x64;"      // d
        " mov byte ptr [rsp+8],  0x6c;"      // l
        " mov byte ptr [rsp+9],  0x6c;"      // l
        " mov byte ptr [rsp+10], 0x00;"
        " mov rcx, rsp;"
        " sub rsp, 0x10;"
        " call [rbp];"                       // Call LoadLibraryA
        " mov rbx, rax;"
    "resolve_symbols_user32:"
        " mov r10d, 0x6717d648;"              // MessageBoxA hash
        " call find_function;"
        " mov [rbp+8], rax;"                 // MessageBoxA address
    "call_MessageBoxA:"
        " xor rcx, rcx;"                     // hWnd = NULL
        " mov byte ptr [rsp],       0x48;"   // H
        " mov byte ptr [rsp+1],     0x65;"   // e
        " mov byte ptr [rsp+2],     0x6c;"   // l
        " mov byte ptr [rsp+3],     0x6c;"   // l
        " mov byte ptr [rsp+4],     0x6f;"   // o
        " mov byte ptr [rsp+5],     0x2c;"   // ,
        " mov byte ptr [rsp+6],     0x20;"   //  
        " mov byte ptr [rsp+7],     0x53;"   // S
        " mov byte ptr [rsp+8],     0x68;"   // h
        " mov byte ptr [rsp+9],     0x65;"   // e
        " mov byte ptr [rsp+10],    0x6c;"   // l
        " mov byte ptr [rsp+11],    0x6c;"   // l
        " mov byte ptr [rsp+12],    0x63;"   // c
        " mov byte ptr [rsp+13],    0x6f;"   // o
        " mov byte ptr [rsp+14],    0x64;"   // d
        " mov byte ptr [rsp+15],    0x65;"   // e
        " mov byte ptr [rsp+16],    0x21;"   // !
        " mov byte ptr [rsp+17],    0x00;"   // \x00
        " mov rdx, rsp;"                     // lpText = "Hello, Shellcode!\x00"
        " sub rsp, 0x20;"
        " mov byte ptr [rsp],       0x48;"   // H
        " mov byte ptr [rsp+1],     0x65;"   // e
        " mov byte ptr [rsp+2],     0x6c;"   // l
        " mov byte ptr [rsp+3],     0x6c;"   // l
        " mov byte ptr [rsp+4],     0x6f;"   // o
        " mov byte ptr [rsp+5],     0x53;"   // S
        " mov byte ptr [rsp+6],     0x68;"   // h
        " mov byte ptr [rsp+7],     0x65;"   // e
        " mov byte ptr [rsp+8],     0x6c;"   // l
        " mov byte ptr [rsp+9],     0x6c;"   // l
        " mov byte ptr [rsp+10],    0x63;"   // c
        " mov byte ptr [rsp+11],    0x6f;"   // o
        " mov byte ptr [rsp+12],    0x64;"   // d
        " mov byte ptr [rsp+13],    0x65;"   // e
        " mov byte ptr [rsp+14],    0x00;"   // \x00
        " mov r8, rsp;"                      // lpCaption = "HelloShellcode\x00"
        " xor r9, r9;"                       // uType = MB_OK
        " call [rbp+8];"                     // call MessageBoxA

    "find_kernel32:"
        " int3;"
        " mov rsi, gs:[0x60];"               // RSI = &(PEB) ([GS:0x60])
        " mov rsi, [rsi+0x18];"              // RSI = PEB->Ldr
        " mov rsi, [rsi+0x10];"              // RSI = PEB->Ldr.InLoadOrderModuleList
    "next_module:"
        " mov rbx, [rsi+0x30];"              // RBX = InLoadOrderModuleList[X].base_address
        " mov rdi, [rsi+0x60];"              // RDI = InLoadOrderModuleList[X].module_name
        " mov rsi, [rsi];"                   // RSI = InLoadOrderModuleList[X].flink (next)
        " xor cx, cx;"
        " cmp [rdi+12*2], cx;"               // (unicode) modulename[12] == 0x00?
        " jne next_module;"                  // No: try next module.
        " ret;"

    "find_function:"
        // Base address of kernel32 is in RBX
        // from Previous step (find_kernel32)
        " xor rax, rax;"
        " xor rcx, rcx;"
        " xor rdi, rdi;"
        " xor rsi, rsi;"
        " mov eax, [rbx+0x3c];"              // Offset to PE Signature
        " mov edi, [rbx+rax+0x88];"          // Export Table Directory RVA
        " add rdi, rbx;"                     // Export Table Directory VMA
        " mov ecx, [rdi+0x18];"              // NumberOfNames
        " mov eax, [rdi+0x20];"              // AddressOfNames RVA
        " add rax, rbx;"                     // AddressOfNames VMA
        " mov [rbp-8], rax;"                 // Save AddressOfNames VMA for later
    "find_function_loop:"
        " jecxz find_function_finished;"     // Jump to the end if ECX is 0
        " dec ecx;"                          // Decrement our names counter
        " mov rax, [rbp-8];"                 // Restore AddressOfNames VMA
        " mov esi, [rax+rcx*4];"             // Get the RVA of the symbol name
        " add rsi, rbx;"                     // Set RSI to the VMA of the current symbol name
    "compute_hash:"
        " xor rax, rax;"                     // NULL RAX
        " xor rdx, rdx;"                     // NULL RDX
        " cld;"                              // Clear direction
    "compute_hash_again:"
        " lodsb;"                            // Load the next byte from RSI into AL
        " test al, al;"                      // Check for NULL terminator
        " jz compute_hash_finished;"         // If the ZF is set, we've hit the NULL term
        " rol edx, 0x0d;"                    // Rotate edx 13 bits to the left
        " add edx, eax;"                     // Add the new byte to the accumulator
        " jmp compute_hash_again;"           // Next iteration
    "compute_hash_finished:"
    "find_function_compare:"
        " cmp edx, r10d;"                    // Compare the computed hash with the requested hash
        " jnz find_function_loop;"           // If it doesn't match go back to find_function_loop
        " mov edx, [rdi+0x24];"              // AddressOfNameOrdinals RVA
        " add rdx, rbx;"                     // AddressOfNameOrdinals VMA
        " mov cx, [rdx+2*rcx];"              // Extrapolate the function's ordinal
        " mov edx, [rdi+0x1c];"              // AddressOfFunctions RVA
        " add rdx, rbx;"                     // AddressOfFunctions VMA
        " mov eax, [rdx+4*rcx];"             // Get the function RVA
        " add rax, rbx;"                     // Get the function VMA
    "find_function_finished:"
        " ret;"
    );
}

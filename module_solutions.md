### Exercise 0.1
push

### Exercise 0.2
`mov ebx, ecx` の ModR/M は Mod 0b11、REG 011、R/M 001 でエンコードされる。よって、0b11011001 = 0xd9 が答え。

### Exercise 0.4
フラグを第1引数に与える必要がある

first_flag

```
Original
| 20 bits | 12 bits |

move the 20-bit-chunk to the right by 12 bits, the 12-bit-chunk to the left by 20 bits
| 12 bits | 20 bits |
```

```
hex(((0xc6667616 << 12) | (0xc6667616 >> 20)) & 0xffffffff)
'0x67616c66'
```

### Exercise 0.5
0x1400014ac

### Exercise 2.2
MessageBoxExA

### Exercise 2.3
* psr.exe
* usocoreworker.exe

```c
for (auto& [dllName, dllData] : table) {
    // TODO: Write your code here
    // Keys in dllData are function names
    if (dllData.find(argv[1]) != dllData.end()) {
        std::wcout << cFilePath << std::endl;
        break;
    }
}
```

### Exercise 3.1
seccamp_reh9dg3b4gnbd0ykihzb.com

BeingDebugged を無効化する

`inet_pton` の第2引数に着目

```
bp Client + 1320
bp Client + 1473
```

## Exercise 4.1
0x16b3fe72

ROR 13 を使用

## Exercise 5.1
GetModuleHandleW

0xd717aaea というハッシュ値

自動化する場合:

```c
for (auto& [funcName, funcAddr] : table["KERNEL32.dll"]) {
    if ((LPVOID)funcAddr < modInfo.lpBaseOfDll or
        (LPBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage <= (LPVOID)funcAddr) {
        std::cout << "The function " << funcName << " (0x" << std::hex << (LPVOID)funcAddr << ") is out of the kernel32 range!" << std::endl;
    }
}
```

WinDbg でデバッグする場合:

```c
*(uint64_t*)lpAddress = rax_5;
```

WinDbg でデバッグする場合:

```
dq ForgeIAT + 26000 L50
? 26000 + 120
```

## Exercise 6.2
0x14000cb80

```c
if (strstr(buffer, "gs:") != NULL) {
    printf("%016" PRIX64 "  ", runtime_address);
    puts(buffer);
}
```

```
> ex_0x62.exe "C:\Users\omega\Desktop\winexp_course\func_10000_msvc.exe"
000000000000CB80  mov rax, gs:[0x0000000000000060]
00000000000288D4  mov rax, gs:[0x0000000000000030]
00000000000288ED  mov rax, gs:[0x0000000000000030]
```

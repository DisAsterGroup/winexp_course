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

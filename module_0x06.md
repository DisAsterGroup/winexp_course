## Zydis による静的解析
モジュール 0x00 で言及したように、リバースエンジニアリングにおいてはコードをできるだけ読まないことが重要で、一度ある程度解析を自動化する仕組みを用意しておくと重宝する。例えば、[Zydis](https://github.com/zyantific/zydis) のようなディスアセンブル用のライブラリを使えば、事前に用意したパターンに合致するようなコードを容易に見つけることができる。このモジュールでは、Zydis を用いた静的解析について解説する。

### Zydis 101
Zydis を用いた自動化の一例として、[ZydisLab](./ZydisLab/) を用意した。この例では、PE ファイルのフルパスを引数に取り、.text セクション内のコードを全てディスアセンブルする。[pe.h](./include/pe.h) 内の関数を使えば、以下のコードで .text セクションを読み取ることができる:

```cpp
// Open and read a PE file
DWORD dwPeSize;
LPBYTE lpPe = OpenReadFileA(argv[1], &dwPeSize);

// Get PE headers
PIMAGE_OPTIONAL_HEADER64 pOptHeader;
PIMAGE_SECTION_HEADER aSecHeaders;
GetPeHeaders(lpPe, 0, 0, 0, &pOptHeader, &aSecHeaders);

// First byte in .text header
DWORD length;
LPBYTE lpText = GetFirstTextPtrFromFile(lpPe, pOptHeader, aSecHeaders, &length);
```

その後、`ZydisDecoderDecodeFull` で `lpText + offset` の位置にある命令をディスアセンブルしていく:

```cpp
// Loop over the instructions in our buffer.
// The runtime-address (instruction pointer) is chosen arbitrary here in order to better
// visualize relative addressing
ZyanU64 runtime_address = 0;
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

    printf("%016" PRIX64 "  ", runtime_address);
    puts(buffer);

    offset += instruction.length;
    runtime_address += instruction.length;
}
```

### Exercise 6.1 (フラグなし)
[ZydisLab](./ZydisLab/) をビルドして、victim.exe をディスアセンブルしてみよう。以下はコマンド例:

```
> ZydisLab.exe C:\Users\omega\Desktop\windows_binary_experiments\course\IATHooking\x64\Release\victim.exe
```

### Exercise 6.2
[func_10000_msvc.exe](./func_10000_msvc.exe) は10000個の関数をランダムに実行し続ける。この中の1つの関数は、PEB を取得することが分かっている。この関数のアドレスを特定し、16進数で回答してほしい。

[ex_0x62](./ex_0x62) をテンプレとして用意した。適宜コードを追加のこと。

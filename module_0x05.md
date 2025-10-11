## IAT Hooking
このモジュールでは、IAT Hooking について解説する。

### IAT Hooking
アンチウイルス製品や EDR は、IAT Hooking というテクニックを用いてマルウェアが使用する API を監視している。

通常、IAT には以下のように関数のアドレスが格納されている:

TODO: Add a picture

このアドレスを書き換えて自前のコードを呼び出すことで、関数の呼び出し、渡される引数などを監視することができる:

TODO: Add a picture

> [!TIP]
> このようなコードはトランポリン (trampoline) と表現される。

### IAT Hooking の検知
Detection:
Read IAT
Check if each entry is within the range
API がエクスポートされているライブラリのアドレスの範囲と比較することで、検知可能

#### Exercise
TODO: IAT forge - What if the address is changed during execution?
解析者への嫌がらせをするため、いずれかの関数の IAT のエントリを書き換えてある
どの関数がいじられているのか、特定してほしい

### Microsoft Detours
Windows API Hooking

関数の命令にパッチする

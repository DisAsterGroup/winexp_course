## Hooking
このモジュールでは、hooking について解説する。Hooking とは自分以外のプロセスの挙動を監視するテクニックのことで、プロセスにコードを注入して、特定の処理が実行された際にそのコードが呼ばれるようにする。

### IAT Hooking
アンチウイルス製品や EDR は、特に IAT Hooking というテクニックを用いてマルウェアが使用する API を監視している。

通常、IAT には以下のように関数のアドレスが格納されている:

<img src="./assets/img_0x0501.png" width="60%">

このアドレスを書き換えて自前のコードを呼び出すことで、関数の呼び出し、渡される引数などを監視することができる:

<img src="./assets/img_0x0502.png" width="60%">

> [!TIP]
> このようなコードはトランポリン (trampoline) と表現される。

TODL: Add an experiment
bp victim!_imp_VirtualAlloc

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

## Hooking
このモジュールでは、hooking について解説する。Hooking とは自分以外のプロセスの挙動を監視するテクニックのことで、プロセスにコードを注入して、特定の処理が実行された際にそのコードが呼ばれるようにする。

### IAT Hooking
アンチウイルス製品や EDR は、特に IAT Hooking というテクニックを用いてマルウェアが使用する API を監視している。

通常、IAT には以下のように関数のアドレスが格納されている:

<img src="./assets/img_0x0501.png" width="60%">

このアドレスを書き換えて自前のコード (トランポリン) を呼び出すことで、関数の呼び出し、渡される引数などを監視することができる:

<img src="./assets/img_0x0502.png" width="60%">

IAT hooking は以下のように実装できる:

* プロセス内にトランポリンを確保
* トランポリンにシェルコードをコピー
* ILT からフックしたい API 名を探索
* 対応する IAT 内エントリのアドレスを書き換える

> [!NOTE]
> フックしたいプロセスは別プロセスである場合が多く、別プロセスのプロセス空間内の読み書きを行う場合は `ReadProcessMemory`、`WriteProcessMemory` といった API を用いる。

> [!NOTE]
> PE ファイルのロードが終わった後、IAT は READONLY になる。書き換える前に `VirtualProtectEx` などで READWRITE に変更する必要がある。

HookIAT.exe は IAT Hooking を実装したもので、渡された PE ファイルから子プロセスを生成し、IAT にシェルコードをフックする:

```
> HookIAT.exe <PE ファイルのフルパス> <API 名>
```

例えば、victim.exe の `VirtualAlloc` にフックすると、トランポリンが `MessageBoxA` を実行する:

```
> HookIAT.exe "C:\Users\omega\Desktop\windows_binary_experiments\course\IATHooking\x64\Release\victim.exe" VirtualAlloc
PID: 4652
---------- PRESS ENTER ----------

PEB: 0x000000C0472F6000
Image Base: 0x00007FF781A20000
Victim size: 28672 bytes
VirtualAlloc found!
Now patching 0x00007FF781A22000
Original address: 0x7ffc1d548840

```

<img src="./assets/img_0x0503.png" width="30%">

WinDbg を用いると、IAT が書き換えられる様子を詳細に確認できる。まずは上記の HookIAT.exe と同じコマンドを実行し、表示される PID を持つプロセスにアタッチする。フック前の段階では、IAT のエントリには `KERNEL32!VirtualAllocStub` が保存されていることが分かる:

<img src="./assets/img_0x0504.png" width="50%">

次に `VirtualAlloc` が呼ばれる直前にブレークポイントを設定して再開、HookIAT.exe 側でエンターを押し、フックする。ブレークしたところで IAT を確認してみると、トランポリンの処理に書き換えられていることが分かる:

<img src="./assets/img_0x0505.png" width="50%">

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

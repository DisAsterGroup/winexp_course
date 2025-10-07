## IAT Hooking

Hook

### Exercise
TODO: IAT forge - What if the address is changed during execution?
解析者への嫌がらせをするため、いずれかの関数の IAT のエントリを書き換えてある
どの関数がいじられているのか、特定してほしい

Detection:
Read IAT
Check if each entry is within the range
API がエクスポートされているライブラリのアドレスの範囲と比較することで、検知可能

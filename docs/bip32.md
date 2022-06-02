## BIP32

### Mnemonic

### Hardened Derivation (BIP32)

### Extended Keys

母私钥 + 母链码 称之为扩展私钥

安全考虑：

+ 常规衍生，从扩展公钥只能衍生出前 2 的 31 次个子公钥
+ 硬化衍生，后 2 的 31 次子公钥只能从扩展私钥衍生

1) Private extended key -> Hardened child private extended key
2) Private extended key -> Non-hardened child private extended key
3) Public extended key -> Non-hardened child public extended key
4) Public extended key -> Hardened child public extended key (INVALID!)

### Address Prefixes

https://en.bitcoin.it/wiki/List_of_address_prefixes

### 相关仓库

https://github.com/tyler-smith/go-bip32

Convert any Bitcoin key prefix to another (e.g.: xpub to ypub, zpriv to Zpriv)

https://gist.github.com/jleo84/97fc58c6174f146642b2c215c20f88f5

2 Party BIP32:

https://github.com/getamis/alice

### 相关论文

1. Hierarchical deterministic Bitcoin wallets that tolerate key leakage

2. Private Key Recovery Combination Attacks: On Extreme Fragility of Popular Bitcoin Key Management, Wallet and Cold Storage Solutions in Presence of Poor RNG Events
# Keystone Go Bindings

基于 [Keystone](https://www.keystone-engine.org/) 的 Go 语言绑定，**纯 Go 实现，无 CGO 依赖**。

## 特性

- **🚀 无 CGO**: 纯 Go 实现
- **DLL 嵌入**: `keystone.dll` 嵌入到 Go 二进制
- **多架构汇编**: 支持 ARM, ARM64, X86, MIPS, SPARC 等

## 使用方法

```go
package main

import "github.com/ddkwork/keystone"

func main() {
    k := &keystone.Keystone{}
    k.Open(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    defer k.Close()
    
    encoding, _ := k.Asm("mov eax, 1", 0)
    fmt.Printf("Encoding: %x\n", encoding)
}
```

## 测试

```bash
go test -v
```

## 许可证

MIT License

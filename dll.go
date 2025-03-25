package keystone

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// 定义引擎句柄类型
type KeystoneEngine uintptr

// 架构类型枚举
const (
	KS_ARCH_ARM     = 1
	KS_ARCH_ARM64   = 2
	KS_ARCH_MIPS    = 3
	KS_ARCH_X86     = 4
	KS_ARCH_PPC     = 5
	KS_ARCH_SPARC   = 6
	KS_ARCH_SYSTEMZ = 7
	KS_ARCH_HEXAGON = 8
	KS_ARCH_EVM     = 9
	KS_ARCH_RISCV   = 10
)

// 模式类型枚举
const (
	KS_MODE_LITTLE_ENDIAN = 0
	KS_MODE_BIG_ENDIAN    = 1 << 30
	KS_MODE_ARM           = 1 << 0
	KS_MODE_THUMB         = 1 << 4
	KS_MODE_V8            = 1 << 6
	KS_MODE_MICRO         = 1 << 4
	KS_MODE_MIPS3         = 1 << 5
	KS_MODE_MIPS32R6      = 1 << 6
	KS_MODE_MIPS32        = 1 << 2
	KS_MODE_MIPS64        = 1 << 3
	KS_MODE_16            = 1 << 1
	KS_MODE_32            = 1 << 2
	KS_MODE_64            = 1 << 3
)

// 错误码映射
var ksErrors = map[uint32]error{
	0: nil,
	1: errors.New("out of memory"),
	2: errors.New("unsupported architecture"),
	3: errors.New("invalid handle"),
	4: errors.New("invalid mode"),
	5: errors.New("version mismatch"),
	6: errors.New("invalid option"),
	// 添加更多错误描述...
}

var (
	lib        *syscall.LazyDLL
	ksOpen     *syscall.LazyProc
	ksClose    *syscall.LazyProc
	ksVersion  *syscall.LazyProc
	ksErrno    *syscall.LazyProc
	ksStrerror *syscall.LazyProc
	ksAsm      *syscall.LazyProc
	ksFree     *syscall.LazyProc
	ksOption   *syscall.LazyProc
)

func init() {
	libName := "keystone.dll"
	switch runtime.GOOS {
	case "linux":
		libName = "libkeystone.so"
	case "darwin":
		libName = "libkeystone.dylib"
	}

	lib = syscall.NewLazyDLL(libName)

	// 绑定所有导出函数
	ksOpen = lib.NewProc("ks_open")
	ksClose = lib.NewProc("ks_close")
	ksVersion = lib.NewProc("ks_version")
	ksErrno = lib.NewProc("ks_errno")
	ksStrerror = lib.NewProc("ks_strerror")
	ksAsm = lib.NewProc("ks_asm")
	ksFree = lib.NewProc("ks_free")
	ksOption = lib.NewProc("ks_option")
}

// 创建新引擎实例
func New(arch, mode int) (KeystoneEngine, error) {
	var engine KeystoneEngine
	rc, _, err := ksOpen.Call(
		uintptr(arch),
		uintptr(mode),
		uintptr(unsafe.Pointer(&engine)),
	)

	if err != syscall.Errno(0) {
		return 0, fmt.Errorf("ks_open failed: %v", err)
	}
	if rc != 0 {
		return 0, ksErrors[uint32(rc)]
	}

	return engine, nil
}

// 关闭引擎
func (ks KeystoneEngine) Close() error {
	rc, _, _ := ksClose.Call(uintptr(ks))
	if rc != 0 {
		return ksErrors[uint32(rc)]
	}
	return nil
}

// 获取错误描述
func (ks KeystoneEngine) ErrorString() string {
	errCode, _, _ := ksErrno.Call(uintptr(ks))
	var buf *byte
	ksStrerror.Call(errCode, uintptr(unsafe.Pointer(&buf)))
	return ptrToString(buf)
}

// 汇编指令
func (ks KeystoneEngine) Assemble(asm string, addr uint64) ([]byte, uint, error) {
	var (
		encode    *byte
		size      uintptr
		statCount uintptr
		cAsm      = syscall.StringBytePtr(asm)
	)

	rc, _, _ := ksAsm.Call(
		uintptr(ks),
		uintptr(unsafe.Pointer(cAsm)),
		uintptr(addr),
		uintptr(unsafe.Pointer(&encode)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&statCount)),
	)

	if rc != 0 {
		return nil, 0, fmt.Errorf("assembly failed: %s", ks.ErrorString())
	}

	// 复制结果到Go切片
	result := CGoBytes(unsafe.Pointer(encode), int(size))
	ksFree.Call(uintptr(unsafe.Pointer(encode)))

	return result, uint(statCount), nil
}

// 设置引擎选项
func (ks KeystoneEngine) SetOption(optType int, value uintptr) error {
	rc, _, _ := ksOption.Call(
		uintptr(ks),
		uintptr(optType),
		value,
	)
	if rc != 0 {
		return ksErrors[uint32(rc)]
	}
	return nil
}

// 辅助函数：指针转字符串
func ptrToString(p *byte) string {
	if p == nil {
		return ""
	}
	var length int
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; ptr = unsafe.Add(ptr, 1) {
		length++
	}
	return string(unsafe.Slice(p, length))
}

// 辅助函数：C字节数组转Go切片
func CGoBytes(p unsafe.Pointer, length int) []byte {
	if p == nil {
		return nil
	}
	return unsafe.Slice((*byte)(p), length)
}

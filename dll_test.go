package keystone

import (
	"fmt"
	"testing"
)

func TestNew(t *testing.T) {
	// 初始化X86-64引擎
	ks, err := New(KS_ARCH_X86, KS_MODE_64)
	if err != nil {
		panic(err)
	}
	defer ks.Close()

	// 设置语法选项（Intel语法）
	if err := ks.SetOption(1 /*KS_OPT_SYNTAX*/, 1 /*KS_OPT_SYNTAX_INTEL*/); err != nil {
		panic(err)
	}

	// 汇编测试指令
	code := "mov eax, 0x1234; ret"
	enc, _, err := ks.Assemble(code, 0x1000)
	if err != nil {
		panic(err)
	}

	// 输出结果
	fmt.Printf("Assembly succeeded!\nEncoded bytes: %x\n", enc)
}

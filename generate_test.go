package keystone

import (
	"strings"
	"testing"

	"github.com/ddkwork/bindgen/c2go"
)

func TestGenerate(t *testing.T) {
	c2go.Generate(t, []c2go.BindgenConfig{{
		HeadersDir:  "clone/keystone/include/keystone",
		OutputDir:   ".",
		PackageName: "keystone",
		HeaderOrder: []string{"keystone.h", "arm.h", "arm64.h", "evm.h", "hexagon.h", "mips.h", "ppc.h", "riscv.h", "sparc.h", "systemz.h", "x86.h"},
		BindDll:     true,
		DllName:     "keystone.dll",
		DllFuncFilter: func(name string) bool {
			return strings.HasPrefix(name, "ks_")
		},
	}})
}

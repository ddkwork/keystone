package keystone

import (
	"fmt"
	"unsafe"
)

// Source: keystone.h
type (
	Ks_engine = Ks_struct
)

type Ks_sym_resolver func(*int8, *uint64) uintptr

// Source: keystone.h:57 -> ks_arch
type Ks_arch uint32

const (
	KsArchArm Ks_arch = 1 + iota
	KsArchArm64
	KsArchMips
	KsArchX86
	KsArchPpc
	KsArchSparc
	KsArchSystemz
	KsArchHexagon
	KsArchEvm
	KsArchRiscv
	KsArchMax
)

func (k Ks_arch) String() string {
	switch k {
	case KsArchArm:
		return "Ks Arch Arm"
	case KsArchArm64:
		return "Ks Arch Arm 64"
	case KsArchMips:
		return "Ks Arch Mips"
	case KsArchX86:
		return "Ks Arch X86"
	case KsArchPpc:
		return "Ks Arch Ppc"
	case KsArchSparc:
		return "Ks Arch Sparc"
	case KsArchSystemz:
		return "Ks Arch Systemz"
	case KsArchHexagon:
		return "Ks Arch Hexagon"
	case KsArchEvm:
		return "Ks Arch Evm"
	case KsArchRiscv:
		return "Ks Arch Riscv"
	case KsArchMax:
		return "Ks Arch Max"
	default:
		return fmt.Sprintf("Ks_arch(0x%X)", uint32(k))
	}
}

// Source: keystone.h:72 -> ks_mode
type Ks_mode uint32

const (
	KsModeLittleEndian Ks_mode = 0
	KsModeBigEndian    Ks_mode = 1073741824
	KsModeArm          Ks_mode = 1
	KsModeThumb        Ks_mode = 16
	KsModeV8           Ks_mode = 64
	KsModeMicro        Ks_mode = 16
	KsModeMips3        Ks_mode = 32
	KsModeMips32r6     Ks_mode = 64
	KsModeMips32       Ks_mode = 4
	KsModeMips64       Ks_mode = 8
	KsMode16           Ks_mode = 2
	KsMode32           Ks_mode = 4
	KsMode64           Ks_mode = 8
	KsModePpc32        Ks_mode = 4
	KsModePpc64        Ks_mode = 8
	KsModeQpx          Ks_mode = 16
	KsModeRiscv32      Ks_mode = 4
	KsModeRiscv64      Ks_mode = 8
	KsModeSparc32      Ks_mode = 4
	KsModeSparc64      Ks_mode = 8
	KsModeV9           Ks_mode = 16
)

func (k Ks_mode) String() string {
	switch k {
	case KsModeLittleEndian:
		return "Ks Mode Little Endian"
	case KsModeBigEndian:
		return "Ks Mode Big Endian"
	case KsModeArm:
		return "Ks Mode Arm"
	case KsModeThumb:
		return "Ks Mode Thumb"
	case KsModeV8:
		return "Ks Mode V8"
	case KsModeMips3:
		return "Ks Mode Mips 3"
	case KsModeMips32:
		return "Ks Mode Mips 32"
	case KsModeMips64:
		return "Ks Mode Mips 64"
	case KsMode16:
		return "Ks Mode 16"
	default:
		return fmt.Sprintf("Ks_mode(0x%X)", uint32(k))
	}
}

// Source: keystone.h:109 -> ks_err
type Ks_err uint32

const (
	KsErrOk                     Ks_err = 0
	KsErrNomem                  Ks_err = 1
	KsErrArch                   Ks_err = 2
	KsErrHandle                 Ks_err = 3
	KsErrMode                   Ks_err = 4
	KsErrVersion                Ks_err = 5
	KsErrOptInvalid             Ks_err = 6
	KsErrAsmExprToken           Ks_err = 128
	KsErrAsmDirectiveValueRange Ks_err = 129
	KsErrAsmDirectiveId         Ks_err = 130
	KsErrAsmDirectiveToken      Ks_err = 131
	KsErrAsmDirectiveStr        Ks_err = 132
	KsErrAsmDirectiveComma      Ks_err = 133
	KsErrAsmDirectiveRelocName  Ks_err = 134
	KsErrAsmDirectiveRelocToken Ks_err = 135
	KsErrAsmDirectiveFpoint     Ks_err = 136
	KsErrAsmDirectiveUnknown    Ks_err = 137
	KsErrAsmDirectiveEqu        Ks_err = 138
	KsErrAsmDirectiveInvalid    Ks_err = 139
	KsErrAsmVariantInvalid      Ks_err = 140
	KsErrAsmExprBracket         Ks_err = 141
	KsErrAsmSymbolModifier      Ks_err = 142
	KsErrAsmSymbolRedefined     Ks_err = 143
	KsErrAsmSymbolMissing       Ks_err = 144
	KsErrAsmRparen              Ks_err = 145
	KsErrAsmStatToken           Ks_err = 146
	KsErrAsmUnsupported         Ks_err = 147
	KsErrAsmMacroToken          Ks_err = 148
	KsErrAsmMacroParen          Ks_err = 149
	KsErrAsmMacroEqu            Ks_err = 150
	KsErrAsmMacroArgs           Ks_err = 151
	KsErrAsmMacroLevelsExceed   Ks_err = 152
	KsErrAsmMacroStr            Ks_err = 153
	KsErrAsmMacroInvalid        Ks_err = 154
	KsErrAsmEscBackslash        Ks_err = 155
	KsErrAsmEscOctal            Ks_err = 156
	KsErrAsmEscSequence         Ks_err = 157
	KsErrAsmEscStr              Ks_err = 158
	KsErrAsmTokenInvalid        Ks_err = 159
	KsErrAsmInsnUnsupported     Ks_err = 160
	KsErrAsmFixupInvalid        Ks_err = 161
	KsErrAsmLabelInvalid        Ks_err = 162
	KsErrAsmFragmentInvalid     Ks_err = 163
	KsErrAsmInvalidoperand      Ks_err = 512
	KsErrAsmMissingfeature      Ks_err = 513
	KsErrAsmMnemonicfail        Ks_err = 514
)

func (k Ks_err) String() string {
	switch k {
	case KsErrOk:
		return "Ks Err Ok"
	case KsErrNomem:
		return "Ks Err Nomem"
	case KsErrArch:
		return "Ks Err Arch"
	case KsErrHandle:
		return "Ks Err Handle"
	case KsErrMode:
		return "Ks Err Mode"
	case KsErrVersion:
		return "Ks Err Version"
	case KsErrOptInvalid:
		return "Ks Err Opt Invalid"
	case KsErrAsmExprToken:
		return "Ks Err Asm Expr Token"
	case KsErrAsmDirectiveValueRange:
		return "Ks Err Asm Directive Value Range"
	case KsErrAsmDirectiveId:
		return "Ks Err Asm Directive Id"
	case KsErrAsmDirectiveToken:
		return "Ks Err Asm Directive Token"
	case KsErrAsmDirectiveStr:
		return "Ks Err Asm Directive Str"
	case KsErrAsmDirectiveComma:
		return "Ks Err Asm Directive Comma"
	case KsErrAsmDirectiveRelocName:
		return "Ks Err Asm Directive Reloc Name"
	case KsErrAsmDirectiveRelocToken:
		return "Ks Err Asm Directive Reloc Token"
	case KsErrAsmDirectiveFpoint:
		return "Ks Err Asm Directive Fpoint"
	case KsErrAsmDirectiveUnknown:
		return "Ks Err Asm Directive Unknown"
	case KsErrAsmDirectiveEqu:
		return "Ks Err Asm Directive Equ"
	case KsErrAsmDirectiveInvalid:
		return "Ks Err Asm Directive Invalid"
	case KsErrAsmVariantInvalid:
		return "Ks Err Asm Variant Invalid"
	case KsErrAsmExprBracket:
		return "Ks Err Asm Expr Bracket"
	case KsErrAsmSymbolModifier:
		return "Ks Err Asm Symbol Modifier"
	case KsErrAsmSymbolRedefined:
		return "Ks Err Asm Symbol Redefined"
	case KsErrAsmSymbolMissing:
		return "Ks Err Asm Symbol Missing"
	case KsErrAsmRparen:
		return "Ks Err Asm Rparen"
	case KsErrAsmStatToken:
		return "Ks Err Asm Stat Token"
	case KsErrAsmUnsupported:
		return "Ks Err Asm Unsupported"
	case KsErrAsmMacroToken:
		return "Ks Err Asm Macro Token"
	case KsErrAsmMacroParen:
		return "Ks Err Asm Macro Paren"
	case KsErrAsmMacroEqu:
		return "Ks Err Asm Macro Equ"
	case KsErrAsmMacroArgs:
		return "Ks Err Asm Macro Args"
	case KsErrAsmMacroLevelsExceed:
		return "Ks Err Asm Macro Levels Exceed"
	case KsErrAsmMacroStr:
		return "Ks Err Asm Macro Str"
	case KsErrAsmMacroInvalid:
		return "Ks Err Asm Macro Invalid"
	case KsErrAsmEscBackslash:
		return "Ks Err Asm Esc Backslash"
	case KsErrAsmEscOctal:
		return "Ks Err Asm Esc Octal"
	case KsErrAsmEscSequence:
		return "Ks Err Asm Esc Sequence"
	case KsErrAsmEscStr:
		return "Ks Err Asm Esc Str"
	case KsErrAsmTokenInvalid:
		return "Ks Err Asm Token Invalid"
	case KsErrAsmInsnUnsupported:
		return "Ks Err Asm Insn Unsupported"
	case KsErrAsmFixupInvalid:
		return "Ks Err Asm Fixup Invalid"
	case KsErrAsmLabelInvalid:
		return "Ks Err Asm Label Invalid"
	case KsErrAsmFragmentInvalid:
		return "Ks Err Asm Fragment Invalid"
	case KsErrAsmInvalidoperand:
		return "Ks Err Asm Invalidoperand"
	case KsErrAsmMissingfeature:
		return "Ks Err Asm Missingfeature"
	case KsErrAsmMnemonicfail:
		return "Ks Err Asm Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err(0x%X)", uint32(k))
	}
}

// Source: keystone.h:173 -> ks_opt_type
type Ks_opt_type uint32

const (
	KsOptSyntax Ks_opt_type = 1 + iota
	KsOptSymResolver
)

func (k Ks_opt_type) String() string {
	switch k {
	case KsOptSyntax:
		return "Ks Opt Syntax"
	case KsOptSymResolver:
		return "Ks Opt Sym Resolver"
	default:
		return fmt.Sprintf("Ks_opt_type(0x%X)", uint32(k))
	}
}

// Source: keystone.h:180 -> ks_opt_value
type Ks_opt_value uint32

const (
	KsOptSyntaxIntel   Ks_opt_value = 1
	KsOptSyntaxAtt     Ks_opt_value = 2
	KsOptSyntaxNasm    Ks_opt_value = 4
	KsOptSyntaxMasm    Ks_opt_value = 8
	KsOptSyntaxGas     Ks_opt_value = 16
	KsOptSyntaxRadix16 Ks_opt_value = 32
)

func (k Ks_opt_value) String() string {
	switch k {
	case KsOptSyntaxIntel:
		return "Ks Opt Syntax Intel"
	case KsOptSyntaxAtt:
		return "Ks Opt Syntax Att"
	case KsOptSyntaxNasm:
		return "Ks Opt Syntax Nasm"
	case KsOptSyntaxMasm:
		return "Ks Opt Syntax Masm"
	case KsOptSyntaxGas:
		return "Ks Opt Syntax Gas"
	case KsOptSyntaxRadix16:
		return "Ks Opt Syntax Radix 16"
	default:
		return fmt.Sprintf("Ks_opt_value(0x%X)", uint32(k))
	}
}

// Source: arm64.h:13 -> ks_err_asm_arm64
type Ks_err_asm_arm64 uint32

const (
	KsErrAsmArm64Invalidoperand Ks_err_asm_arm64 = 512 + iota
	KsErrAsmArm64Missingfeature
	KsErrAsmArm64Mnemonicfail
)

func (k Ks_err_asm_arm64) String() string {
	switch k {
	case KsErrAsmArm64Invalidoperand:
		return "Ks Err Asm Arm 64 Invalidoperand"
	case KsErrAsmArm64Missingfeature:
		return "Ks Err Asm Arm 64 Missingfeature"
	case KsErrAsmArm64Mnemonicfail:
		return "Ks Err Asm Arm 64 Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_arm64(0x%X)", uint32(k))
	}
}

// Source: arm.h:13 -> ks_err_asm_arm
type Ks_err_asm_arm uint32

const (
	KsErrAsmArmInvalidoperand Ks_err_asm_arm = 512 + iota
	KsErrAsmArmMissingfeature
	KsErrAsmArmMnemonicfail
)

func (k Ks_err_asm_arm) String() string {
	switch k {
	case KsErrAsmArmInvalidoperand:
		return "Ks Err Asm Arm Invalidoperand"
	case KsErrAsmArmMissingfeature:
		return "Ks Err Asm Arm Missingfeature"
	case KsErrAsmArmMnemonicfail:
		return "Ks Err Asm Arm Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_arm(0x%X)", uint32(k))
	}
}

// Source: evm.h:13 -> ks_err_asm_evm
type Ks_err_asm_evm uint32

const (
	KsErrAsmEvmInvalidoperand Ks_err_asm_evm = 512 + iota
	KsErrAsmEvmMissingfeature
	KsErrAsmEvmMnemonicfail
)

func (k Ks_err_asm_evm) String() string {
	switch k {
	case KsErrAsmEvmInvalidoperand:
		return "Ks Err Asm Evm Invalidoperand"
	case KsErrAsmEvmMissingfeature:
		return "Ks Err Asm Evm Missingfeature"
	case KsErrAsmEvmMnemonicfail:
		return "Ks Err Asm Evm Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_evm(0x%X)", uint32(k))
	}
}

// Source: hexagon.h:13 -> ks_err_asm_hexagon
type Ks_err_asm_hexagon uint32

const (
	KsErrAsmHexagonInvalidoperand Ks_err_asm_hexagon = 512 + iota
	KsErrAsmHexagonMissingfeature
	KsErrAsmHexagonMnemonicfail
)

func (k Ks_err_asm_hexagon) String() string {
	switch k {
	case KsErrAsmHexagonInvalidoperand:
		return "Ks Err Asm Hexagon Invalidoperand"
	case KsErrAsmHexagonMissingfeature:
		return "Ks Err Asm Hexagon Missingfeature"
	case KsErrAsmHexagonMnemonicfail:
		return "Ks Err Asm Hexagon Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_hexagon(0x%X)", uint32(k))
	}
}

// Source: mips.h:13 -> ks_err_asm_mips
type Ks_err_asm_mips uint32

const (
	KsErrAsmMipsInvalidoperand Ks_err_asm_mips = 512 + iota
	KsErrAsmMipsMissingfeature
	KsErrAsmMipsMnemonicfail
)

func (k Ks_err_asm_mips) String() string {
	switch k {
	case KsErrAsmMipsInvalidoperand:
		return "Ks Err Asm Mips Invalidoperand"
	case KsErrAsmMipsMissingfeature:
		return "Ks Err Asm Mips Missingfeature"
	case KsErrAsmMipsMnemonicfail:
		return "Ks Err Asm Mips Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_mips(0x%X)", uint32(k))
	}
}

// Source: ppc.h:13 -> ks_err_asm_ppc
type Ks_err_asm_ppc uint32

const (
	KsErrAsmPpcInvalidoperand Ks_err_asm_ppc = 512 + iota
	KsErrAsmPpcMissingfeature
	KsErrAsmPpcMnemonicfail
)

func (k Ks_err_asm_ppc) String() string {
	switch k {
	case KsErrAsmPpcInvalidoperand:
		return "Ks Err Asm Ppc Invalidoperand"
	case KsErrAsmPpcMissingfeature:
		return "Ks Err Asm Ppc Missingfeature"
	case KsErrAsmPpcMnemonicfail:
		return "Ks Err Asm Ppc Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_ppc(0x%X)", uint32(k))
	}
}

// Source: riscv.h:13 -> ks_err_asm_riscv
type Ks_err_asm_riscv uint32

const (
	KsErrAsmRiscvInvalidoperand Ks_err_asm_riscv = 512 + iota
	KsErrAsmRiscvMissingfeature
	KsErrAsmRiscvMnemonicfail
)

func (k Ks_err_asm_riscv) String() string {
	switch k {
	case KsErrAsmRiscvInvalidoperand:
		return "Ks Err Asm Riscv Invalidoperand"
	case KsErrAsmRiscvMissingfeature:
		return "Ks Err Asm Riscv Missingfeature"
	case KsErrAsmRiscvMnemonicfail:
		return "Ks Err Asm Riscv Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_riscv(0x%X)", uint32(k))
	}
}

// Source: sparc.h:13 -> ks_err_asm_sparc
type Ks_err_asm_sparc uint32

const (
	KsErrAsmSparcInvalidoperand Ks_err_asm_sparc = 512 + iota
	KsErrAsmSparcMissingfeature
	KsErrAsmSparcMnemonicfail
)

func (k Ks_err_asm_sparc) String() string {
	switch k {
	case KsErrAsmSparcInvalidoperand:
		return "Ks Err Asm Sparc Invalidoperand"
	case KsErrAsmSparcMissingfeature:
		return "Ks Err Asm Sparc Missingfeature"
	case KsErrAsmSparcMnemonicfail:
		return "Ks Err Asm Sparc Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_sparc(0x%X)", uint32(k))
	}
}

// Source: systemz.h:13 -> ks_err_asm_systemz
type Ks_err_asm_systemz uint32

const (
	KsErrAsmSystemzInvalidoperand Ks_err_asm_systemz = 512 + iota
	KsErrAsmSystemzMissingfeature
	KsErrAsmSystemzMnemonicfail
)

func (k Ks_err_asm_systemz) String() string {
	switch k {
	case KsErrAsmSystemzInvalidoperand:
		return "Ks Err Asm Systemz Invalidoperand"
	case KsErrAsmSystemzMissingfeature:
		return "Ks Err Asm Systemz Missingfeature"
	case KsErrAsmSystemzMnemonicfail:
		return "Ks Err Asm Systemz Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_systemz(0x%X)", uint32(k))
	}
}

// Source: x86.h:13 -> ks_err_asm_x86
type Ks_err_asm_x86 uint32

const (
	KsErrAsmX86Invalidoperand Ks_err_asm_x86 = 512 + iota
	KsErrAsmX86Missingfeature
	KsErrAsmX86Mnemonicfail
)

func (k Ks_err_asm_x86) String() string {
	switch k {
	case KsErrAsmX86Invalidoperand:
		return "Ks Err Asm X86 Invalidoperand"
	case KsErrAsmX86Missingfeature:
		return "Ks Err Asm X86 Missingfeature"
	case KsErrAsmX86Mnemonicfail:
		return "Ks Err Asm X86 Mnemonicfail"
	default:
		return fmt.Sprintf("Ks_err_asm_x86(0x%X)", uint32(k))
	}
}

type (
	Ks_struct struct{} // keystone.h:38 -> ks_struct
)

func KsMakeVersion(Major uint32, Minor uint32) uint32 {
	return uint32(((Major << 8) + Minor))
}

// Source: keystone.h -> Macro constants
const (
	KsApiMajor     uint32 = 0
	KsApiMinor     uint32 = 9
	KsVersionMajor uint32 = KsApiMajor
	KsVersionMinor uint32 = KsApiMinor
	KsVersionExtra uint32 = 2
	KsErrAsm       uint32 = 128
	KsErrAsmArch   uint32 = 512
)

func (k *Keystone) KsVersion(Major *uint32, Minor *uint32) uint32 {
	r1, _, _ := getProc("ks_version").Call(uintptr(unsafe.Pointer(Major)), uintptr(unsafe.Pointer(Minor)))
	return uint32(r1)
}

func (k *Keystone) KsArchSupported(Arch Ks_arch) bool {
	r1, _, _ := getProc("ks_arch_supported").Call(uintptr(Arch))
	return r1 != 0
}

func (k *Keystone) KsOpen(Arch Ks_arch, Mode int32, Ks **Ks_engine) Ks_err {
	r1, _, _ := getProc("ks_open").Call(uintptr(Arch), uintptr(Mode), uintptr(unsafe.Pointer(Ks)))
	return Ks_err(uint32(r1))
}

func (k *Keystone) KsClose(Ks *Ks_engine) Ks_err {
	r1, _, _ := getProc("ks_close").Call(uintptr(unsafe.Pointer(Ks)))
	return Ks_err(uint32(r1))
}

func (k *Keystone) KsErrno(Ks *Ks_engine) Ks_err {
	r1, _, _ := getProc("ks_errno").Call(uintptr(unsafe.Pointer(Ks)))
	return Ks_err(uint32(r1))
}

func (k *Keystone) KsStrerror(Code Ks_err) *int8 {
	r1, _, _ := getProc("ks_strerror").Call(uintptr(Code))
	return (*int8)(unsafe.Pointer(r1))
}

func (k *Keystone) KsOption(Ks *Ks_engine, Type Ks_opt_type, Value uintptr) Ks_err {
	r1, _, _ := getProc("ks_option").Call(uintptr(unsafe.Pointer(Ks)), uintptr(Type), Value)
	return Ks_err(uint32(r1))
}

func (k *Keystone) KsAsm(Ks *Ks_engine, String *int8, Address uint64, Encoding **uint8, Encoding_size *uintptr, Stat_count *uintptr) int32 {
	r1, _, _ := getProc("ks_asm").Call(uintptr(unsafe.Pointer(Ks)), uintptr(unsafe.Pointer(String)), *(*uintptr)(unsafe.Pointer(&Address)), uintptr(unsafe.Pointer(Encoding)), uintptr(unsafe.Pointer(Encoding_size)), uintptr(unsafe.Pointer(Stat_count)))
	return int32(r1)
}

func (k *Keystone) KsFree(P *uint8) {
	getProc("ks_free").Call(uintptr(unsafe.Pointer(P)))
}

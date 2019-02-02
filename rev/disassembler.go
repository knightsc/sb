package rev

import (
	"bytes"
	"debug/macho"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/knightsc/gapstone"
)

// Symbol is a
type Symbol struct {
	Name    string
	Address uint64
	Offset  uint64
}

func (s *Symbol) String() string {
	return fmt.Sprintf("%s %016x %016x", s.Name, s.Address, s.Offset)
}

// File is a
type File struct {
	file   *macho.File
	engine gapstone.Engine
	code   []gapstone.Instruction
	ip     int
}

// OpenFile does
func OpenFile(name string) (*File, error) {
	f := &File{}

	if err := f.initMachoFile(name); err != nil {
		return nil, err
	}

	if err := f.initEngine(); err != nil {
		return nil, err
	}

	if err := f.initCode(); err != nil {
		return nil, err
	}

	return f, nil
}

func (f *File) initMachoFile(name string) error {
	var err error
	f.file, err = macho.Open(name)
	if err != nil {
		fatFile, err := macho.OpenFat(name)
		if err != nil {
			return err
		}

		for _, arch := range fatFile.Arches {
			if arch.Cpu == macho.CpuAmd64 ||
				arch.Cpu == macho.CpuArm64 {
				f.file = arch.File
				break
			}
		}

		if (f.file == nil) ||
			((f.file.Cpu != macho.CpuAmd64) &&
				(f.file.Cpu != macho.CpuArm64)) {
			return errors.New("only x86_64 and arm64 are supported")
		}
	}

	return nil
}

func (f *File) initEngine() error {
	var err error
	arch, mode := archModeFromCPU(f.file.Cpu)
	f.engine, err = gapstone.New(arch, mode)
	f.engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	f.engine.SetOption(gapstone.CS_OPT_SKIPDATA, gapstone.CS_OPT_ON)

	if err != nil {
		return err
	}

	return nil
}

func archModeFromCPU(cpu macho.Cpu) (arch int, mode int) {
	switch cpu {
	case macho.CpuAmd64:
		arch = gapstone.CS_ARCH_X86
		mode = gapstone.CS_MODE_64
	case macho.CpuArm64:
		arch = gapstone.CS_ARCH_ARM64
		mode = gapstone.CS_MODE_ARM
	default:
		arch = 0
		mode = 0
	}

	return arch, mode
}

func (f *File) initCode() error {
	sec := f.file.Section("__text")
	if sec == nil {
		return errors.New("section __text not found")
	}

	text, err := sec.Data()
	if err != nil {
		return err
	}

	insns, err := f.engine.Disasm(text, sec.Addr, 0)
	if err != nil {
		return err
	}

	f.code = insns
	f.ip = 0

	return nil
}

// CloseFile closes engine
func (f *File) CloseFile() error {
	if err := f.file.Close(); err != nil {
		return err
	}

	if err := f.engine.Close(); err != nil {
		return err
	}

	return nil
}

// FindSymbol looks for a named symbol
func (f *File) FindSymbol(name string) (*Symbol, error) {
	for _, sym := range f.file.Symtab.Syms {
		if sym.Name == name {
			s := &Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Offset:  0,
			}
			return s, nil
		}
	}

	return nil, fmt.Errorf("symbol %s not found", name)
}

// FindString looks for a C string in the __cstring section
func (f *File) FindString(s string) (*Symbol, error) {
	sec := f.file.Section("__cstring")
	if sec == nil {
		return nil, errors.New("section __cstring not found")
	}

	cstring, err := sec.Data()
	if err != nil {
		return nil, errors.New("error getting section data")
	}

	pos := bytes.Index(cstring, []byte(s))
	if pos != -1 {
		s := &Symbol{
			Name:    stringToSymbolName(s),
			Address: sec.Addr + uint64(pos),
			Offset:  uint64(sec.Offset + uint32(pos)),
		}
		return s, nil
	}

	return nil, fmt.Errorf("string \"%s\" not found", s)
}

func stringToSymbolName(s string) string {
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		log.Fatal(err)
	}
	processedString := reg.ReplaceAllString(strings.Title(s), "")

	return "a" + processedString[:14]
}

// XrefsTo Getting xrefs - dependent on searching for instructions
func (f *File) XrefsTo(addr uint64) []uint64 {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	for f.ip < len(f.code) {
		insn := f.code[f.ip]

		if f.hasXref() {
			xref := f.xref()
			if addr == xref {
				fmt.Fprintf(w, "%016x\t%s\t%s\t%s\n", insn.Address, hex.EncodeToString(insn.Bytes), insn.Mnemonic, insn.OpStr)
			}
		}
		f.ip++
	}
	f.ip = 0

	w.Flush()

	return nil
}

func (f *File) hasXref() bool {
	insn := f.code[f.ip]
	switch f.file.Cpu {
	case macho.CpuAmd64:
		return insn.Mnemonic == "lea" &&
			insn.X86.Operands[1].Type == gapstone.X86_OP_MEM &&
			insn.X86.Operands[1].Mem.Base == gapstone.X86_REG_RIP
	case macho.CpuArm64:
		return insn.Mnemonic == "adrp" && f.code[f.ip+1].Mnemonic == "add"
	default:
		return false
	}
}

func (f *File) xref() uint64 {
	insn := f.code[f.ip]
	switch f.file.Cpu {
	case macho.CpuAmd64:
		// rip + offset
		return uint64(int64(f.code[f.ip+1].Address) + insn.X86.Operands[1].Mem.Disp)
	case macho.CpuArm64:
		//adrp imm + add imm
		return uint64(insn.Arm64.Operands[1].Imm) + uint64(f.code[f.ip+1].Arm64.Operands[2].Imm)
	default:
		return 0
	}
}

// getting procedures
// return instructions?

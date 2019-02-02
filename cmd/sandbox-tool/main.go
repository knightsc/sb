package main

import (
	"fmt"
	"log"
	"os"

	"github.com/knightsc/sb/rev"
)

// From Sandbox.kext
// extract offset names operation_names
// extract platform profile platform_profile
// extract profile collections sandbox_collection

// From libsandbox.dylib
// extract scm files
// filter_info
// modifier_info
// operation_info

func main() {
	filename := os.Args[1]

	f, err := rev.OpenFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.CloseFile()

	sym, err := f.FindString("\"failed to initialize platform sandbox")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sym.String())
	fmt.Println()

	f.XrefsTo(sym.Address)
	// for _, xref := range m.XrefsTo(sym.Address) {

	// }

	// text := f.Section("__text")
	// data, err = text.Data()

	// off := 0
	// var errorAddressXref uint64
	// for len(data) > 0 {
	// 	pos := bytes.Index(data[off:], []byte{0x48, 0x8d})
	// 	if pos != -1 {
	// 		rip := text.SectionHeader.Addr + uint64(off+pos) + 0x7 //length of LEA
	// 		modrm := data[off+pos+2 : off+pos+3]

	// 		// RIP relative LEA only
	// 		if (modrm[0] & 0xc5) == 0x5 {
	// 			relativeAddress := int32(binary.LittleEndian.Uint32(data[off+pos+3 : off+pos+7]))
	// 			addr := rip + uint64(relativeAddress)

	// 			// fmt.Printf("%016x lea reg [%016x]\n", (text.SectionHeader.Addr + uint64(off+pos)), addr)

	// 			if addr == errorAddress {
	// 				fmt.Printf("error message xref = 0x%016x\n", (text.SectionHeader.Addr + uint64(off+pos)))
	// 				errorAddressXref = text.SectionHeader.Addr + uint64(off+pos)
	// 			}
	// 		}

	// 		off = off + pos + 7
	// 	} else {
	// 		break
	// 	}
	// }

	// off = int(errorAddressXref - text.SectionHeader.Addr)

	// // search backwards for func start
	// ins32 := binary.BigEndian.Uint32(data[off : off+5])
	// for ins32 != 0x554889e5 {
	// 	off--
	// 	ins32 = binary.BigEndian.Uint32(data[off : off+5])
	// }
	// funcStart := text.SectionHeader.Addr + uint64(off)
	// // fmt.Printf("%016x push rbp\n", funcStart)

	// // search forwards for func end
	// ins16 := binary.BigEndian.Uint16(data[off : off+5])
	// for ins16 != 0x5dc3 {
	// 	off++
	// 	ins16 = binary.BigEndian.Uint16(data[off : off+3])
	// }
	// funcEnd := text.SectionHeader.Addr + uint64(off) + 1
	// // fmt.Printf("%016x pop rbp\n", funcEnd)

	// engine, err := gapstone.New(
	// 	gapstone.CS_ARCH_X86,
	// 	gapstone.CS_MODE_64,
	// )

	// if err == nil {
	// 	defer engine.Close()

	// 	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	// 	code := data[funcStart-text.SectionHeader.Addr : funcEnd-text.SectionHeader.Addr+1]
	// 	insns, err := engine.Disasm(code, funcStart, 0)
	// 	if err == nil {
	// 		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	// 		for count, insn := range insns {
	// 			fmt.Fprintf(w, "%016x\t%s\t%s\t%s", insn.Address, hex.EncodeToString(insn.Bytes), insn.Mnemonic, insn.OpStr)
	// 			if insn.Address == uint(errorAddressXref) {
	// 				i := count
	// 				for insns[i].Mnemonic != "call" {
	// 					i--
	// 				}
	// 				// createProfileAddress := insns[i].X86.Operands[0].Imm
	// 				for {
	// 					i--
	// 					if len(insns[i].X86.Operands) == 2 && insns[i].X86.Operands[1].Type == gapstone.CS_OP_IMM {
	// 						break
	// 					}
	// 				}
	// 				length := insns[i].X86.Operands[1].Imm

	// 				for {
	// 					i--
	// 					if len(insns[i].X86.Operands) == 2 &&
	// 						insns[i].X86.Operands[0].Type == gapstone.CS_OP_REG &&
	// 						insns[i].X86.Operands[0].Reg == gapstone.X86_REG_RSI {
	// 						break
	// 					}
	// 				}

	// 				addr := int64(insns[i+1].Address) + insns[i].X86.Operands[1].Mem.Disp
	// 				fmt.Printf("platform_profile = 0x%016x 0x%04x\n\n", addr, length)

	// 				fmt.Fprintf(w, " <------- failed to initialize platform sandbox")

	// 			}
	// 			fmt.Fprintf(w, "\n")
	// 		}
	// 		w.Flush()
	// 	}
	// 	// disassembly error
	// }
	// engine failed to open

	// off = int(errorAddressXref - text.SectionHeader.Addr)

	// go backwards to mov ecx
	// for {
	// 	off--
	// 	if data[off] == 0xb9 {
	// 		break
	// 	}
	// }
	// length := binary.LittleEndian.Uint32(data[off+1 : off+5])

	// go backwards to lea
	// for {
	// 	off--
	// 	if data[off] == 0x8d {
	// 		off = off - 0x4
	// 		break
	// 	}
	// }
	// rip := text.SectionHeader.Addr + uint64(off) + 0x7 //length of LEA
	// relativeAddress := int32(binary.LittleEndian.Uint32(data[off+3 : off+7]))
	// addr := rip + uint64(relativeAddress)

	// fmt.Printf("%016x %04x lea reg [%016x]\n", (text.SectionHeader.Addr + uint64(off)), relativeAddress, addr)

	// sym, err := FindSymbol(f, "_the_real_platform_profile_data")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("%v\n", sym)
	// var address uint64 = 0x000000000001b6b8
	// bs := make([]byte, 8)
	// fmt.Printf("0x%016x\n", address)
	// binary.LittleEndian.PutUint64(bs, address)
	// for _, b := range bs {
	// 	fmt.Printf("%02x ", b)
	// }
	// fmt.Printf("\n")

	// for _, load := range f.Loads {
	// 	if seg, ok := load.(*macho.Segment); ok {
	// 		data, err := seg.Data()
	// 		if err == nil {
	// 			pos := bytes.Index(data, bs)
	// 			if pos != -1 {
	// 				fmt.Printf("0x%016x\n", (seg.SegmentHeader.Offset + uint64(pos)))
	// 			}
	// 		} else {
	// 			fmt.Printf("%s", err.Error())
	// 		}
	// 	}
	// }
}

// search for failed to initialize platform sandbox
// Find xref
// Find enclosing procedure start and end
// create slice of procedure
// Disassemble

// Walk backwords to the call that is do_profile_create
// walk backwards to the platform_profile size
// walk backwards to _the_real_platform_profile_data
// walk backwards to _previous do_profile_create (not everything has the collection 10.10 doesn't)
// walk backwards to collection size
// walk backwards to collection_data
// extract both
// Calculate op size
// extract proper operation names

// earlier versions had it in sandboxd? I don't really care about 10.9 or earlier macOS 10 and iOS 8 and above

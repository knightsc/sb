package sb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
)

// A FormatError reports that the input is not a valid sandbox profile
type FormatError string

func (e FormatError) Error() string { return "sb: invalid format: " + string(e) }

// Version represents what specific format the binary sandbox profile follows.
type Version int

const (
	// Version1 sandbox files have no globals or patterns.
	Version1 Version = iota + 1

	// Version2 sandbox files are the same as Version1 with the addition of globals.
	Version2

	// Version3 sandbox files have a slightly different structure and additionally
	// new fields for patterns.
	Version3
)

func (v Version) headerLength() uint16 {
	switch v {
	case Version1:
		return 0x6
	case Version2:
		return 0xa
	default:
		// Version3 and above
		return 0xc
	}
}

// An Entry represents a chunk of binary data in a Table.
type Entry struct {
	Offset uint16
	Length uint32
	Raw    []uint8
}

// A Table represents one of the different data tables found in a Profile.
type Table struct {
	TableOffset uint16
	TableCount  uint16
	Entries     []Entry
}

// A Profile represents a compiled sandbox profile.
type Profile struct {
	Version
	Magic   uint16
	Ops     []Operation
	OpNodes map[uint16]OperationNode
	Regexp  *Table
	Global  *Table
	Pattern *Table

	closer io.Closer
	sr     *io.SectionReader
}

// An Operation represents ...
type Operation struct {
	Idx    int
	Name   string
	Offset uint16
}

// An OperationNode represents the filters and actions
type OperationNode struct {
	Type          uint8
	Filter        uint8
	Value         uint16
	MatchOffset   uint16
	UnmatchOffset uint16
}

// Open opens the named file using os.Open and prepares it for use as a sandbox Profile.
func Open(name string) (*Profile, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	p, err := NewProfile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	p.closer = f
	return p, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (p *Profile) Close() error {
	var err error
	if p.closer != nil {
		err = p.closer.Close()
		p.closer = nil
	}
	return err
}

// NewProfile creates a new instance of a compiled sandbox Profile object.
func NewProfile(r io.ReaderAt) (*Profile, error) {
	p := new(Profile)
	p.sr = io.NewSectionReader(r, 0, 1<<63-1)
	p.Regexp = new(Table)
	p.Global = new(Table)
	p.Pattern = new(Table)

	if err := p.readHeader(); err != nil {
		return nil, err
	}

	if err := p.loadTable(p.Regexp); err != nil {
		return nil, err
	}

	if err := p.loadTable(p.Global); err != nil {
		return nil, err
	}

	if err := p.loadTable(p.Pattern); err != nil {
		return nil, err
	}

	p.sr.Seek(int64(p.Version.headerLength()), io.SeekStart)
	idx := 0
	for {
		var offset uint16
		binary.Read(p.sr, binary.LittleEndian, &offset)
		if offset == 0x0000 {
			// skip padding
			continue
		} else if offset&0x00ff == 0x0000 {
			// reached the start of the OpNodes
			break
		} else {
			op := Operation{
				Idx:    idx,
				Offset: offset,
			}
			p.Ops = append(p.Ops, op)
		}
		idx++
	}

	operationNames := OperationNames[len(p.Ops)]
	if operationNames == nil {
		return nil, FormatError("no matching operation_names found.")
	}

	for i := 0; i < len(p.Ops); i++ {
		p.Ops[i].Name = operationNames[p.Ops[i].Idx]
	}

	start, _ := p.sr.Seek(-2, io.SeekCurrent)
	end := int64(p.Regexp.TableOffset * 8)

	p.OpNodes = make(map[uint16]OperationNode)
	for start < end {
		on := OperationNode{}
		binary.Read(p.sr, binary.LittleEndian, &on)
		p.OpNodes[uint16(start/8)] = on
		start += 8
	}

	return p, nil
}

func (p *Profile) loadTable(t *Table) error {
	if t.TableCount > 0 {
		t.Entries = make([]Entry, t.TableCount)
		for i := uint16(0); i < t.TableCount; i++ {
			if _, err := p.sr.Seek(int64(t.TableOffset*8+i*2), io.SeekStart); err != nil {
				return err
			}

			e := Entry{}
			if err := binary.Read(p.sr, binary.LittleEndian, &e.Offset); err != nil {
				return err
			}

			if _, err := p.sr.Seek(int64(e.Offset*8), io.SeekStart); err != nil {
				return err
			}

			if err := binary.Read(p.sr, binary.LittleEndian, &e.Length); err != nil {
				return err
			}

			e.Raw = make([]uint8, e.Length)
			if err := binary.Read(p.sr, binary.LittleEndian, &e.Raw); err != nil {
				return err
			}
			t.Entries[i] = e
		}
	}
	return nil
}

func sortedKeys(m map[uint16]OperationNode) []int {
	keys := make([]int, len(m))
	i := 0
	for k := range m {
		keys[i] = int(k)
		i++
	}
	sort.Ints(keys)
	return keys
}

func (p *Profile) GoString() string {
	var b bytes.Buffer

	b.WriteString(fmt.Sprintf("Version: %d\n", p.Version))
	b.WriteString(fmt.Sprintf("Magic: 0x%04x\n", p.Magic))
	b.WriteString(fmt.Sprintf("Header Length: 0x%04x\n", p.Version.headerLength()))
	b.WriteString("\n")

	// sort.Slice(p.Ops, func(i, j int) bool {
	// 	if p.Ops[i].Offset < p.Ops[j].Offset {
	// 		return true
	// 	}
	// 	if p.Ops[i].Offset > p.Ops[j].Offset {
	// 		return false
	// 	}
	// 	return p.Ops[i].Idx < p.Ops[j].Idx
	// })
	for i := 0; i < len(p.Ops); i++ {
		b.WriteString(fmt.Sprintf("0x%04x: %s\n", p.Ops[i].Offset, p.Ops[i].Name))
	}
	b.WriteString("\n")

	for _, offset := range sortedKeys(p.OpNodes) {
		n := p.OpNodes[uint16(offset)]
		b.WriteString(fmt.Sprintf("0x%04x: (%02x %02x %04x %04x %04x)\n", offset, n.Type, n.Filter, n.Value, n.MatchOffset, n.UnmatchOffset))
	}
	b.WriteString("\n")

	printTable := func(t *Table) {
		b.WriteString(fmt.Sprintf("Table Offset: 0x%04x\n", t.TableOffset))
		b.WriteString(fmt.Sprintf(" Table Count: 0x%04x\n", t.TableCount))
		b.WriteString("\n")
		for i := uint16(0); i < t.TableCount; i++ {
			b.WriteString(fmt.Sprintf("Entry Offset: 0x%04x\n", t.Entries[i].Offset))
			b.WriteString(fmt.Sprintf("Entry Length: 0x%08x\n", t.Entries[i].Length))
			b.WriteString(hex.Dump(t.Entries[i].Raw))
			b.WriteString("\n")
		}
	}

	b.WriteString("Regexps\n")
	b.WriteString("--------------------\n")
	printTable(p.Regexp)
	b.WriteString("Globals\n")
	b.WriteString("--------------------\n")
	printTable(p.Global)
	b.WriteString("Patterns\n")
	b.WriteString("--------------------\n")
	printTable(p.Pattern)

	return b.String()
}

func (p *Profile) readHeader() error {
	if _, err := p.sr.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := binary.Read(p.sr, binary.LittleEndian, &p.Magic); err != nil {
		return err
	}
	if p.Magic != 0x0000 {
		return FormatError("bad magic identifier")
	}

	if err := binary.Read(p.sr, binary.LittleEndian, &p.Regexp.TableOffset); err != nil {
		return err
	}

	p.readHeaderVersion3()
	if p.Pattern.TableOffset < p.Regexp.TableOffset {
		// Since the pattern section comes after the re section the number
		// should not be smaller. If it is then most likely we have a count and
		// should fallback to version 2
		p.readHeaderVersion2()
	}

	if p.Global.TableOffset < p.Regexp.TableOffset {
		// If there is a global var offset it should always be bigger than the
		// RE Table offsets. If it's not then we probably don't have global vars
		// and should fall back to the version 1 format
		p.readHeaderVersion1()
	}

	return nil
}

func (p *Profile) readHeaderVersion1() error {
	if _, err := p.sr.Seek(0x4, io.SeekStart); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Regexp.TableCount); err != nil {
		return err
	}

	p.Pattern.TableOffset = 0
	p.Pattern.TableCount = 0
	p.Global.TableOffset = 0
	p.Global.TableCount = 0
	p.Version = Version1

	return nil
}

func (p *Profile) readHeaderVersion2() error {
	if _, err := p.sr.Seek(0x4, io.SeekStart); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Regexp.TableCount); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Global.TableOffset); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Global.TableCount); err != nil {

	}
	p.Pattern.TableOffset = 0
	p.Pattern.TableCount = 0
	p.Version = Version2

	return nil
}

func (p *Profile) readHeaderVersion3() error {
	if _, err := p.sr.Seek(0x4, io.SeekStart); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Pattern.TableOffset); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Global.TableOffset); err != nil {
		return err
	}
	if err := binary.Read(p.sr, binary.LittleEndian, &p.Regexp.TableCount); err != nil {
		return err
	}
	var b uint8
	if err := binary.Read(p.sr, binary.LittleEndian, &b); err != nil {
		return err
	}
	p.Pattern.TableCount = uint16(b)
	if err := binary.Read(p.sr, binary.LittleEndian, &b); err != nil {
		return err
	}
	p.Global.TableCount = uint16(b)

	p.Version = Version3

	return nil
}

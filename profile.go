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
		b.WriteString(fmt.Sprintf("0x%04x: (%02x %02x %04x %04x %04x)", offset, n.Type, n.Filter, n.Value, n.MatchOffset, n.UnmatchOffset))
		switch n.Filter {
		case 0x00:
			b.WriteString(" null")
		case 0x01:
			b.WriteString(" path")
		case 0x02:
			b.WriteString(" mount-relative-path")
		case 0x03:
			b.WriteString(" xattr")
		case 0x04:
			b.WriteString(" file-mode")
		case 0x05:
			b.WriteString(" ipc-posix-name")
		case 0x06:
			b.WriteString(" global-name")
		case 0x07:
			b.WriteString(" local-name")
		case 0x08:
			b.WriteString(" local")
		case 0x09:
			b.WriteString(" remote")
		case 0x0a:
			b.WriteString(" control-name")
		case 0x0b:
			b.WriteString(" socket-domain")
		case 0x0c:
			b.WriteString(" socket-type")
		case 0x0d:
			b.WriteString(" socket-protocol")
		case 0x0e:
			b.WriteString(" target")
		case 0x0f:
			b.WriteString(" fsctl-command")
		case 0x10:
			b.WriteString(" ioctl-command")
		case 0x11:
			b.WriteString(" iokit-register-entry-class")
		case 0x12:
			b.WriteString(" iokit-property")
		case 0x13:
			b.WriteString(" iokit-connection")
		case 0x14:
			b.WriteString(" device-major")
		case 0x15:
			b.WriteString(" device-minor")
		case 0x16:
			b.WriteString(" device-conforms-to")
		case 0x17:
			b.WriteString(" extension")
		case 0x18:
			b.WriteString(" extension-class")
		case 0x19:
			b.WriteString(" appleevent-destination")
		case 0x1a:
			b.WriteString(" system-attribute")
		case 0x1b:
			b.WriteString(" right-name")
		case 0x1c:
			b.WriteString(" preference-domain")
		case 0x1d:
			b.WriteString(" vnode-type")
		case 0x1e:
			b.WriteString(" %entitlement-load")
		case 0x1f:
			b.WriteString(" %entitlement-boolean")
		case 0x20:
			b.WriteString(" %entitlement-string")
		case 0x21:
			b.WriteString(" kext-bundle-id")
		case 0x22:
			b.WriteString(" info-type")
		case 0x23:
			b.WriteString(" notification-name")
		case 0x24:
			b.WriteString(" notification-payload")
		case 0x25:
			b.WriteString(" semaphore-owner")
		case 0x26:
			b.WriteString(" sysctl-name")
		case 0x27:
			b.WriteString(" process-path")
		case 0x28:
			b.WriteString(" rootless-boot-device-filter")
		case 0x29:
			b.WriteString(" rootless-disk-filter")
		case 0x2a:
			b.WriteString(" privilege-id")
		case 0x2b:
			b.WriteString(" process-attribute")
		case 0x2c:
			b.WriteString(" uid")
		case 0x2d:
			b.WriteString(" nvram-variable")
		case 0x2e:
			b.WriteString(" csr")
		case 0x2f:
			b.WriteString(" host-special-port")
		case 0x30:
			b.WriteString(" filesystem-name")
		case 0x31:
			b.WriteString(" boot-arg")
		case 0x32:
			b.WriteString(" xpc-service-name")
		case 0x33:
			b.WriteString(" signing-identifier")
		case 0x34:
			b.WriteString(" signal-number")
		case 0x35:
			b.WriteString(" target-signing-identifier")
		case 0x36:
			b.WriteString(" reboot-flags")
		case 0x37:
			b.WriteString(" datavault-disk-filter")
		case 0x38:
			b.WriteString(" extension-path-ancestor")
		case 0x39:
			b.WriteString(" file-attribute")
		case 0x3a:
			b.WriteString(" storage-class")
		case 0x3b:
			b.WriteString(" storage-class-extension")
		case 0x3c:
			b.WriteString(" iokit-usb-interface-class")
		case 0x3d:
			b.WriteString(" iokit-usb-interface-subclass")
		case 0x3e:
			b.WriteString(" ancestor-signing-identifier")
		case 0x3f:
			b.WriteString(" require-ancestor-with-entitlement")
		case 0x81:
			b.WriteString(" regex")
		case 0x82:
			b.WriteString(" mount-relative-regex")
		case 0x83:
			b.WriteString(" xattr-regex")
		case 0x85:
			b.WriteString(" ipc-posix-name-regex")
		case 0x86:
			b.WriteString(" global-name-regex")
		case 0x87:
			b.WriteString(" local-name-regex")
		case 0x91:
			b.WriteString(" iokit-user-client-class-regex")
		case 0x92:
			b.WriteString(" iokit-property-regex")
		case 0x93:
			b.WriteString(" iokit-connection-regex")
		case 0x98:
			b.WriteString(" extension-class-regex")
		case 0x99:
			b.WriteString(" appleevent-destination-regex")
		case 0x9b:
			b.WriteString(" right-name-regex")
		case 0x9c:
			b.WriteString(" preference-domain-regex")
		case 0xa0:
			b.WriteString(" entitlement-value-regex")
		case 0xa1:
			b.WriteString(" kext-bundle-id-regex")
		case 0xa3:
			b.WriteString(" notification-name-regex")
		case 0xa6:
			b.WriteString(" sysctl-name-regex")
		case 0xa7:
			b.WriteString(" process-name-regex")
		default:
			b.WriteString(" unknown")
		}
		b.WriteString("\n")
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

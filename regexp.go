package sb

import (
	"bytes"
	"encoding/binary"
)

func entryToGraph(entry *Entry) *Graph {
	g := NewGraph()
	buf := bytes.NewBuffer(entry.Raw)

	for {
		var t uint8
		var jump uint16
		binary.Read(buf, binary.LittleEndian, &t)
		switch t {
		case 0x02:
			// actual character
			binary.Read(buf, binary.LittleEndian, &t)
			continue
		case 0x0a:
			// jump back
			continue
		case 0x0b:
			// character class
			// for example [1-9] or [ae]
		case 0x09:
			// .
			continue
		case 0x15:
			// reached the end
			break
		case 0x19:
			// ^
			// beginning of line
			continue
		case 0x29:
			// $
			// end of line
			continue
		case 0x2f:
			// jump forward
			binary.Read(buf, binary.LittleEndian, &jump)
			continue
		default:
			// set error unknown code
			break
		}
	}

	return g
}

func graphToRegexp(g *Graph) string {
	return ""
}

// EntryToRegexp reads the binary regexp table and converts it to string form.
func EntryToRegexp(entry *Entry) string {
	return graphToRegexp(entryToGraph(entry))
}

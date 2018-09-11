package sb

// #cgo LDFLAGS: -lsandbox
// #include <stdlib.h>
// #include "compiler_darwin.h"
import "C"
import (
	"bytes"
	"fmt"
	"io"
	"unsafe"

	"github.com/pkg/errors"
)

// Compile reads a sbpl file and compiles it into binary form.
func Compile(in io.Reader, out io.Writer) error {
	buf := new(bytes.Buffer)
	size, err := buf.ReadFrom(in)
	if err != nil {
		return errors.Wrap(err, "failed to read input")
	}

	if size == 0 {
		return errors.New("input is empty")
	}

	params := C.sandbox_create_params()
	if params == nil {
		return errors.New("creating sandbox params")
	}

	var cerr *C.char
	cs := C.CString(buf.String())
	defer C.free(unsafe.Pointer(cs))

	profile := C.sandbox_compile_string(cs, params, &cerr)
	defer C.sandbox_free_profile(profile)

	if profile == nil {
		return fmt.Errorf("compiling profile: %s", C.GoString(cerr))
	}

	if profile.blob != nil {
		b := C.GoBytes(profile.blob, profile.len)
		out.Write(b)
	}

	return nil
}

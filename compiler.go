// +build !darwin

package sb

import (
	"errors"
	"io"
)

func Compile(in io.Reader, out io.Writer) error {
	return errors.New("compile only supported on macOS")
}

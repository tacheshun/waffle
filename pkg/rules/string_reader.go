package rules

import (
	"io"
)

// stringReader implements io.Reader for a string
type stringReader struct {
	body     string
	position int
}

// Read implements the io.Reader interface for stringReader
func (r *stringReader) Read(p []byte) (n int, err error) {
	if r.position >= len(r.body) {
		return 0, io.EOF
	}

	n = copy(p, r.body[r.position:])
	r.position += n
	return n, nil
}

// Close is a no-op to satisfy io.Closer interface
func (r *stringReader) Close() error {
	return nil
}

// Package wire is the length-prefixed JSON transport of the dispatch plane and
// the typed Go realization of contracts/schemas/wire.schema.json. It binds the
// framing, the envelope, and every message body. Strictness is the rule:
// unknown fields are rejected everywhere (fail-closed).
package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxFrameBytes caps a single frame. Domain bytes never travel the wire — they
// go through the CAS — so control frames are small; this bound is generous and
// exists only to deny memory-exhaustion via a giant length prefix.
const MaxFrameBytes = 4 << 20 // 4 MiB

// ContractVersion is the frozen wire version. A mismatch at hello is a hard
// error (a misconfiguration), never a negotiated mixed-version state.
const ContractVersion = "0.1"

// ReadFrame reads one length-prefixed frame: a 4-byte big-endian length, then
// that many payload bytes. It returns ErrFrameTooLarge if the prefix exceeds
// MaxFrameBytes (before allocating), and io.EOF cleanly at a frame boundary.
func ReadFrame(r io.Reader) ([]byte, error) {
	var lenbuf [4]byte
	if _, err := io.ReadFull(r, lenbuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenbuf[:])
	if n == 0 {
		return nil, fmt.Errorf("wire: zero-length frame")
	}
	if n > MaxFrameBytes {
		return nil, ErrFrameTooLarge{Got: n}
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		// A truncated payload after a valid prefix is a protocol error, not EOF.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

// WriteFrame writes payload as one length-prefixed frame.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("wire: refusing to write zero-length frame")
	}
	if len(payload) > MaxFrameBytes {
		return ErrFrameTooLarge{Got: uint32(len(payload))}
	}
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(payload)))
	if _, err := w.Write(lenbuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ErrFrameTooLarge is returned when a frame's declared or actual size exceeds
// MaxFrameBytes.
type ErrFrameTooLarge struct{ Got uint32 }

func (e ErrFrameTooLarge) Error() string {
	return fmt.Sprintf("wire: frame of %d bytes exceeds max %d", e.Got, MaxFrameBytes)
}

package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

var typeRe = regexp.MustCompile(`^[a-z_]{1,32}$`)

// StrictUnmarshal decodes JSON into v, rejecting unknown fields and trailing
// data. This is the fail-closed decode used everywhere untrusted JSON enters.
func StrictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing bytes after the first JSON value.
	if dec.More() {
		return fmt.Errorf("wire: trailing data after JSON value")
	}
	return nil
}

// DecodeEnvelope strictly decodes and validates the outer frame envelope.
func DecodeEnvelope(frame []byte) (Envelope, error) {
	var env Envelope
	if err := StrictUnmarshal(frame, &env); err != nil {
		return Envelope{}, fmt.Errorf("wire: envelope decode: %w", err)
	}
	if env.V != ContractVersion {
		return Envelope{}, fmt.Errorf("wire: envelope version %q, want %q", env.V, ContractVersion)
	}
	if !typeRe.MatchString(env.Type) {
		return Envelope{}, fmt.Errorf("wire: invalid message type %q", env.Type)
	}
	if len(env.ID) < 1 || len(env.ID) > 64 {
		return Envelope{}, fmt.Errorf("wire: invalid message id length %d", len(env.ID))
	}
	if len(env.Body) == 0 {
		return Envelope{}, fmt.Errorf("wire: empty body")
	}
	return env, nil
}

// DecodeBody strictly decodes an envelope's body into a T.
func DecodeBody[T any](env Envelope) (T, error) {
	var v T
	if err := StrictUnmarshal(env.Body, &v); err != nil {
		return v, fmt.Errorf("wire: body decode (%s): %w", env.Type, err)
	}
	return v, nil
}

// MarshalEnvelope builds the envelope bytes (no length prefix) for a typed body.
func MarshalEnvelope(id, typ string, body any) ([]byte, error) {
	if !typeRe.MatchString(typ) {
		return nil, fmt.Errorf("wire: invalid message type %q", typ)
	}
	if len(id) < 1 || len(id) > 64 {
		return nil, fmt.Errorf("wire: invalid message id length %d", len(id))
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("wire: body marshal (%s): %w", typ, err)
	}
	env := Envelope{V: ContractVersion, Type: typ, ID: id, Body: raw}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("wire: envelope marshal (%s): %w", typ, err)
	}
	return out, nil
}

// WriteMessage frames and writes a typed message.
func WriteMessage(w io.Writer, id, typ string, body any) error {
	env, err := MarshalEnvelope(id, typ, body)
	if err != nil {
		return err
	}
	return WriteFrame(w, env)
}

// ReadMessage reads one frame and decodes its envelope.
func ReadMessage(r io.Reader) (Envelope, error) {
	frame, err := ReadFrame(r)
	if err != nil {
		return Envelope{}, err
	}
	return DecodeEnvelope(frame)
}

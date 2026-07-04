package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
)

// A tiny CBOR (RFC 8949) decoder — just enough to parse WebAuthn attestation
// objects and COSE keys. Integers decode to int64, byte strings to []byte, text
// to string, arrays to []any, and maps to map[any]any (COSE keys are integers).

var errCBOR = errors.New("webauthn: malformed CBOR")

// cborDecode decodes a single CBOR data item, returning it and the number of
// bytes consumed.
func cborDecode(data []byte) (any, int, error) {
	if len(data) == 0 {
		return nil, 0, errCBOR
	}
	major := data[0] >> 5
	minor := data[0] & 0x1f

	arg, n, err := cborArg(data, minor)
	if err != nil {
		return nil, 0, err
	}
	off := n

	switch major {
	case 0: // unsigned int
		return int64(arg), off, nil
	case 1: // negative int
		return int64(-1) - int64(arg), off, nil
	case 2: // byte string
		end := off + int(arg)
		if end > len(data) || end < off {
			return nil, 0, errCBOR
		}
		b := make([]byte, arg)
		copy(b, data[off:end])
		return b, end, nil
	case 3: // text string
		end := off + int(arg)
		if end > len(data) || end < off {
			return nil, 0, errCBOR
		}
		return string(data[off:end]), end, nil
	case 4: // array
		arr := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, m, err := cborDecode(data[off:])
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			off += m
		}
		return arr, off, nil
	case 5: // map
		m := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, kn, err := cborDecode(data[off:])
			if err != nil {
				return nil, 0, err
			}
			off += kn
			v, vn, err := cborDecode(data[off:])
			if err != nil {
				return nil, 0, err
			}
			off += vn
			m[k] = v
		}
		return m, off, nil
	case 6: // tag — decode and return the tagged item
		v, m, err := cborDecode(data[off:])
		if err != nil {
			return nil, 0, err
		}
		return v, off + m, nil
	case 7: // simple / float
		switch minor {
		case 20:
			return false, off, nil
		case 21:
			return true, off, nil
		case 22, 23:
			return nil, off, nil
		case 26:
			return float64(math.Float32frombits(uint32(arg))), off, nil
		case 27:
			return math.Float64frombits(arg), off, nil
		default:
			return int64(arg), off, nil
		}
	}
	return nil, 0, errCBOR
}

// cborArg reads the argument of a CBOR item given its minor (additional info)
// value, returning the argument and total bytes consumed (including the initial
// byte).
func cborArg(data []byte, minor byte) (uint64, int, error) {
	switch {
	case minor < 24:
		return uint64(minor), 1, nil
	case minor == 24:
		if len(data) < 2 {
			return 0, 0, errCBOR
		}
		return uint64(data[1]), 2, nil
	case minor == 25:
		if len(data) < 3 {
			return 0, 0, errCBOR
		}
		return uint64(binary.BigEndian.Uint16(data[1:3])), 3, nil
	case minor == 26:
		if len(data) < 5 {
			return 0, 0, errCBOR
		}
		return uint64(binary.BigEndian.Uint32(data[1:5])), 5, nil
	case minor == 27:
		if len(data) < 9 {
			return 0, 0, errCBOR
		}
		return binary.BigEndian.Uint64(data[1:9]), 9, nil
	default:
		return 0, 0, errCBOR
	}
}

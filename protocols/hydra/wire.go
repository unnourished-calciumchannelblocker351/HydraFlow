// Package hydra implements the Hydra wire protocol for HydraFlow.
// Hydra is an adaptive anti-censorship proxy protocol with transport
// switching, randomized TLS fingerprinting, and traffic camouflage.
package hydra

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Protocol version.
const HydraVersion byte = 0x01

// Frame type constants define the different frame types in the Hydra wire format.
const (
	FrameData            byte = 0x01
	FrameTransportSwitch byte = 0x02
	FrameKeepalive       byte = 0x03
	FrameClose           byte = 0x04
)

// Authentication method constants.
const (
	AuthPassword byte = 0x01
	AuthUUID     byte = 0x02
	AuthToken    byte = 0x03
)

// Transport hint constants sent during the handshake to indicate
// the client's preferred transport.
const (
	TransportHintTLS  byte = 0x01
	TransportHintWS   byte = 0x02
	TransportHintGRPC byte = 0x03
	TransportHintH2   byte = 0x04
	TransportHintAuto byte = 0x00
)

// Maximum sizes to prevent abuse.
const (
	maxAuthDataLen  = 256
	maxFramePayload = 65535
	maxPaddingLen   = 255
)

// Handshake represents the Hydra protocol handshake message exchanged
// at the start of a connection.
//
// Wire format:
//
//	[1 byte: version] [1 byte: auth_method] [2 bytes: auth_data_len BE]
//	[N bytes: auth_data] [1 byte: transport_hint]
type Handshake struct {
	Version       byte
	AuthMethod    byte
	AuthData      []byte
	TransportHint byte
}

// MarshalBinary encodes the handshake into its wire format.
func (h *Handshake) MarshalBinary() ([]byte, error) {
	if len(h.AuthData) > maxAuthDataLen {
		return nil, fmt.Errorf("hydra: auth data too long: %d > %d", len(h.AuthData), maxAuthDataLen)
	}

	buf := make([]byte, 0, 5+len(h.AuthData))
	buf = append(buf, h.Version)
	buf = append(buf, h.AuthMethod)
	buf = append(buf, byte(len(h.AuthData)>>8), byte(len(h.AuthData)&0xFF))
	buf = append(buf, h.AuthData...)
	buf = append(buf, h.TransportHint)
	return buf, nil
}

// UnmarshalBinary decodes a handshake from its wire format.
func (h *Handshake) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("hydra: handshake too short: %d bytes", len(data))
	}

	h.Version = data[0]
	h.AuthMethod = data[1]
	authLen := int(binary.BigEndian.Uint16(data[2:4]))

	if authLen > maxAuthDataLen {
		return fmt.Errorf("hydra: auth data too long: %d > %d", authLen, maxAuthDataLen)
	}
	if len(data) < 4+authLen+1 {
		return fmt.Errorf("hydra: handshake truncated: need %d, have %d", 4+authLen+1, len(data))
	}

	h.AuthData = make([]byte, authLen)
	copy(h.AuthData, data[4:4+authLen])
	h.TransportHint = data[4+authLen]
	return nil
}

// ReadHandshake reads a Hydra handshake from a reader.
func ReadHandshake(r io.Reader) (*Handshake, error) {
	// Read fixed header: version + auth_method + auth_data_len (4 bytes).
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("hydra: read handshake header: %w", err)
	}

	authLen := int(binary.BigEndian.Uint16(header[2:4]))
	if authLen > maxAuthDataLen {
		return nil, fmt.Errorf("hydra: auth data too long: %d", authLen)
	}

	// Read auth data + transport hint.
	rest := make([]byte, authLen+1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("hydra: read handshake body: %w", err)
	}

	h := &Handshake{
		Version:       header[0],
		AuthMethod:    header[1],
		AuthData:      rest[:authLen],
		TransportHint: rest[authLen],
	}
	return h, nil
}

// WriteHandshake writes a Hydra handshake to a writer.
func WriteHandshake(w io.Writer, h *Handshake) error {
	data, err := h.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Frame represents a single Hydra protocol frame.
//
// Wire format:
//
//	[1 byte: type] [2 bytes: payload_length BE] [1 byte: padding_length]
//	[N bytes: payload] [M bytes: padding]
type Frame struct {
	Type       byte
	Payload    []byte
	PaddingLen byte
}

// MarshalBinary encodes the frame into its wire format.
func (f *Frame) MarshalBinary() ([]byte, error) {
	payloadLen := len(f.Payload)
	if payloadLen > maxFramePayload {
		return nil, fmt.Errorf("hydra: payload too large: %d > %d", payloadLen, maxFramePayload)
	}

	totalLen := 4 + payloadLen + int(f.PaddingLen)
	buf := make([]byte, totalLen)

	buf[0] = f.Type
	binary.BigEndian.PutUint16(buf[1:3], uint16(payloadLen))
	buf[3] = f.PaddingLen
	copy(buf[4:4+payloadLen], f.Payload)
	// Padding bytes are zero-filled by make().

	return buf, nil
}

// UnmarshalBinary decodes a frame from its wire format.
func (f *Frame) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("hydra: frame too short: %d bytes", len(data))
	}

	f.Type = data[0]
	payloadLen := int(binary.BigEndian.Uint16(data[1:3]))
	f.PaddingLen = data[3]

	expectedLen := 4 + payloadLen + int(f.PaddingLen)
	if len(data) < expectedLen {
		return fmt.Errorf("hydra: frame truncated: need %d, have %d", expectedLen, len(data))
	}

	f.Payload = make([]byte, payloadLen)
	copy(f.Payload, data[4:4+payloadLen])
	// Padding is discarded.

	return nil
}

// ReadFrame reads a single Hydra frame from a reader.
func ReadFrame(r io.Reader) (*Frame, error) {
	// Read frame header: type + payload_length + padding_length (4 bytes).
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("hydra: read frame header: %w", err)
	}

	frameType := header[0]
	payloadLen := int(binary.BigEndian.Uint16(header[1:3]))
	paddingLen := int(header[3])

	if payloadLen > maxFramePayload {
		return nil, fmt.Errorf("hydra: payload too large: %d", payloadLen)
	}

	// Read payload and padding.
	body := make([]byte, payloadLen+paddingLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("hydra: read frame body: %w", err)
	}

	return &Frame{
		Type:       frameType,
		Payload:    body[:payloadLen],
		PaddingLen: byte(paddingLen),
	}, nil
}

// WriteFrame writes a single Hydra frame to a writer.
func WriteFrame(w io.Writer, f *Frame) error {
	data, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// frameTypeName returns a human-readable name for a frame type.
func frameTypeName(ft byte) string {
	switch ft {
	case FrameData:
		return "DATA"
	case FrameTransportSwitch:
		return "TRANSPORT_SWITCH"
	case FrameKeepalive:
		return "KEEPALIVE"
	case FrameClose:
		return "CLOSE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", ft)
	}
}

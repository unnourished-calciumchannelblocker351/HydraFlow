package hydra

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------- Wire format tests ----------

func TestHandshakeMarshalRoundtrip(t *testing.T) {
	tests := []struct {
		name      string
		handshake Handshake
	}{
		{
			name: "password auth",
			handshake: Handshake{
				Version:       HydraVersion,
				AuthMethod:    AuthPassword,
				AuthData:      []byte("my-secret-password"),
				TransportHint: TransportHintTLS,
			},
		},
		{
			name: "uuid auth",
			handshake: Handshake{
				Version:       HydraVersion,
				AuthMethod:    AuthUUID,
				AuthData:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				TransportHint: TransportHintWS,
			},
		},
		{
			name: "token auth",
			handshake: Handshake{
				Version:       HydraVersion,
				AuthMethod:    AuthToken,
				AuthData:      []byte("bearer-token-abc-123"),
				TransportHint: TransportHintGRPC,
			},
		},
		{
			name: "empty auth data",
			handshake: Handshake{
				Version:       HydraVersion,
				AuthMethod:    AuthPassword,
				AuthData:      []byte{},
				TransportHint: TransportHintAuto,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.handshake.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var decoded Handshake
			if err := decoded.UnmarshalBinary(data); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if decoded.Version != tt.handshake.Version {
				t.Errorf("version: got %d, want %d", decoded.Version, tt.handshake.Version)
			}
			if decoded.AuthMethod != tt.handshake.AuthMethod {
				t.Errorf("auth method: got 0x%02x, want 0x%02x", decoded.AuthMethod, tt.handshake.AuthMethod)
			}
			if !bytes.Equal(decoded.AuthData, tt.handshake.AuthData) {
				t.Errorf("auth data: got %x, want %x", decoded.AuthData, tt.handshake.AuthData)
			}
			if decoded.TransportHint != tt.handshake.TransportHint {
				t.Errorf("transport hint: got 0x%02x, want 0x%02x", decoded.TransportHint, tt.handshake.TransportHint)
			}
		})
	}
}

func TestHandshakeReadWrite(t *testing.T) {
	original := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    AuthToken,
		AuthData:      []byte("test-token-data"),
		TransportHint: TransportHintH2,
	}

	var buf bytes.Buffer

	if err := WriteHandshake(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	decoded, err := ReadHandshake(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version: got %d, want %d", decoded.Version, original.Version)
	}
	if decoded.AuthMethod != original.AuthMethod {
		t.Errorf("auth method mismatch")
	}
	if !bytes.Equal(decoded.AuthData, original.AuthData) {
		t.Errorf("auth data mismatch")
	}
	if decoded.TransportHint != original.TransportHint {
		t.Errorf("transport hint mismatch")
	}
}

func TestFrameMarshalRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "data frame no padding",
			frame: Frame{
				Type:       FrameData,
				Payload:    []byte("hello, hydra protocol"),
				PaddingLen: 0,
			},
		},
		{
			name: "data frame with padding",
			frame: Frame{
				Type:       FrameData,
				Payload:    []byte("padded payload"),
				PaddingLen: 16,
			},
		},
		{
			name: "keepalive frame",
			frame: Frame{
				Type:       FrameKeepalive,
				Payload:    nil,
				PaddingLen: 0,
			},
		},
		{
			name: "close frame",
			frame: Frame{
				Type:       FrameClose,
				Payload:    nil,
				PaddingLen: 0,
			},
		},
		{
			name: "transport switch frame",
			frame: Frame{
				Type:       FrameTransportSwitch,
				Payload:    []byte{TransportHintWS},
				PaddingLen: 4,
			},
		},
		{
			name: "large payload",
			frame: Frame{
				Type:       FrameData,
				Payload:    bytes.Repeat([]byte("A"), 4096),
				PaddingLen: 32,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.frame.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var decoded Frame
			if err := decoded.UnmarshalBinary(data); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if decoded.Type != tt.frame.Type {
				t.Errorf("type: got 0x%02x, want 0x%02x", decoded.Type, tt.frame.Type)
			}
			if !bytes.Equal(decoded.Payload, tt.frame.Payload) {
				t.Errorf("payload mismatch: got %d bytes, want %d bytes", len(decoded.Payload), len(tt.frame.Payload))
			}
			if decoded.PaddingLen != tt.frame.PaddingLen {
				t.Errorf("padding len: got %d, want %d", decoded.PaddingLen, tt.frame.PaddingLen)
			}
		})
	}
}

func TestFrameReadWrite(t *testing.T) {
	original := &Frame{
		Type:       FrameData,
		Payload:    []byte("read-write test payload"),
		PaddingLen: 8,
	}

	var buf bytes.Buffer

	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("type mismatch")
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf("payload mismatch")
	}
	if decoded.PaddingLen != original.PaddingLen {
		t.Errorf("padding len mismatch")
	}
}

func TestFrameMultipleReadWrite(t *testing.T) {
	frames := []*Frame{
		{Type: FrameData, Payload: []byte("frame one"), PaddingLen: 2},
		{Type: FrameKeepalive, Payload: nil, PaddingLen: 0},
		{Type: FrameData, Payload: []byte("frame three"), PaddingLen: 10},
		{Type: FrameClose, Payload: nil, PaddingLen: 0},
	}

	var buf bytes.Buffer

	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	for i, expected := range frames {
		decoded, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if decoded.Type != expected.Type {
			t.Errorf("frame %d: type got 0x%02x, want 0x%02x", i, decoded.Type, expected.Type)
		}
		if !bytes.Equal(decoded.Payload, expected.Payload) {
			t.Errorf("frame %d: payload mismatch", i)
		}
	}
}

func TestHandshakeAuthDataTooLong(t *testing.T) {
	h := Handshake{
		Version:    HydraVersion,
		AuthMethod: AuthPassword,
		AuthData:   make([]byte, maxAuthDataLen+1),
	}

	_, err := h.MarshalBinary()
	if err == nil {
		t.Fatal("expected error for oversized auth data")
	}
}

func TestFramePayloadTooLarge(t *testing.T) {
	f := Frame{
		Type:    FrameData,
		Payload: make([]byte, maxFramePayload+1),
	}

	_, err := f.MarshalBinary()
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

// ---------- Fingerprint pool tests ----------

func TestFingerprintPoolReturnsValidConfigs(t *testing.T) {
	pool := NewFingerprintPool()
	profiles := pool.Profiles()

	if len(profiles) == 0 {
		t.Fatal("fingerprint pool has no profiles")
	}

	for _, p := range profiles {
		if p.Name == "" {
			t.Error("profile has empty name")
		}
		if len(p.CipherSuites) == 0 {
			t.Errorf("profile %q has no cipher suites", p.Name)
		}
		if len(p.CurvePreferences) == 0 {
			t.Errorf("profile %q has no curve preferences", p.Name)
		}
		if len(p.ALPNProtocols) == 0 {
			t.Errorf("profile %q has no ALPN protocols", p.Name)
		}
		if p.MinVersion == 0 {
			t.Errorf("profile %q has zero MinVersion", p.Name)
		}
		if p.MaxVersion == 0 {
			t.Errorf("profile %q has zero MaxVersion", p.Name)
		}
	}
}

func TestRandomFingerprintProducesVariation(t *testing.T) {
	pool := NewFingerprintPool()

	// Generate many fingerprints and check that we get variation.
	names := make(map[string]int)
	for i := 0; i < 100; i++ {
		fp := pool.RandomFingerprint()
		names[fp.Name]++
	}

	// With 6 profiles and 100 draws, we should see at least 2 different names.
	if len(names) < 2 {
		t.Errorf("expected multiple different profiles, got %d: %v", len(names), names)
	}
}

func TestFingerprintToTLSConfig(t *testing.T) {
	pool := NewFingerprintPool()
	fp := pool.RandomFingerprint()

	cfg := fp.ToTLSConfig("example.com")

	if cfg.ServerName != "example.com" {
		t.Errorf("server name: got %q, want %q", cfg.ServerName, "example.com")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
	if len(cfg.CipherSuites) == 0 {
		t.Error("no cipher suites in TLS config")
	}
	if len(cfg.NextProtos) == 0 {
		t.Error("no ALPN protocols in TLS config")
	}
}

func TestFingerprintPoolAddProfile(t *testing.T) {
	pool := NewFingerprintPool()
	initial := len(pool.Profiles())

	pool.AddProfile(FingerprintProfile{
		Name:          "Custom/1.0",
		CipherSuites:  []uint16{0x1301},
		ALPNProtocols: []string{"h2"},
		MinVersion:    0x0303,
		MaxVersion:    0x0304,
	})

	if got := len(pool.Profiles()); got != initial+1 {
		t.Errorf("expected %d profiles, got %d", initial+1, got)
	}
}

// ---------- Camouflage tests ----------

func TestCamouflageWriterReaderRoundtrip(t *testing.T) {
	config := DefaultCamouflageConfig()

	testData := [][]byte{
		[]byte("hello"),
		[]byte("this is a longer message with more content"),
		bytes.Repeat([]byte("X"), 1000),
		[]byte("short"),
	}

	var buf bytes.Buffer
	writer := NewCamouflageWriter(&buf, config)

	for _, data := range testData {
		n, err := writer.Write(data)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if n != len(data) {
			t.Fatalf("write: got %d, want %d", n, len(data))
		}
	}

	reader := NewCamouflageReader(&buf, config)

	for i, expected := range testData {
		got := make([]byte, len(expected)+100) // extra room
		n, err := reader.Read(got)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		got = got[:n]

		if !bytes.Equal(got, expected) {
			t.Errorf("data %d: got %q, want %q", i, string(got), string(expected))
		}
	}
}

func TestCamouflageWriterAddsPadding(t *testing.T) {
	config := DefaultCamouflageConfig()
	config.PaddingEnabled = true

	var buf bytes.Buffer
	writer := NewCamouflageWriter(&buf, config)

	payload := []byte("test")
	writer.Write(payload) //nolint:errcheck

	// The written data should be larger than just the payload
	// (4 byte frame header + payload + padding).
	if buf.Len() <= len(payload)+4 {
		t.Errorf("expected padding, but total size is only %d", buf.Len())
	}
}

func TestCamouflageNoPadding(t *testing.T) {
	config := DefaultCamouflageConfig()
	config.PaddingEnabled = false

	var buf bytes.Buffer
	writer := NewCamouflageWriter(&buf, config)

	payload := []byte("no-padding-test")
	writer.Write(payload) //nolint:errcheck

	// Without padding: 4 byte header + payload.
	expectedSize := 4 + len(payload)
	if buf.Len() != expectedSize {
		t.Errorf("without padding: got %d bytes, want %d", buf.Len(), expectedSize)
	}
}

func TestCamouflageReaderHandlesCloseFrame(t *testing.T) {
	var buf bytes.Buffer

	closeFrame := &Frame{
		Type:       FrameClose,
		Payload:    nil,
		PaddingLen: 0,
	}
	WriteFrame(&buf, closeFrame) //nolint:errcheck

	config := DefaultCamouflageConfig()
	reader := NewCamouflageReader(&buf, config)

	p := make([]byte, 100)
	_, err := reader.Read(p)
	if err != io.EOF {
		t.Errorf("expected EOF on close frame, got %v", err)
	}
}

func TestTimingObfuscator(t *testing.T) {
	config := CamouflageConfig{
		Enabled:  true,
		MinDelay: 0,
		MaxDelay: 1 * time.Millisecond,
	}

	obfuscator := NewTimingObfuscator(config)

	// Just verify it doesn't panic or hang.
	start := time.Now()
	obfuscator.Delay()
	elapsed := time.Since(start)

	// Should complete within a reasonable time.
	if elapsed > 100*time.Millisecond {
		t.Errorf("delay took too long: %v", elapsed)
	}
}

func TestTimingObfuscatorDisabled(t *testing.T) {
	config := CamouflageConfig{
		Enabled: false,
	}

	obfuscator := NewTimingObfuscator(config)

	start := time.Now()
	obfuscator.Delay()
	elapsed := time.Since(start)

	if elapsed > 1*time.Millisecond {
		t.Errorf("disabled obfuscator should not delay, but took %v", elapsed)
	}

	if obfuscator.ShouldDelay() {
		t.Error("disabled obfuscator should never trigger delay")
	}
}

// ---------- Transport selector tests ----------

// mockTransport is a test transport that can be configured to succeed or fail.
type mockTransport struct {
	name   string
	err    error
	conn   net.Conn
	called bool
	mu     sync.Mutex
}

func (m *mockTransport) Name() string { return m.name }

func (m *mockTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	m.mu.Lock()
	m.called = true
	m.mu.Unlock()

	if m.err != nil {
		return nil, m.err
	}
	if m.conn != nil {
		return m.conn, nil
	}
	// Return a pipe as a mock connection.
	client, _ := net.Pipe()
	return client, nil
}

func (m *mockTransport) wasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.called
}

func TestTransportSelectorFallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	failing1 := &mockTransport{name: "tls", err: fmt.Errorf("connection refused")}
	failing2 := &mockTransport{name: "websocket", err: fmt.Errorf("timeout")}
	succeeding := &mockTransport{name: "grpc"}

	selector := NewTransportSelector(
		[]Transport{failing1, failing2, succeeding},
		logger,
	)

	conn, transport, err := selector.Dial(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	defer conn.Close()

	if transport.Name() != "grpc" {
		t.Errorf("expected grpc transport, got %q", transport.Name())
	}

	if !failing1.wasCalled() {
		t.Error("tls transport should have been tried")
	}
	if !failing2.wasCalled() {
		t.Error("websocket transport should have been tried")
	}
	if !succeeding.wasCalled() {
		t.Error("grpc transport should have been tried")
	}
}

func TestTransportSelectorAllFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	selector := NewTransportSelector(
		[]Transport{
			&mockTransport{name: "tls", err: fmt.Errorf("fail1")},
			&mockTransport{name: "ws", err: fmt.Errorf("fail2")},
			&mockTransport{name: "grpc", err: fmt.Errorf("fail3")},
		},
		logger,
	)

	_, _, err := selector.Dial(context.Background(), "127.0.0.1:443")
	if err == nil {
		t.Fatal("expected error when all transports fail")
	}
}

func TestTransportSelectorFirstSucceeds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	first := &mockTransport{name: "tls"}
	second := &mockTransport{name: "ws"}

	selector := NewTransportSelector(
		[]Transport{first, second},
		logger,
	)

	conn, transport, err := selector.Dial(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()

	if transport.Name() != "tls" {
		t.Errorf("expected tls, got %q", transport.Name())
	}

	// Second transport should NOT have been called.
	if second.wasCalled() {
		t.Error("second transport should not be tried if first succeeds")
	}
}

func TestTransportSelectorNoTransports(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	selector := NewTransportSelector(nil, logger)

	_, _, err := selector.Dial(context.Background(), "127.0.0.1:443")
	if err == nil {
		t.Fatal("expected error with no transports")
	}
}

// ---------- Full protocol handshake test ----------

func TestFullHandshakeWithMockServer(t *testing.T) {
	// Create a server-client pipe to simulate a network connection.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	password := "test-password-123"

	// Server goroutine.
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)

		// Read client handshake.
		hs, err := ReadHandshake(serverConn)
		if err != nil {
			serverDone <- fmt.Errorf("server read handshake: %w", err)
			return
		}

		// Validate.
		if hs.Version != HydraVersion {
			serverDone <- fmt.Errorf("server: wrong version %d", hs.Version)
			return
		}
		if hs.AuthMethod != AuthPassword {
			serverDone <- fmt.Errorf("server: wrong auth method 0x%02x", hs.AuthMethod)
			return
		}
		if string(hs.AuthData) != password {
			// Send rejection.
			resp := &Handshake{
				Version:       HydraVersion,
				AuthMethod:    0xFF,
				TransportHint: TransportHintAuto,
			}
			WriteHandshake(serverConn, resp) //nolint:errcheck
			serverDone <- fmt.Errorf("server: wrong password")
			return
		}

		// Send acceptance.
		resp := &Handshake{
			Version:       HydraVersion,
			AuthMethod:    0x00,
			TransportHint: TransportHintAuto,
		}
		if err := WriteHandshake(serverConn, resp); err != nil {
			serverDone <- fmt.Errorf("server write response: %w", err)
			return
		}

		serverDone <- nil
	}()

	// Client side: send handshake.
	clientHS := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    AuthPassword,
		AuthData:      []byte(password),
		TransportHint: TransportHintTLS,
	}

	if err := WriteHandshake(clientConn, clientHS); err != nil {
		t.Fatalf("client write handshake: %v", err)
	}

	// Read server response.
	resp, err := ReadHandshake(clientConn)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}

	if resp.Version != HydraVersion {
		t.Errorf("response version: got %d, want %d", resp.Version, HydraVersion)
	}
	if resp.AuthMethod != 0x00 {
		t.Errorf("response auth: got 0x%02x, want 0x00 (accepted)", resp.AuthMethod)
	}

	// Wait for server to finish.
	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestFullHandshakeRejection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Server goroutine that rejects any auth.
	go func() {
		hs, err := ReadHandshake(serverConn)
		if err != nil {
			return
		}
		_ = hs

		resp := &Handshake{
			Version:       HydraVersion,
			AuthMethod:    0xFF, // rejected
			TransportHint: TransportHintAuto,
		}
		WriteHandshake(serverConn, resp) //nolint:errcheck
	}()

	// Client sends handshake.
	clientHS := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    AuthPassword,
		AuthData:      []byte("wrong-password"),
		TransportHint: TransportHintTLS,
	}

	if err := WriteHandshake(clientConn, clientHS); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := ReadHandshake(clientConn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.AuthMethod != 0xFF {
		t.Errorf("expected rejection (0xFF), got 0x%02x", resp.AuthMethod)
	}
}

func TestFullDataExchangeWithCamouflage(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	config := DefaultCamouflageConfig()

	// Write from client, read from server.
	messages := []string{
		"first message",
		"second message with more data",
		"third",
	}

	writerDone := make(chan error, 1)
	go func() {
		writer := NewCamouflageWriter(clientConn, config)
		for _, msg := range messages {
			if _, err := writer.Write([]byte(msg)); err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	reader := NewCamouflageReader(serverConn, config)
	for i, expected := range messages {
		buf := make([]byte, 4096)
		n, err := reader.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		got := string(buf[:n])
		if got != expected {
			t.Errorf("message %d: got %q, want %q", i, got, expected)
		}
	}

	if err := <-writerDone; err != nil {
		t.Fatalf("writer error: %v", err)
	}
}

// ---------- Protocol config tests ----------

func TestHydraConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  HydraConfig
		wantErr bool
	}{
		{
			name: "valid password config",
			config: HydraConfig{
				Host:           "example.com",
				Port:           443,
				Password:       "secret",
				TransportOrder: []string{"tls"},
			},
			wantErr: false,
		},
		{
			name: "valid uuid config",
			config: HydraConfig{
				Host:           "example.com",
				Port:           443,
				UUID:           "550e8400-e29b-41d4-a716-446655440000",
				TransportOrder: []string{"tls", "websocket"},
			},
			wantErr: false,
		},
		{
			name: "missing host",
			config: HydraConfig{
				Port:           443,
				Password:       "secret",
				TransportOrder: []string{"tls"},
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			config: HydraConfig{
				Host:           "example.com",
				Port:           0,
				Password:       "secret",
				TransportOrder: []string{"tls"},
			},
			wantErr: true,
		},
		{
			name: "no auth",
			config: HydraConfig{
				Host:           "example.com",
				Port:           443,
				TransportOrder: []string{"tls"},
			},
			wantErr: true,
		},
		{
			name: "empty transport order",
			config: HydraConfig{
				Host:           "example.com",
				Port:           443,
				Password:       "secret",
				TransportOrder: []string{},
			},
			wantErr: true,
		},
		{
			name: "unknown transport",
			config: HydraConfig{
				Host:           "example.com",
				Port:           443,
				Password:       "secret",
				TransportOrder: []string{"tls", "quic"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHydraConfigAuthMethod(t *testing.T) {
	t.Run("uuid auth", func(t *testing.T) {
		cfg := &HydraConfig{UUID: "550e8400-e29b-41d4-a716-446655440000"}
		method, data, err := cfg.authMethod()
		if err != nil {
			t.Fatal(err)
		}
		if method != AuthUUID {
			t.Errorf("method: got 0x%02x, want 0x%02x", method, AuthUUID)
		}
		if len(data) != 16 {
			t.Errorf("uuid data length: got %d, want 16", len(data))
		}
	})

	t.Run("token auth", func(t *testing.T) {
		cfg := &HydraConfig{Token: "my-token"}
		method, data, err := cfg.authMethod()
		if err != nil {
			t.Fatal(err)
		}
		if method != AuthToken {
			t.Errorf("method: got 0x%02x, want 0x%02x", method, AuthToken)
		}
		if string(data) != "my-token" {
			t.Errorf("token data: got %q", string(data))
		}
	})

	t.Run("password auth", func(t *testing.T) {
		cfg := &HydraConfig{Password: "secret"}
		method, data, err := cfg.authMethod()
		if err != nil {
			t.Fatal(err)
		}
		if method != AuthPassword {
			t.Errorf("method: got 0x%02x, want 0x%02x", method, AuthPassword)
		}
		if string(data) != "secret" {
			t.Errorf("password data: got %q", string(data))
		}
	})

	t.Run("uuid preferred over password", func(t *testing.T) {
		cfg := &HydraConfig{UUID: "550e8400-e29b-41d4-a716-446655440000", Password: "secret"}
		method, _, err := cfg.authMethod()
		if err != nil {
			t.Fatal(err)
		}
		if method != AuthUUID {
			t.Error("UUID should be preferred over password")
		}
	})
}

// ---------- WebSocket frame encoding test ----------

func TestWSFrameRoundtrip(t *testing.T) {
	payload := []byte("websocket frame test data")

	encoded := encodeWSFrame(payload)

	decoded, err := decodeWSFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !bytes.Equal(decoded, payload) {
		t.Errorf("payload mismatch: got %q, want %q", string(decoded), string(payload))
	}
}

func TestWSFrameRoundtripLarge(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 300) // > 125 bytes

	encoded := encodeWSFrame(payload)

	decoded, err := decodeWSFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !bytes.Equal(decoded, payload) {
		t.Errorf("payload length: got %d, want %d", len(decoded), len(payload))
	}
}

// ---------- Frame type name test ----------

func TestFrameTypeName(t *testing.T) {
	tests := []struct {
		ft   byte
		want string
	}{
		{FrameData, "DATA"},
		{FrameTransportSwitch, "TRANSPORT_SWITCH"},
		{FrameKeepalive, "KEEPALIVE"},
		{FrameClose, "CLOSE"},
		{0xFF, "UNKNOWN(0xff)"},
	}

	for _, tt := range tests {
		got := frameTypeName(tt.ft)
		if got != tt.want {
			t.Errorf("frameTypeName(0x%02x): got %q, want %q", tt.ft, got, tt.want)
		}
	}
}

// ---------- Listener accept test ----------

func TestListenerAcceptAndAuth(t *testing.T) {
	cfg := DefaultHydraConfig()
	cfg.Host = "127.0.0.1"
	cfg.Password = "test-pass"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start listener on a random port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	hydraListener := &hydraListener{
		Listener: listener,
		config:   cfg,
		logger:   logger,
		fpPool:   NewFingerprintPool(),
	}

	acceptDone := make(chan struct {
		conn net.Conn
		err  error
	}, 1)

	go func() {
		conn, err := hydraListener.Accept()
		acceptDone <- struct {
			conn net.Conn
			err  error
		}{conn, err}
	}()

	// Connect as client.
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	// Send handshake.
	clientHS := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    AuthPassword,
		AuthData:      []byte("test-pass"),
		TransportHint: TransportHintTLS,
	}
	if err := WriteHandshake(clientConn, clientHS); err != nil {
		t.Fatal(err)
	}

	// Read response.
	resp, err := ReadHandshake(clientConn)
	if err != nil {
		t.Fatal(err)
	}

	if resp.AuthMethod != 0x00 {
		t.Errorf("expected acceptance (0x00), got 0x%02x", resp.AuthMethod)
	}

	// Check server side.
	result := <-acceptDone
	if result.err != nil {
		t.Fatalf("accept: %v", result.err)
	}
	if result.conn != nil {
		result.conn.Close()
	}
}

func TestListenerRejectsWrongPassword(t *testing.T) {
	cfg := DefaultHydraConfig()
	cfg.Host = "127.0.0.1"
	cfg.Password = "correct-password"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	hydraListener := &hydraListener{
		Listener: listener,
		config:   cfg,
		logger:   logger,
		fpPool:   NewFingerprintPool(),
	}

	go func() {
		conn, _ := hydraListener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	clientHS := &Handshake{
		Version:       HydraVersion,
		AuthMethod:    AuthPassword,
		AuthData:      []byte("wrong-password"),
		TransportHint: TransportHintTLS,
	}
	if err := WriteHandshake(clientConn, clientHS); err != nil {
		t.Fatal(err)
	}

	resp, err := ReadHandshake(clientConn)
	if err != nil {
		t.Fatal(err)
	}

	if resp.AuthMethod != 0xFF {
		t.Errorf("expected rejection (0xFF), got 0x%02x", resp.AuthMethod)
	}
}

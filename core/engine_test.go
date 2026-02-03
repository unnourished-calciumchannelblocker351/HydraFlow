package core

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// mockProtocol implements Protocol for testing.
type mockProtocol struct {
	name      string
	priority  int
	available bool
	dialErr   error
	dialDelay time.Duration
	conn      net.Conn
	dialCount atomic.Int32
}

func (m *mockProtocol) Name() string            { return m.name }
func (m *mockProtocol) Priority() int           { return m.priority }
func (m *mockProtocol) Available() bool         { return m.available }
func (m *mockProtocol) ProbeTests() []ProbeTest { return nil }

func (m *mockProtocol) Dial(ctx context.Context) (net.Conn, error) {
	m.dialCount.Add(1)
	if m.dialDelay > 0 {
		select {
		case <-time.After(m.dialDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	if m.conn != nil {
		return m.conn, nil
	}
	// Return a pipe connection for testing
	client, _ := net.Pipe()
	return client, nil
}

func (m *mockProtocol) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return nil, fmt.Errorf("not implemented")
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestEngineNew(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	if engine.ActiveProtocol() != nil {
		t.Error("ActiveProtocol() should be nil before connection")
	}
}

func TestEngineRegisterProtocol(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	p := &mockProtocol{name: "test-proto", priority: 1, available: true}
	engine.RegisterProtocol(p)

	if len(engine.protocols) != 1 {
		t.Errorf("expected 1 protocol, got %d", len(engine.protocols))
	}
	if engine.protocols[0].Name() != "test-proto" {
		t.Errorf("expected protocol name 'test-proto', got '%s'", engine.protocols[0].Name())
	}
}

func TestEngineConnectNoProtocols(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	_, err = engine.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should fail with no protocols")
	}
}

func TestEngineConnectSuccess(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	p := &mockProtocol{name: "working", priority: 1, available: true}
	engine.RegisterProtocol(p)

	conn, err := engine.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer conn.Close()

	if engine.ActiveProtocol() == nil {
		t.Error("ActiveProtocol() should not be nil after connection")
	}
	if engine.ActiveProtocol().Name() != "working" {
		t.Errorf("expected active protocol 'working', got '%s'", engine.ActiveProtocol().Name())
	}
}

func TestEngineConnectFallback(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	// First protocol fails, second succeeds
	failing := &mockProtocol{
		name:     "failing",
		priority: 1,
		dialErr:  fmt.Errorf("connection blocked by DPI"),
	}
	working := &mockProtocol{
		name:      "working",
		priority:  2,
		available: true,
	}

	engine.RegisterProtocol(failing)
	engine.RegisterProtocol(working)

	conn, err := engine.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer conn.Close()

	if failing.dialCount.Load() != 1 {
		t.Errorf("failing protocol should have been tried once, got %d", failing.dialCount.Load())
	}
	if working.dialCount.Load() != 1 {
		t.Errorf("working protocol should have been tried once, got %d", working.dialCount.Load())
	}
	if engine.ActiveProtocol().Name() != "working" {
		t.Errorf("should have fallen back to 'working', got '%s'", engine.ActiveProtocol().Name())
	}
}

func TestEngineConnectAllFail(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	engine.RegisterProtocol(&mockProtocol{
		name:    "proto1",
		dialErr: fmt.Errorf("blocked"),
	})
	engine.RegisterProtocol(&mockProtocol{
		name:    "proto2",
		dialErr: fmt.Errorf("filtered"),
	})

	_, err = engine.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should fail when all protocols fail")
	}
}

func TestEngineConnectContextCancel(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	slow := &mockProtocol{
		name:      "slow",
		priority:  1,
		dialDelay: 10 * time.Second,
	}
	engine.RegisterProtocol(slow)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = engine.Connect(ctx)
	if err == nil {
		t.Error("Connect() should fail on context timeout")
	}
}

func TestEngineMultipleRegistrations(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	for i := 0; i < 5; i++ {
		engine.RegisterProtocol(&mockProtocol{
			name:     fmt.Sprintf("proto-%d", i),
			priority: i,
		})
	}

	if len(engine.protocols) != 5 {
		t.Errorf("expected 5 protocols, got %d", len(engine.protocols))
	}
}

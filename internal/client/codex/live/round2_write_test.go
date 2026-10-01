package live

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// A synchronous in-memory WebSocket peer. Revoke on an actual transport write,
// not a timer: no sockets, production upstreams, sleeps or background work.
type round2WebsocketTransport struct {
	incoming  *bytes.Reader
	message   []byte
	wire      bytes.Buffer
	onWrite   func()
	handshake bool
}

func (c *round2WebsocketTransport) Read(p []byte) (int, error) {
	return c.incoming.Read(p)
}

func (c *round2WebsocketTransport) Write(p []byte) (int, error) {
	if !c.handshake {
		request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(p)))
		if err != nil {
			return 0, err
		}
		digest := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		header := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(digest[:]) + "\r\n\r\n"
		incoming := []byte(header)
		if c.message != nil {
			frame := []byte{0x81, 127}
			frame = binary.BigEndian.AppendUint64(frame, uint64(len(c.message)))
			incoming = append(incoming, frame...)
			incoming = append(incoming, c.message...)
		}
		c.incoming = bytes.NewReader(incoming)
		c.handshake = true
		return len(p), nil
	}
	n, err := c.wire.Write(p)
	if c.onWrite != nil {
		c.onWrite()
	}
	return n, err
}

func (*round2WebsocketTransport) Close() error {
	return nil
}

func (*round2WebsocketTransport) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (*round2WebsocketTransport) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (*round2WebsocketTransport) SetDeadline(time.Time) error {
	return nil
}

func (*round2WebsocketTransport) SetReadDeadline(time.Time) error {
	return nil
}

func (*round2WebsocketTransport) SetWriteDeadline(time.Time) error {
	return nil
}

func round2Websocket(t *testing.T, message []byte, onWrite func()) (*websocket.Conn, *round2WebsocketTransport) {
	t.Helper()
	transport := &round2WebsocketTransport{message: message, onWrite: onWrite}
	address, err := url.Parse("ws://in-memory.invalid/realtime")
	if err != nil {
		t.Fatal(err)
	}
	connection, _, err := websocket.NewClient(transport, address, nil, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, transport
}

func round2Policy(t *testing.T, models bool) (*Handler, *auth.Manager, *config.Config, context.Context, *auth.Auth) {
	t.Helper()
	const key = "synthetic-round2-key"
	digest := sha256.Sum256([]byte(key))
	policy := config.APIKeyPolicy{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"original@example.com"}}
	if models {
		allowed := []string{"gpt-realtime"}
		policy.AllowedModels = &allowed
	}
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{policy}}}
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	selected := &auth.Auth{ID: "round2-auth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"email": "original@example.com", "access_token": "synthetic-token"}}
	ctx := manager.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), key, cfg.APIKeyPolicies), "gpt-realtime")
	ctx = context.WithValue(ctx, liveModelInspectionContextKey{}, models)
	return NewHandler(manager, cfg), manager, cfg, ctx, selected
}

func TestRound2TokenInitializationRevocation(t *testing.T) {
	handler, manager, cfg, ctx, selected := round2Policy(t, true)
	update, err := json.Marshal(map[string]any{"type": "session.update", "session": map[string]any{"instructions": strings.Repeat("i", 60<<10)}})
	if err != nil {
		t.Fatal(err)
	}
	connection, transport := round2Websocket(t, nil, func() {
		revoked := cfg.CloneForRuntime()
		revoked.APIKeyPolicies[0].AllowedAuths = nil
		manager.SetConfig(revoked)
	})
	err = writeCheckedWebsocketMessage(connection, websocket.TextMessage, bytes.NewReader(update), func() error { return handler.validateLiveAuth(ctx, selected) })
	if err == nil {
		t.Fatal("initialization survived mid-send revocation")
	}
	if n := transport.wire.Len(); n == 0 || n > 4096+32 {
		t.Fatalf("initialization escaped fragment checks: %d bytes sent", n)
	}
	round2AssertNoFinalFrame(t, transport.wire.Bytes())
}

func TestRound2AllowedModelsMidSendRevocation(t *testing.T) {
	handler, manager, cfg, ctx, selected := round2Policy(t, true)
	payload := []byte(`{"type":"response.create","response":{"model":"gpt-realtime","instructions":"` + strings.Repeat("i", (16<<20)-128) + `"}}`)
	source, _ := round2Websocket(t, payload, nil)
	destination, transport := round2Websocket(t, nil, func() {
		revoked := cfg.CloneForRuntime()
		revoked.APIKeyPolicies[0].AllowedAuths = nil
		manager.SetConfig(revoked)
	})
	policy := handler.clientMessagePolicy(ctx, selected)
	if policy == nil {
		t.Fatal("allowed-models inspection not enabled")
	}
	err := copyWebsocketWithMessagePolicy(destination, source, policy, func() error { return handler.validateLiveAuth(ctx, selected) })
	if err == nil {
		t.Fatal("inspected message survived mid-send revocation")
	}
	if n := transport.wire.Len(); n == 0 || n > 4096+32 {
		t.Fatalf("WriterTo bypassed fragment checks: %d bytes sent", n)
	}
	round2AssertNoFinalFrame(t, transport.wire.Bytes())
}

// Revoke exactly when copying reaches EOF, while the message remains buffered.
type round2EOFRevoker struct {
	reader io.Reader
	revoke func()
}

func (r round2EOFRevoker) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err == io.EOF {
		r.revoke()
	}
	return n, err
}

// The final-flush check is shared by generated initialization and inspected relay.
func TestRound2FinalFlushDenial(t *testing.T) {
	handler, manager, cfg, ctx, selected := round2Policy(t, true)
	connection, transport := round2Websocket(t, nil, nil)
	reader := round2EOFRevoker{reader: strings.NewReader(`{"type":"session.update","session":{"instructions":"buffered"}}`), revoke: func() {
		revoked := cfg.CloneForRuntime()
		revoked.APIKeyPolicies[0].AllowedAuths = nil
		manager.SetConfig(revoked)
	}}
	err := writeCheckedWebsocketMessage(connection, websocket.TextMessage, reader, func() error { return handler.validateLiveAuth(ctx, selected) })
	if err == nil {
		t.Fatal("final flush did not check revocation")
	}
	if transport.wire.Len() != 0 {
		t.Fatal("denied final flush sent buffered client content")
	}
}

func TestRound2CheckedWriterShortWrite(t *testing.T) {
	writer := policyCheckedWebsocketWriter{Writer: round2ShortWriter{}}
	n, err := writer.Write([]byte("short"))
	if n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write = %d, %v", n, err)
	}
}

func round2AssertNoFinalFrame(t *testing.T, wire []byte) {
	t.Helper()
	for len(wire) > 0 {
		if len(wire) < 2 {
			t.Fatal("truncated WebSocket frame")
		}
		if wire[0]&0x80 != 0 {
			t.Fatal("denied write closed/flushed its buffered message")
		}
		size := int(wire[1] & 0x7f)
		header := 2
		switch size {
		case 126:
			if len(wire) < 4 {
				t.Fatal("truncated frame length")
			}
			size = int(binary.BigEndian.Uint16(wire[2:4]))
			header = 4
		case 127:
			if len(wire) < 10 {
				t.Fatal("truncated frame length")
			}
			size = int(binary.BigEndian.Uint64(wire[2:10]))
			header = 10
		}
		if wire[1]&0x80 != 0 {
			header += 4
		}
		if size < 0 || size > len(wire)-header {
			t.Fatal("truncated frame payload")
		}
		wire = wire[header+size:]
	}
}

// Mechanically confirm the generated token update uses the tested helper, not
// Gorilla's unbounded WriteMessage fast path. The behavioral test above revokes
// during the actual in-memory WebSocket writes made by that helper.
func TestRound2TokenInitializationUsesCheckedPath(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "websocket.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "HandleDirectWebsocket" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "WriteMessage" {
				t.Error("generated token initialization still uses unchecked WriteMessage")
			}
			if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "writeCheckedWebsocketMessage" {
				checked = true
			}
			return true
		})
	}
	if !checked {
		t.Fatal("generated token initialization is not wired to checked writes")
	}
}

type round2ShortWriter struct{}

func (round2ShortWriter) Write([]byte) (int, error) {
	return 1, nil
}

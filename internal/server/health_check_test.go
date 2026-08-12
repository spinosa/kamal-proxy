package server

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	longTimeout  = time.Millisecond * 20
	shortTimeout = time.Millisecond * 10
)

func TestHealthCheck(t *testing.T) {
	run := func(t *testing.T, path string, expected []bool) {
		serverURL := testHealthCheckTarget(t, "")
		consumer := make(mockHealthCheckConsumer)

		serverURL.Path = path

		hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, "", HealthCheckProtocolHTTP, "")
		t.Cleanup(hc.Close)

		for _, exp := range expected {
			result := <-consumer
			assert.Equal(t, exp, result)
		}
	}

	t.Run("Success", func(t *testing.T) {
		run(t, "", []bool{true})
	})

	t.Run("Success after retrying multiple attempts", func(t *testing.T) {
		run(t, "/retrying", []bool{false, false, true})
	})

	t.Run("Endpoint timing out", func(t *testing.T) {
		run(t, "/slow", []bool{false})
	})

	t.Run("Endpoint error", func(t *testing.T) {
		run(t, "/error", []bool{false})
	})
}

func TestHealthCheckWithCustomHost(t *testing.T) {
	t.Run("Custom Host header is sent", func(t *testing.T) {
		customHost := "example.com"
		serverURL := testHealthCheckTarget(t, customHost)
		consumer := make(mockHealthCheckConsumer)

		hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, customHost, HealthCheckProtocolHTTP, "")
		t.Cleanup(hc.Close)

		result := <-consumer
		assert.True(t, result, "Health check should succeed with correct Host header")
	})

	t.Run("Health check fails with incorrect Host header", func(t *testing.T) {
		expectedHost := "example.com"
		wrongHost := "wrong.com"
		serverURL := testHealthCheckTarget(t, expectedHost)
		consumer := make(mockHealthCheckConsumer)

		hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, wrongHost, HealthCheckProtocolHTTP, "")
		t.Cleanup(hc.Close)

		result := <-consumer
		assert.False(t, result, "Health check should fail when Host header doesn't match")
	})

	t.Run("Empty Host header uses default behavior", func(t *testing.T) {
		serverURL := testHealthCheckTarget(t, "")
		consumer := make(mockHealthCheckConsumer)

		hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, "", HealthCheckProtocolHTTP, "")
		t.Cleanup(hc.Close)

		result := <-consumer
		assert.True(t, result, "Health check should succeed with default Host header")
	})
}

// Mocks

type mockHealthCheckConsumer chan bool

func (m mockHealthCheckConsumer) HealthCheckCompleted(success bool) {
	m <- success
}

// Helpers

func testHealthCheckTarget(t testing.TB, expectedHost string) *url.URL {
	t.Helper()

	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Host header if expectedHost is set
		if expectedHost != "" && r.Host != expectedHost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		switch r.URL.Path {
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "/retrying":
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
		case "/slow":
			time.Sleep(longTimeout)
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	serverURL, _ := url.Parse(server.URL)
	return serverURL
}

// A WebSocket-only target has no HTTP endpoint: a plain GET is answered by
// closing the connection.
func TestHealthCheckWithWebSocketProtocol(t *testing.T) {
	websocketTarget := func(t *testing.T) *url.URL {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Upgrade") != "websocket" {
				// What a WebSocket-only server does with a plain GET.
				http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
				return
			}

			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
			require.NoError(t, err)
			c.CloseNow()
		}))
		t.Cleanup(server.Close)

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)
		return serverURL
	}

	t.Run("101 Switching Protocols is healthy", func(t *testing.T) {
		consumer := make(mockHealthCheckConsumer)
		hc := NewHealthCheck(consumer, websocketTarget(t), shortTimeout, shortTimeout, "", HealthCheckProtocolWebSocket, "")
		t.Cleanup(hc.Close)

		assert.True(t, <-consumer)
	})

	t.Run("an HTTP check against the same target fails", func(t *testing.T) {
		consumer := make(mockHealthCheckConsumer)
		hc := NewHealthCheck(consumer, websocketTarget(t), shortTimeout, shortTimeout, "", HealthCheckProtocolHTTP, "")
		t.Cleanup(hc.Close)

		assert.False(t, <-consumer)
	})

	t.Run("an empty protocol defaults to HTTP", func(t *testing.T) {
		consumer := make(mockHealthCheckConsumer)
		hc := NewHealthCheck(consumer, testHealthCheckTarget(t, ""), shortTimeout, shortTimeout, "", "", "")
		t.Cleanup(hc.Close)

		assert.True(t, <-consumer)
	})
}

// Regression: a real server holds the connection open after the handshake, so
// draining the body blocks and the check reports nothing at all. The httptest
// servers above hide this by closing the connection when the handler returns.
func TestHealthCheckWebSocketDoesNotBlockOnAnOpenConnection(t *testing.T) {
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				// Go writes this header in its own canonical form.
				key := ""
				for _, line := range strings.Split(string(buf[:n]), "\r\n") {
					name, value, found := strings.Cut(line, ": ")
					if found && strings.EqualFold(name, "Sec-WebSocket-Key") {
						key = value
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
					"Connection: Upgrade\r\nSec-WebSocket-Accept: " + webSocketAccept(key) + "\r\n\r\n"))
				<-held // hold it open, like a broker awaiting frames
				c.Close()
			}(conn)
		}
	}()

	serverURL, err := url.Parse("http://" + listener.Addr().String())
	require.NoError(t, err)

	consumer := make(mockHealthCheckConsumer)
	hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, "", HealthCheckProtocolWebSocket, "mqtt")
	t.Cleanup(hc.Close)

	select {
	case result := <-consumer:
		assert.True(t, result, "a completed handshake on a held-open connection is healthy")
	case <-time.After(time.Second):
		t.Fatal("health check blocked on the upgraded connection instead of reporting")
	}
}

// A target that answers 101 without the right digest is not a WebSocket
// endpoint, and must not be treated as healthy.
func TestHealthCheckWebSocketRejectsABogusHandshake(t *testing.T) {
	run := func(t *testing.T, subprotocol string, respond func(http.ResponseWriter, *http.Request)) {
		server := httptest.NewServer(http.HandlerFunc(respond))
		t.Cleanup(server.Close)

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		consumer := make(mockHealthCheckConsumer)
		hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, "", HealthCheckProtocolWebSocket, subprotocol)
		t.Cleanup(hc.Close)

		assert.False(t, <-consumer)
	}

	accept := func(r *http.Request) string { return webSocketAccept(r.Header.Get("Sec-WebSocket-Key")) }

	t.Run("wrong digest", func(t *testing.T) {
		run(t, "", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Sec-WebSocket-Accept", "obviously-not-the-right-digest")
			w.WriteHeader(http.StatusSwitchingProtocols)
		})
	})

	t.Run("101 without the upgrade headers", func(t *testing.T) {
		run(t, "", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Sec-WebSocket-Accept", accept(r))
			w.WriteHeader(http.StatusSwitchingProtocols)
		})
	})

	t.Run("missing the Connection token", func(t *testing.T) {
		run(t, "", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Sec-WebSocket-Accept", accept(r))
			w.WriteHeader(http.StatusSwitchingProtocols)
		})
	})

	t.Run("a subprotocol we never offered", func(t *testing.T) {
		run(t, "mqtt", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Sec-WebSocket-Accept", accept(r))
			w.Header().Set("Sec-WebSocket-Protocol", "chat")
			w.WriteHeader(http.StatusSwitchingProtocols)
		})
	})
}

// The key is a nonce: RFC 6455 requires a fresh random one per connection.
func TestWebSocketKeysAreRandomAndWellFormed(t *testing.T) {
	first, err := newWebSocketKey()
	require.NoError(t, err)
	second, err := newWebSocketKey()
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "the handshake key must not be reused between connections")

	decoded, err := base64.StdEncoding.DecodeString(first)
	require.NoError(t, err)
	assert.Len(t, decoded, 16, "RFC 6455 requires a 16-byte nonce")
}

// A typo must fail loudly rather than silently becoming an HTTP check.
func TestHealthCheckConfigValidate(t *testing.T) {
	t.Run("accepts the supported protocols", func(t *testing.T) {
		for _, protocol := range []string{"", HealthCheckProtocolHTTP, HealthCheckProtocolWebSocket} {
			assert.NoError(t, HealthCheckConfig{Protocol: protocol}.Validate(), "protocol %q", protocol)
		}
	})

	t.Run("rejects an unknown protocol", func(t *testing.T) {
		err := HealthCheckConfig{Protocol: "websockets"}.Validate()

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHealthCheckConfigInvalid)
		assert.Contains(t, err.Error(), "websockets", "the message should name the offending value")
	})

	t.Run("rejects a subprotocol without websocket", func(t *testing.T) {
		err := HealthCheckConfig{Protocol: HealthCheckProtocolHTTP, WebSocketSubprotocol: "mqtt"}.Validate()

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHealthCheckConfigInvalid)
	})

	t.Run("allows a subprotocol with websocket", func(t *testing.T) {
		assert.NoError(t, HealthCheckConfig{Protocol: HealthCheckProtocolWebSocket, WebSocketSubprotocol: "mqtt"}.Validate())
	})
}

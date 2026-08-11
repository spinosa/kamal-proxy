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

// A WebSocket-only target (an MQTT-over-WebSocket broker, for instance) has no
// HTTP endpoint to offer: a plain GET is answered by closing the connection.
// Checking it with the WebSocket handshake tests the port clients actually use,
// instead of a second listener that proves nothing about the first.
func TestHealthCheckWithWebSocketProtocol(t *testing.T) {
	websocketTarget := func(t *testing.T) *url.URL {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Upgrade") != "websocket" {
				// What a WebSocket-only server does with a plain GET.
				http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
				return
			}
			// Complete the handshake the way RFC 6455 requires.
			w.Header().Set("Sec-WebSocket-Accept", webSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
			w.WriteHeader(http.StatusSwitchingProtocols)
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

// Regression: a real WebSocket server completes the handshake and then waits
// for the client to speak the protocol -- it does not close the connection.
// Draining the response body in that state blocks until the timeout, so the
// check reports nothing at all: no success, no failure, just a stalled deploy.
// The httptest servers above hide this by returning from the handler (which
// closes the connection), so this one holds it open the way a broker does.
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
				// Case-insensitive on purpose: Go writes this header in its own
				// canonical form ("Sec-Websocket-Key"), and header names are
				// case-insensitive on the wire anyway.
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

// Answering 101 is cheap; deriving the right digest from our key is not. A
// target that does the former but not the latter is not a WebSocket endpoint,
// and treating it as healthy would route real traffic at it.
func TestHealthCheckWebSocketRejectsABogusHandshake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Sec-WebSocket-Accept", "obviously-not-the-right-digest")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	consumer := make(mockHealthCheckConsumer)
	hc := NewHealthCheck(consumer, serverURL, shortTimeout, shortTimeout, "", HealthCheckProtocolWebSocket, "")
	t.Cleanup(hc.Close)

	assert.False(t, <-consumer)
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

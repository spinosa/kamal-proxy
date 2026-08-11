package server

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

const (
	healthCheckUserAgent = "kamal-proxy"

	// Health check protocols. `http` sends a GET and requires a 2xx.
	// `websocket` sends the opening handshake of a WebSocket connection and
	// requires a 101, so that WebSocket-only targets -- which have no HTTP
	// endpoint to offer -- can be checked on the port they actually serve,
	// rather than needing a second listener that proves nothing about the
	// first one.
	HealthCheckProtocolHTTP      = "http"
	HealthCheckProtocolWebSocket = "websocket"

	// RFC 6455's fixed GUID, concatenated with our key and hashed by the server
	// to produce Sec-WebSocket-Accept. Not a security mechanism: it exists so a
	// client can tell a real WebSocket endpoint from something that merely
	// answers 101.
	webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var (
	ErrorHealthCheckRequestTimedOut  = errors.New("request timed out")
	ErrorHealthCheckUnexpectedStatus = errors.New("unexpected status")
	ErrorHealthCheckInvalidHandshake = errors.New("invalid websocket handshake")
)

type HealthCheckConsumer interface {
	HealthCheckCompleted(success bool)
}

type HealthCheck struct {
	consumer    HealthCheckConsumer
	endpoint    *url.URL
	interval    time.Duration
	timeout     time.Duration
	host        string
	protocol    string
	subprotocol string

	ctx    context.Context
	cancel context.CancelFunc
}

func NewHealthCheck(consumer HealthCheckConsumer, endpoint *url.URL, interval time.Duration, timeout time.Duration, host string, protocol string, subprotocol string) *HealthCheck {
	ctx, cancel := context.WithCancel(context.Background())

	if protocol == "" {
		protocol = HealthCheckProtocolHTTP
	}

	hc := &HealthCheck{
		consumer:    consumer,
		endpoint:    endpoint,
		interval:    interval,
		timeout:     timeout,
		host:        host,
		protocol:    protocol,
		subprotocol: subprotocol,

		ctx:    ctx,
		cancel: cancel,
	}

	go hc.run()
	return hc
}

func (hc *HealthCheck) Close() {
	hc.cancel()
}

// Private

func (hc *HealthCheck) run() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	hc.check()

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.check()
		}
	}
}

func (hc *HealthCheck) check() {
	ctx, cancel := context.WithTimeout(hc.ctx, hc.timeout)
	defer cancel()

	var websocketKey string

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hc.endpoint.String(), nil)
	if err != nil {
		hc.reportResult(false, err)
		return
	}

	req.Header.Set("User-Agent", healthCheckUserAgent)

	if hc.protocol == HealthCheckProtocolWebSocket {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		// RFC 6455 4.1: the key MUST be a randomly selected 16-byte value,
		// freshly chosen for each connection. It is not a secret -- it stops
		// intermediaries from replaying a cached handshake -- but a fixed one
		// would both violate the spec and defeat that purpose.
		key, err := newWebSocketKey()
		if err != nil {
			hc.reportResult(false, err)
			return
		}
		websocketKey = key

		req.Header.Set("Sec-WebSocket-Key", key)
		req.Header.Set("Sec-WebSocket-Version", "13")

		if hc.subprotocol != "" {
			req.Header.Set("Sec-WebSocket-Protocol", hc.subprotocol)
		}
	}

	if hc.host != "" {
		req.Host = hc.host
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			err = ErrorHealthCheckRequestTimedOut
		}
		hc.reportResult(false, err)
		return
	}
	defer resp.Body.Close()

	// Draining lets the connection be reused, but it must not happen on an
	// upgrade. Go replaces Response.Body with the underlying connection
	// (net/http's readWriteCloserBody) when a response is a genuine protocol
	// switch -- 101 AND an Upgrade header AND Connection: Upgrade, see
	// Response.isProtocolSwitch. Reading that body blocks until the peer sends
	// something, which for a protocol we deliberately don't speak is never, so
	// the check would report neither success nor failure.
	//
	// Skipping on any 101 is a superset of that condition and safe either way:
	// a connection that has switched protocols is not reusable for HTTP, so
	// there is nothing to gain by draining it. Close() below still runs.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	if !hc.statusIsHealthy(resp.StatusCode) {
		hc.reportResult(false, fmt.Errorf("%w (%d)", ErrorHealthCheckUnexpectedStatus, resp.StatusCode))
		return
	}

	// Answering 101 is not the same as speaking WebSocket. Verifying the digest
	// the server derived from our key is what distinguishes a real endpoint
	// from anything that just returns the right number.
	if hc.protocol == HealthCheckProtocolWebSocket {
		if got, want := resp.Header.Get("Sec-WebSocket-Accept"), webSocketAccept(websocketKey); got != want {
			hc.reportResult(false, ErrorHealthCheckInvalidHandshake)
			return
		}
	}

	hc.reportResult(true, nil)
}

// A successful WebSocket handshake answers 101 Switching Protocols, which is
// not a 2xx. We close the connection immediately afterwards without speaking
// the protocol -- completing the handshake proves the listener is accepting
// and answering connections, which is what a health check is for.
func (hc *HealthCheck) statusIsHealthy(status int) bool {
	if hc.protocol == HealthCheckProtocolWebSocket {
		return status == http.StatusSwitchingProtocols
	}

	return status >= 200 && status <= 299
}

func newWebSocketKey() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(nonce), nil
}

// The digest RFC 6455 requires the server to return for a given key. SHA-1 is
// mandated by the protocol here and is not being relied on for security.
func webSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + webSocketGUID))

	return base64.StdEncoding.EncodeToString(sum[:])
}

func (hc *HealthCheck) reportResult(success bool, err error) {
	if !success {
		slog.Info("Healthcheck failed", "url", hc.endpoint.String(), "error", err)
	}

	hc.consumer.HealthCheckCompleted(success)
}

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

	// WebSocket-only targets have no HTTP endpoint to check, and answer a GET
	// by closing the connection.
	HealthCheckProtocolHTTP      = "http"
	HealthCheckProtocolWebSocket = "websocket"

	// Concatenated with our key and hashed by the server to produce
	// Sec-WebSocket-Accept (RFC 6455).
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
		// RFC 6455 4.1 requires a fresh random nonce for each connection.
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

	// On a protocol switch, Response.Body is the underlying connection (see
	// Response.isProtocolSwitch), and reading it blocks until the peer sends
	// something. Nothing to drain in that case anyway, as the connection can
	// no longer be reused for HTTP.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	if !hc.statusIsHealthy(resp.StatusCode) {
		hc.reportResult(false, fmt.Errorf("%w (%d)", ErrorHealthCheckUnexpectedStatus, resp.StatusCode))
		return
	}

	// Check that the server derived the digest from our key, not just that it
	// answered 101.
	if hc.protocol == HealthCheckProtocolWebSocket {
		if got, want := resp.Header.Get("Sec-WebSocket-Accept"), webSocketAccept(websocketKey); got != want {
			hc.reportResult(false, ErrorHealthCheckInvalidHandshake)
			return
		}
	}

	hc.reportResult(true, nil)
}

// A successful WebSocket handshake answers 101, which is not a 2xx.
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

// webSocketAccept returns the digest RFC 6455 requires the server to send back
// for a given key. SHA-1 is mandated by the protocol, not chosen for security.
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

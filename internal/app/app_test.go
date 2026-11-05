package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/config"
	applog "github.com/akhmed9505/kaspersky-backend-internship/internal/logger"
)

func serverConfig(t *testing.T) (config.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("cannot trust test certificate")
	}
	return config.Config{Address: ":8443", CertificateFile: certFile, PrivateKeyFile: keyFile, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16384}, roots
}

func TestTLSConfigurationAndHandshake(t *testing.T) {
	cfg, roots := serverConfig(t)
	server, err := newServer(cfg, applog.New(io.Discard, slog.LevelInfo), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS12 || server.ReadHeaderTimeout != cfg.ReadHeaderTimeout || server.WriteTimeout != cfg.WriteTimeout || server.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatal("server settings not applied")
	}
	for _, version := range []uint16{tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			_ = clientSide.SetDeadline(time.Now().Add(2 * time.Second))
			_ = serverSide.SetDeadline(time.Now().Add(2 * time.Second))
			client := tls.Client(clientSide, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: version, MaxVersion: version})
			serverTLS := server.TLSConfig.Clone()
			// Handshake-only peers do not consume post-handshake session tickets.
			serverTLS.SessionTicketsDisabled = true
			remote := tls.Server(serverSide, serverTLS)
			done := make(chan error, 1)
			go func() { done <- remote.Handshake() }()
			clientErr := client.Handshake()
			serverErr := <-done
			if version < tls.VersionTLS12 {
				if clientErr == nil || serverErr == nil {
					t.Fatal("TLS 1.1 accepted")
				}
			} else if clientErr != nil || serverErr != nil {
				t.Fatalf("handshake failed: client=%v server=%v", clientErr, serverErr)
			}
		})
	}
	cfg.PrivateKeyFile = filepath.Join(t.TempDir(), "missing-key")
	if _, err := newServer(cfg, applog.New(io.Discard, slog.LevelInfo), nil); err == nil {
		t.Fatal("missing certificate/key accepted")
	}
}

// A real net/http HTTPS server can run on net.Pipe without opening OS sockets.
type memoryListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newMemoryListener() *memoryListener {
	return &memoryListener{connections: make(chan net.Conn), closed: make(chan struct{})}
}
func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memoryListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memoryListener) Addr() net.Addr { return memoryAddress{} }

type memoryAddress struct{}

func (memoryAddress) Network() string { return "pipe" }
func (memoryAddress) String() string  { return "memory-listener" }
func (l *memoryListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.connections <- server:
		return client, nil
	case <-l.closed:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	}
}

func TestGracefulHTTPSShutdown(t *testing.T) {
	cfg, roots := serverConfig(t)
	started, release := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
			t.Error("graceful shutdown canceled an active request")
		}
	})
	server, err := newServer(cfg, applog.New(io.Discard, slog.LevelInfo), handler)
	if err != nil {
		t.Fatal(err)
	}
	listener := newMemoryListener()
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, server, listener, time.Second) }()
	transport := &http.Transport{DialContext: listener.dial, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	responseDone := make(chan error, 1)
	go func() {
		response, err := client.Get("https://localhost/info")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != 204 {
				err = errors.New("unexpected response status")
			}
		}
		responseDone <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTPS handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("server returned before active request completed: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-responseDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestForcedHTTPSShutdown(t *testing.T) {
	cfg, roots := serverConfig(t)
	started, canceled := make(chan struct{}), make(chan struct{})
	server, err := newServer(cfg, applog.New(io.Discard, slog.LevelInfo), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(canceled) }))
	if err != nil {
		t.Fatal(err)
	}
	listener := newMemoryListener()
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, server, listener, 25*time.Millisecond) }()
	transport := &http.Transport{DialContext: listener.dial, TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	clientDone := make(chan struct{})
	go func() {
		response, err := client.Get("https://localhost/info")
		if err == nil {
			_ = response.Body.Close()
		}
		close(clientDone)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTPS handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected forced shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forced shutdown stuck")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("request context not canceled")
	}
	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish")
	}
}

func TestCanceledServerStart(t *testing.T) {
	cfg, _ := serverConfig(t)
	server, err := newServer(cfg, applog.New(io.Discard, slog.LevelInfo), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	listener := newMemoryListener()
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serve(ctx, server, listener, time.Second); err != nil {
		t.Fatal(err)
	}
}

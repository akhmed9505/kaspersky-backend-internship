// Package app assembles dependencies and manages the HTTPS server lifecycle.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/config"
	httpapi "github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/middleware"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/infra/postgres"
	applog "github.com/akhmed9505/kaspersky-backend-internship/internal/logger"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/repository"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
)

// Run builds the application and serves HTTPS until cancellation or a server error.
// Configuration must come from config.Load. Migrations are a separate operation.
func Run(ctx context.Context, c config.Config, logger *slog.Logger) error {
	server, err := newServer(c, logger, nil)
	if err != nil {
		return err
	}
	pool, err := postgres.NewPool(ctx, postgres.Config{DSN: c.DatabaseDSN, MaxConns: c.DatabaseMaxConns, ConnectTimeout: c.DatabaseConnectTimeout})
	if err != nil {
		return errors.New("PostgreSQL initialization failed")
	}
	// serve returns only after shutdown/forced close; do not close the pool earlier.
	defer pool.Close()
	router := httpapi.NewRouter(httpapi.NewHandler(threat.New(repository.NewThreat(pool))))
	server.Handler, err = middleware.New(router, middleware.Config{APIKey: c.APIKey, GlobalRPS: c.GlobalRPS, GlobalBurst: c.GlobalBurst, AuthorizedRPS: c.AuthorizedRPS, AuthorizedBurst: c.AuthorizedBurst, RequestTimeout: c.RequestTimeout}, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", c.Address)
	if err != nil {
		return errors.New("cannot open HTTPS listener")
	}
	logger.Info("HTTPS server started")
	return serve(ctx, server, listener, c.ShutdownTimeout)
}

func newServer(c config.Config, logger *slog.Logger, handler http.Handler) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(c.CertificateFile, c.PrivateKeyFile)
	if err != nil {
		return nil, errors.New("cannot load TLS certificate and private key")
	}
	return &http.Server{Addr: c.Address, Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: c.ReadHeaderTimeout, ReadTimeout: c.ReadTimeout, WriteTimeout: c.WriteTimeout, IdleTimeout: c.IdleTimeout, MaxHeaderBytes: c.MaxHeaderBytes, ErrorLog: applog.HTTPErrorLog(logger)}, nil
}

func serve(ctx context.Context, server *http.Server, listener net.Listener, timeout time.Duration) error {
	defer listener.Close()
	requestContext, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	server.BaseContext = func(net.Listener) context.Context { return requestContext }
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	var serveErr error
	serverExited := false
	select {
	case <-ctx.Done():
	case serveErr = <-done:
		serverExited = true
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownContext)
	if shutdownErr != nil {
		cancelRequests()
		_ = server.Close()
	}
	if !serverExited {
		serveErr = <-done
	}
	if shutdownErr != nil {
		return fmt.Errorf("HTTPS shutdown: %w", shutdownErr)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("HTTPS server failed")
	}
	return nil
}

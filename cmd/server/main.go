// Command server starts the Information Exchange Service over HTTPS.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/app"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/config"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/logger"
)

func main() { os.Exit(run()) }
func run() int {
	log := logger.New(os.Stderr, slog.LevelInfo)
	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return 1
	}
	log = logger.New(os.Stderr, cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("application stopped", "error", err.Error())
		return 1
	}
	log.Info("application stopped")
	return 0
}

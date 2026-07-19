package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"vpn-api/internal/api"
	"vpn-api/internal/clients"
	"vpn-api/internal/config"
	"vpn-api/internal/crypto"
	"vpn-api/internal/database"
	"vpn-api/internal/xui"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if err := database.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	encKey, err := crypto.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return err
	}
	cryptor, err := crypto.NewAESGCM(encKey)
	if err != nil {
		return err
	}

	panel, err := xui.NewPanel(cfg.XUIBaseURL, cfg.XUIAPIToken)
	if err != nil {
		return err
	}

	clientsSvc := clients.NewService(pool, panel, cryptor, cfg.XUIInboundID, cfg.HysteriaConfigPath, cfg.HysteriaReloadCommand)

	r := api.NewRouter(pool, clientsSvc)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

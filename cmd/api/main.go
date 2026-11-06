package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/yourusername/usermgmt/internal/config"
	"github.com/yourusername/usermgmt/internal/middleware"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/db"
	"github.com/yourusername/usermgmt/internal/platform/httpx"
)

func main() {
	// 1. Load config
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 2. Setup structured logging
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	slog.Info("starting user management service", "addr", cfg.HTTPAddr)

	// 3. Connect to DB
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DBHealthCheckPeriod)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg)
	if err != nil {
		slog.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	slog.Info("connected to database pool")

	// 4. Connect to Cache (Redis or fallback to in-memory)
	var cacheBackend cache.Cache
	if cfg.RedisURL != "" {
		rc, err := cache.NewRedis(cfg.RedisURL)
		if err != nil {
			slog.Warn("failed to initialize redis client, falling back to in-memory cache", "err", err)
			cacheBackend = cache.NewMemory()
		} else {
			if err := rc.Ping(context.Background()); err != nil {
				slog.Warn("redis ping failed, falling back to in-memory cache", "err", err)
				cacheBackend = cache.NewMemory()
			} else {
				slog.Info("connected to redis cache")
				cacheBackend = rc
			}
		}
	} else {
		slog.Info("using in-memory cache (REDIS_URL not configured)")
		cacheBackend = cache.NewMemory()
	}

	// 5. Router & Middlewares
	r := chi.NewRouter()
	r.Use(httpx.RequestIDMiddleware)
	r.Use(middleware.Recover)
	r.Use(middleware.Logger)

	// Health check endpoints
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		pingCtx, pingCancel := context.WithTimeout(r.Context(), cfg.DBHealthCheckPeriod)
		defer pingCancel()

		if err := pool.Ping(pingCtx); err != nil {
			slog.Error("readiness check failed: db ping error", "err", err)
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unready",
				"error":  "database unavailable",
			})
			return
		}

		if err := cacheBackend.Ping(pingCtx); err != nil {
			slog.Error("readiness check failed: cache ping error", "err", err)
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unready",
				"error":  "cache unavailable",
			})
			return
		}

		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	// 6. HTTP Server
	server := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// 7. Graceful Shutdown
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		slog.Error("server failed to start", "err", err)
		os.Exit(1)
	case sig := <-quit:
		slog.Info("shutting down server...", "signal", sig.String())
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server forced to shutdown", "err", err)
	} else {
		slog.Info("server exited cleanly")
	}
}


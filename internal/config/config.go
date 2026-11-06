package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v10"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Server
	HTTPAddr         string        `env:"HTTP_ADDR"          envDefault:":8080"`
	ReadTimeout      time.Duration `env:"READ_TIMEOUT"       envDefault:"10s"`
	WriteTimeout     time.Duration `env:"WRITE_TIMEOUT"      envDefault:"30s"`
	IdleTimeout      time.Duration `env:"IDLE_TIMEOUT"       envDefault:"60s"`
	ShutdownTimeout  time.Duration `env:"SHUTDOWN_TIMEOUT"   envDefault:"15s"`
	MaxRequestBodyMB int64         `env:"MAX_REQUEST_BODY_MB" envDefault:"1"`

	// Database
	DatabaseURL        string        `env:"DATABASE_URL"             envDefault:"postgres://postgres:postgres@localhost:5432/usermgmt?sslmode=disable"`
	DBMaxConns         int32         `env:"DB_MAX_CONNS"             envDefault:"25"`
	DBMinConns         int32         `env:"DB_MIN_CONNS"             envDefault:"5"`
	DBMaxConnLifetime  time.Duration `env:"DB_MAX_CONN_LIFETIME"     envDefault:"1h"`
	DBMaxConnIdleTime  time.Duration `env:"DB_MAX_CONN_IDLE"         envDefault:"5m"`
	DBHealthCheckPeriod time.Duration `env:"DB_HEALTH_CHECK_PERIOD"  envDefault:"1m"`

	// Redis
	RedisURL string `env:"REDIS_URL" envDefault:""`

	// JWT
	JWTSecret    string        `env:"JWT_SECRET"`
	JWTKid       string        `env:"JWT_KID"          envDefault:"v1"`
	JWTIssuer    string        `env:"JWT_ISSUER"       envDefault:"usermgmt"`
	JWTAudience  string        `env:"JWT_AUDIENCE"     envDefault:"usermgmt-api"`
	AccessTTL    time.Duration `env:"ACCESS_TTL"       envDefault:"15m"`
	RefreshTTL   time.Duration `env:"REFRESH_TTL"      envDefault:"168h"` // 7 days

	// Bcrypt
	BcryptCost int `env:"BCRYPT_COST" envDefault:"12"`

	// Cache TTLs
	PermCacheTTL    time.Duration `env:"PERM_CACHE_TTL"    envDefault:"5m"`
	TenantCacheTTL  time.Duration `env:"TENANT_CACHE_TTL"  envDefault:"30s"`

	// Migrations
	MigrationsPath string `env:"MIGRATIONS_PATH" envDefault:"migrations"`

	// Features
	EnableRLS bool `env:"ENABLE_RLS" envDefault:"false"`

	// Logging
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("config: parse env: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.JWTSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 bytes, got %d", len(c.JWTSecret))
	}
	return nil
}

// Package api configures the HTTP router and dependency wiring for the service.
package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/auth"
	"github.com/yourusername/usermgmt/internal/config"
	"github.com/yourusername/usermgmt/internal/middleware"
	"github.com/yourusername/usermgmt/internal/permission"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/httpx"
	"github.com/yourusername/usermgmt/internal/platform/jwtx"
	"github.com/yourusername/usermgmt/internal/platform/password"
	"github.com/yourusername/usermgmt/internal/role"
	"github.com/yourusername/usermgmt/internal/tenant"
	"github.com/yourusername/usermgmt/internal/user"
)

// NewRouter constructs the complete HTTP handler with all domains and middlewares.
func NewRouter(cfg *config.Config, pool *pgxpool.Pool, cacheBackend cache.Cache) http.Handler {
	r := chi.NewRouter()

	// Base middlewares
	r.Use(httpx.RequestIDMiddleware)
	r.Use(middleware.Recover)
	r.Use(middleware.Logger)

	// Platform & Infrastructure Services
	hasher := password.New(cfg.BcryptCost)
	issuer := jwtx.New(jwtx.Config{
		Secret:   []byte(cfg.JWTSecret),
		Kid:      cfg.JWTKid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})
	auditor := audit.NewRecorder()

	// Domains
	auditRepo := audit.NewRepository(pool)
	auditHandler := audit.NewHandler(auditRepo)

	permRepo := permission.NewRepository(pool)
	permResolver := permission.NewResolver(permRepo, cacheBackend, cfg.PermCacheTTL)
	permHandler := permission.NewHandler(permRepo)

	authRepo := auth.NewRepo(pool)
	authSvc := auth.NewService(pool, authRepo, issuer, hasher, cacheBackend, auditor, auth.Config{
		AccessTTL:  cfg.AccessTTL,
		RefreshTTL: cfg.RefreshTTL,
	})
	authHandler := auth.NewHandler(authSvc, permResolver)

	tenantRepo := tenant.NewRepository(pool)
	tenantSvc := tenant.NewService(pool, tenantRepo, hasher, cacheBackend, auditor)
	tenantHandler := tenant.NewHandler(tenantSvc)

	userRepo := user.NewRepository(pool)
	userSvc := user.NewService(pool, userRepo, hasher, permResolver, cacheBackend, auditor)
	userHandler := user.NewHandler(userSvc)

	roleRepo := role.NewRepository(pool)
	roleSvc := role.NewService(pool, roleRepo, permResolver, auditor)
	roleHandler := role.NewHandler(roleSvc)

	// Liveness & Readiness checks
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), cfg.DBHealthCheckPeriod)
		defer cancel()

		if err := pool.Ping(ctx); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unready",
				"error":  "database unavailable",
			})
			return
		}
		if err := cacheBackend.Ping(ctx); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unready",
				"error":  "cache unavailable",
			})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	// Swagger / OpenAPI documentation
	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/openapi.yaml")
	})

	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
	})

	r.Get("/swagger/index.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		const swaggerUI = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Multi-Tenant User Management API - Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" charset="UTF-8"></script>
<script>
  window.onload = () => {
    window.ui = SwaggerUIBundle({
      url: '/openapi.yaml',
      dom_id: '#swagger-ui',
    });
  };
</script>
</body>
</html>`
		w.Write([]byte(swaggerUI))
	})

	// API Routes under /api/v1
	r.Route("/api/v1", func(api chi.Router) {
		// Public Auth Routes
		api.Post("/auth/login", authHandler.Login)
		api.Post("/auth/refresh", authHandler.Refresh)

		// Authenticated & Tenant-Active Routes
		api.Group(func(authed chi.Router) {
			authed.Use(middleware.Authenticate(authSvc))
			authed.Use(middleware.TenantActive(tenantSvc))

			// Auth Context operations
			authed.Post("/auth/logout", authHandler.Logout)
			authed.Post("/auth/switch-tenant", authHandler.SwitchTenant)
			authed.Get("/auth/me", authHandler.Me)

			// Platform Tenant Only Routes (/tenants)
			authed.Group(func(platform chi.Router) {
				platform.Use(tenantHandler.PlatformOnlyGuard)

				platform.With(middleware.RequirePermission(permResolver, "tenant:create")).
					Post("/tenants", tenantHandler.CreateTenant)
				platform.With(middleware.RequirePermission(permResolver, "tenant:read")).
					Get("/tenants", tenantHandler.ListTenants)
				platform.With(middleware.RequirePermission(permResolver, "tenant:read")).
					Get("/tenants/{id}", tenantHandler.GetTenant)
				platform.With(middleware.RequirePermission(permResolver, "tenant:update")).
					Patch("/tenants/{id}", tenantHandler.UpdateTenant)
				platform.With(middleware.RequirePermission(permResolver, "tenant:suspend")).
					Post("/tenants/{id}/suspend", tenantHandler.SuspendTenant)
				platform.With(middleware.RequirePermission(permResolver, "tenant:suspend")).
					Post("/tenants/{id}/activate", tenantHandler.ActivateTenant)
			})

			// Current Tenant Routes (/tenant)
			authed.With(middleware.RequirePermission(permResolver, "tenant:read")).
				Get("/tenant", tenantHandler.GetCurrentTenant)
			authed.With(middleware.RequirePermission(permResolver, "tenant:update")).
				Patch("/tenant", tenantHandler.UpdateCurrentTenant)

			// Users Routes (/users)
			authed.With(middleware.RequirePermission(permResolver, "user:create")).
				Post("/users", userHandler.CreateUser)
			authed.With(middleware.RequirePermission(permResolver, "user:read")).
				Get("/users", userHandler.ListUsers)
			authed.With(middleware.RequirePermission(permResolver, "user:read")).
				Get("/users/{id}", userHandler.GetUser)
			authed.With(middleware.RequirePermission(permResolver, "user:update")).
				Patch("/users/{id}", userHandler.UpdateUser)
			authed.With(middleware.RequirePermission(permResolver, "user:delete")).
				Delete("/users/{id}", userHandler.DeleteUser)
			authed.With(middleware.RequirePermission(permResolver, "user:update")).
				Put("/users/{id}/password", userHandler.ChangePassword)

			// User Roles Assignment
			authed.With(middleware.RequirePermission(permResolver, "role:assign")).
				Put("/users/{id}/roles", userHandler.AssignRoles)
			authed.With(middleware.RequirePermission(permResolver, "role:assign")).
				Post("/users/{id}/roles/{roleId}", userHandler.AddRole)
			authed.With(middleware.RequirePermission(permResolver, "role:assign")).
				Delete("/users/{id}/roles/{roleId}", userHandler.RemoveRole)

			// Roles Routes (/roles)
			authed.With(middleware.RequirePermission(permResolver, "role:create")).
				Post("/roles", roleHandler.CreateRole)
			authed.With(middleware.RequirePermission(permResolver, "role:read")).
				Get("/roles", roleHandler.ListRoles)
			authed.With(middleware.RequirePermission(permResolver, "role:read")).
				Get("/roles/{id}", roleHandler.GetRole)
			authed.With(middleware.RequirePermission(permResolver, "role:update")).
				Patch("/roles/{id}", roleHandler.UpdateRole)
			authed.With(middleware.RequirePermission(permResolver, "role:delete")).
				Delete("/roles/{id}", roleHandler.DeleteRole)
			authed.With(middleware.RequirePermission(permResolver, "permission:assign")).
				Put("/roles/{id}/permissions", roleHandler.AssignPermissions)

			// Permissions Catalog Route
			authed.With(middleware.RequirePermission(permResolver, "permission:read")).
				Get("/permissions", permHandler.ListPermissions)

			// Audit Logs Route
			authed.With(middleware.RequirePermission(permResolver, "audit:read")).
				Get("/audit-logs", auditHandler.ListAuditLogs)
		})
	})

	return r
}


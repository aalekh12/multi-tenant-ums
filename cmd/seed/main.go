// Command seed populates demo tenants, roles, users, and permissions idempotently.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/usermgmt/internal/config"
	"github.com/yourusername/usermgmt/internal/platform/password"
)

type tenantSeed struct {
	id         string
	code       string
	name       string
	isPlatform bool
}

type rolePermDef struct {
	name        string
	description string
	isSystem    bool
	permCodes   []string
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("database ping failed: %v", err)
	}

	hasher := password.New(cfg.BcryptCost)
	defaultPassword := "ChangeMe!12345"
	pwHash, err := hasher.Hash(defaultPassword)
	if err != nil {
		log.Fatalf("failed to hash default password: %v", err)
	}

	fmt.Println("==================================================")
	fmt.Println(" Seeding Multi-Tenant User Management Database")
	fmt.Println("==================================================")

	// 1. Ensure permissions catalog exists
	allPerms, err := getOrSeedPermissions(ctx, pool)
	if err != nil {
		log.Fatalf("failed to verify permissions catalog: %v", err)
	}
	fmt.Printf("[✓] Catalog verified: %d permissions active\n", len(allPerms))

	// Non-platform perms (all except tenant:*)
	var tenantAdminPerms []string
	var userManagerPerms []string
	var viewerPerms []string

	for _, p := range allPerms {
		if p != "tenant:create" && p != "tenant:suspend" {
			tenantAdminPerms = append(tenantAdminPerms, p)
		}
		if p == "user:create" || p == "user:read" || p == "user:update" || p == "user:delete" ||
			p == "role:read" || p == "permission:read" {
			userManagerPerms = append(userManagerPerms, p)
		}
		if p == "user:read" || p == "role:read" || p == "permission:read" || p == "tenant:read" {
			viewerPerms = append(viewerPerms, p)
		}
	}

	// 2. Platform Tenant
	platformTenant, err := upsertTenant(ctx, pool, "platform", "Platform Admin", true)
	if err != nil {
		log.Fatalf("failed to seed platform tenant: %v", err)
	}
	fmt.Printf("[✓] Seeded Tenant: %-10s (ID: %s, Platform: true)\n", platformTenant.code, platformTenant.id)

	platformAdminRoleID, err := upsertRoleWithPerms(ctx, pool, platformTenant.id, "platform_admin", "Full platform access across all domains", true, allPerms)
	if err != nil {
		log.Fatalf("failed to seed platform_admin role: %v", err)
	}

	rootUser, err := upsertUser(ctx, pool, "root@platform.test", pwHash, "Platform Superadmin")
	if err != nil {
		log.Fatalf("failed to seed root user: %v", err)
	}
	if err := assignUserRole(ctx, pool, platformTenant.id, rootUser, platformAdminRoleID, rootUser); err != nil {
		log.Fatalf("failed to assign platform role: %v", err)
	}
	fmt.Printf("    - User: root@platform.test -> platform_admin\n")

	// 3. Acme Tenant
	acmeTenant, err := upsertTenant(ctx, pool, "acme", "Acme Corp", false)
	if err != nil {
		log.Fatalf("failed to seed acme tenant: %v", err)
	}
	fmt.Printf("[✓] Seeded Tenant: %-10s (ID: %s, Platform: false)\n", acmeTenant.code, acmeTenant.id)

	acmeAdminRoleID, err := upsertRoleWithPerms(ctx, pool, acmeTenant.id, "tenant_admin", "Full administrative control of Acme Corp", true, tenantAdminPerms)
	if err != nil {
		log.Fatalf("failed to seed acme tenant_admin: %v", err)
	}
	acmeManagerRoleID, err := upsertRoleWithPerms(ctx, pool, acmeTenant.id, "user_manager", "Can manage users and memberships in Acme Corp", true, userManagerPerms)
	if err != nil {
		log.Fatalf("failed to seed acme user_manager: %v", err)
	}
	acmeViewerRoleID, err := upsertRoleWithPerms(ctx, pool, acmeTenant.id, "viewer", "Read-only access to Acme Corp", true, viewerPerms)
	if err != nil {
		log.Fatalf("failed to seed acme viewer: %v", err)
	}

	acmeAdmin, _ := upsertUser(ctx, pool, "admin@acme.test", pwHash, "Acme Administrator")
	_ = assignUserRole(ctx, pool, acmeTenant.id, acmeAdmin, acmeAdminRoleID, acmeAdmin)
	fmt.Printf("    - User: admin@acme.test   -> tenant_admin\n")

	acmeManager, _ := upsertUser(ctx, pool, "manager@acme.test", pwHash, "Acme User Manager")
	_ = assignUserRole(ctx, pool, acmeTenant.id, acmeManager, acmeManagerRoleID, acmeAdmin)
	fmt.Printf("    - User: manager@acme.test -> user_manager\n")

	acmeViewer, _ := upsertUser(ctx, pool, "viewer@acme.test", pwHash, "Acme Viewer")
	_ = assignUserRole(ctx, pool, acmeTenant.id, acmeViewer, acmeViewerRoleID, acmeAdmin)
	fmt.Printf("    - User: viewer@acme.test  -> viewer\n")

	// 50 filler users for pagination
	for i := 1; i <= 50; i++ {
		email := fmt.Sprintf("user%02d@acme.test", i)
		name := fmt.Sprintf("Acme User %02d", i)
		uID, err := upsertUser(ctx, pool, email, pwHash, name)
		if err == nil {
			_ = assignUserRole(ctx, pool, acmeTenant.id, uID, acmeViewerRoleID, acmeAdmin)
		}
	}
	fmt.Printf("    - Seeded 50 filler users (user01@acme.test .. user50@acme.test) -> viewer\n")

	// 4. Globex Tenant
	globexTenant, err := upsertTenant(ctx, pool, "globex", "Globex Corporation", false)
	if err != nil {
		log.Fatalf("failed to seed globex tenant: %v", err)
	}
	fmt.Printf("[✓] Seeded Tenant: %-10s (ID: %s, Platform: false)\n", globexTenant.code, globexTenant.id)

	globexAdminRoleID, err := upsertRoleWithPerms(ctx, pool, globexTenant.id, "tenant_admin", "Full administrative control of Globex Corp", true, tenantAdminPerms)
	if err != nil {
		log.Fatalf("failed to seed globex tenant_admin: %v", err)
	}
	_, err = upsertRoleWithPerms(ctx, pool, globexTenant.id, "viewer", "Read-only access to Globex Corp", true, viewerPerms)
	if err != nil {
		log.Fatalf("failed to seed globex viewer: %v", err)
	}

	globexAdmin, _ := upsertUser(ctx, pool, "admin@globex.test", pwHash, "Globex Administrator")
	_ = assignUserRole(ctx, pool, globexTenant.id, globexAdmin, globexAdminRoleID, globexAdmin)
	fmt.Printf("    - User: admin@globex.test -> tenant_admin\n")

	// 5. Multi-Tenant User (shared@example.test)
	sharedUser, err := upsertUser(ctx, pool, "shared@example.test", pwHash, "Cross-Tenant User")
	if err != nil {
		log.Fatalf("failed to seed shared user: %v", err)
	}
	_ = assignUserRole(ctx, pool, acmeTenant.id, sharedUser, acmeViewerRoleID, acmeAdmin)
	_ = assignUserRole(ctx, pool, globexTenant.id, sharedUser, globexAdminRoleID, globexAdmin)
	fmt.Printf("[✓] Seeded Cross-Tenant User: shared@example.test\n")
	fmt.Printf("    - Membership in 'acme'   -> viewer\n")
	fmt.Printf("    - Membership in 'globex' -> tenant_admin\n")

	fmt.Println("\n==================================================")
	fmt.Println(" Seed Credentials Summary")
	fmt.Println(" Password for all accounts: ChangeMe!12345")
	fmt.Println("==================================================")
	fmt.Println("| Tenant   | Email                 | Roles / Purpose                 |")
	fmt.Println("|----------|-----------------------|---------------------------------|")
	fmt.Println("| platform | root@platform.test    | platform_admin (manage tenants) |")
	fmt.Println("| acme     | admin@acme.test       | tenant_admin (full acme admin)  |")
	fmt.Println("| acme     | manager@acme.test     | user_manager (manage users)     |")
	fmt.Println("| acme     | viewer@acme.test      | viewer (read-only)              |")
	fmt.Println("| globex   | admin@globex.test     | tenant_admin (full globex admin)|")
	fmt.Println("| MULTI    | shared@example.test   | viewer (acme), admin (globex)   |")
	fmt.Println("==================================================")
	fmt.Println("\nSample curl command to login:")
	fmt.Println(`curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.test","password":"ChangeMe!12345","tenant_code":"acme"}'`)
	fmt.Println()
}

func getOrSeedPermissions(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, "SELECT code FROM permissions ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		codes = append(codes, c)
	}
	return codes, nil
}

func upsertTenant(ctx context.Context, pool *pgxpool.Pool, code, name string, isPlatform bool) (*tenantSeed, error) {
	var t tenantSeed
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, code, is_platform, status)
		VALUES ($1, $2, $3, 'active')
		ON CONFLICT (code) DO UPDATE
			SET name = EXCLUDED.name, status = 'active'
		RETURNING id, code, name, is_platform`, name, code, isPlatform,
	).Scan(&t.id, &t.code, &t.name, &t.isPlatform)
	if err != nil {
		return nil, fmt.Errorf("upsert tenant %s: %w", code, err)
	}
	return &t, nil
}

func upsertRoleWithPerms(ctx context.Context, pool *pgxpool.Pool, tenantID, name, desc string, isSystem bool, perms []string) (string, error) {
	var roleID string
	err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, description, is_system)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, name) DO UPDATE
			SET description = EXCLUDED.description
		RETURNING id`, tenantID, name, desc, isSystem,
	).Scan(&roleID)
	if err != nil {
		return "", fmt.Errorf("upsert role %s: %w", name, err)
	}

	for _, p := range perms {
		_, err = pool.Exec(ctx, `
			INSERT INTO role_permissions (tenant_id, role_id, permission_id)
			SELECT $1, $2, id FROM permissions WHERE code = $3
			ON CONFLICT (role_id, permission_id) DO NOTHING`,
			tenantID, roleID, p,
		)
		if err != nil {
			return "", fmt.Errorf("link perm %s to role %s: %w", p, name, err)
		}
	}
	return roleID, nil
}

func upsertUser(ctx context.Context, pool *pgxpool.Pool, email, passwordHash, fullName string) (string, error) {
	var userID string
	err := pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name)
		VALUES ($1, $2, $3)
		ON CONFLICT (email) WHERE deleted_at IS NULL DO UPDATE
			SET full_name = EXCLUDED.full_name
		RETURNING id`, email, passwordHash, fullName,
	).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("upsert user %s: %w", email, err)
	}
	return userID, nil
}

func assignUserRole(ctx context.Context, pool *pgxpool.Pool, tenantID, userID, roleID, assignedBy string) error {
	// Ensure tenant_users membership exists
	_, err := pool.Exec(ctx, `
		INSERT INTO tenant_users (tenant_id, user_id, status)
		VALUES ($1, $2, 'active')
		ON CONFLICT (tenant_id, user_id) DO UPDATE
			SET status = 'active', deleted_at = NULL`,
		tenantID, userID,
	)
	if err != nil {
		return fmt.Errorf("upsert membership %s/%s: %w", tenantID, userID, err)
	}

	// Assign role
	_, err = pool.Exec(ctx, `
		INSERT INTO user_roles (tenant_id, user_id, role_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING`,
		tenantID, userID, roleID, assignedBy,
	)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

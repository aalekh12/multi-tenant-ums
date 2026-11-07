# Multi-Tenant User Management System (Go + PostgreSQL + Redis)

A multi-tenant user management backend platform designed for security, strict tenant isolation, and horizontal scalability.

Built in Go 1.22+ using pure PostgreSQL (jackc/pgx/v5 connection pool, handwritten SQL, no ORM), Redis shared cache, and `go-chi/chi/v5`.

---

## 1. Architecture Overview

The system implements clean 3-layer architecture (`Handler → Service → Repository`) per domain, with strict layer isolation and interfaces for complete unit testability.

```mermaid
flowchart TD
    Client(["HTTP Client / SPA"])

    subgraph MiddlewareChain ["HTTP Middleware Pipeline"]
        direction TB
        MW1["RequestID (httpx)"] --> MW2["Recover (panic recovery)"]
        MW2 --> MW3["Structured Logger (slog JSON)"]
        MW3 --> MW4["Authenticate (JWT HS256 validation)"]
        MW4 --> MW5["TenantActive (status cache / DB)"]
        MW5 --> MW6["RequirePermission (cached RBAC resolver)"]
    end

    subgraph Domains ["Domain Services"]
        direction TB
        AuthSvc["Auth Service\n(login, token rotation, reuse revocation)"]
        TenantSvc["Tenant Service\n(bootstrap, lifecycle, suspension)"]
        UserSvc["User Service\n(memberships, soft-delete, roles)"]
        RoleSvc["Role Service\n(RBAC, escalation guard, perms)"]
        AuditSvc["Audit Recorder\n(transactional audit logs)"]
    end

    subgraph DataStorage ["Data & Cache Layer"]
        PG[("PostgreSQL 15+\nComposite FKs, Partial Indexes")]
        Redis[("Redis Cache\nPerms 5m, Tenant 30s, SingleFlight")]
    end

    Client --> MiddlewareChain
    MiddlewareChain --> Domains
    Domains --> PG
    Domains --> Redis
```

---

## 2. Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| **Language** | Go 1.22+ | Statically typed, high throughput, low memory footprint |
| **HTTP Router** | `go-chi/chi/v5` | Lightweight, 100% `net/http` compatible, idiomatic middleware |
| **Database Pool** | `jackc/pgx/v5/pgxpool` | High-performance PostgreSQL native driver with connection pooling (no ORM) |
| **Migrations** | `golang-migrate/migrate` | Versioned, bidirectional SQL migrations (`migrations/000001` .. `000007`) |
| **Authentication** | `golang-jwt/jwt/v5` | HS256 JWT access tokens + family-tracked refresh tokens |
| **Password Hashing** | `golang.org/x/crypto/bcrypt` | Configurable cost (default 12, 4 in test) with dummy hash timing protection |
| **Validation** | `go-playground/validator/v10` | Struct validation with custom `password_policy` |
| **Caching** | Interface `cache.Cache` | Redis (`go-redis/v9`) with in-memory fallback + singleflight stampede guard |
| **Structured Logs** | `log/slog` | Correlated JSON logging with `request_id`, `tenant_id`, and `actor_id` |

---

## 3. Key Decisions & Security Model

1. **Strict Tenant Isolation (404 Not Found):**
   - Attempting to access another tenant's resource returns `404 Not Found` (never `403` or `200`). Foreign resource IDs are indistinguishable from nonexistent IDs to prevent probing.
2. **Stateless JWT Claims & Token-Only Context:**
   - The active tenant ID is extracted exclusively from the cryptographically verified JWT `tid` claim.
   - Request bodies attempting to inject `tenant_id` are strictly rejected with `400 Bad Request` (`UNKNOWN_FIELD`).
3. **Physical Isolation via Composite Foreign Keys:**
   - `user_roles` references `(tenant_id, user_id)` and `(tenant_id, role_id)`.
   - `role_permissions` references `(tenant_id, role_id)`.
   - Even if application code errs, cross-tenant role assignment is physically prevented by the PostgreSQL engine.
4. **Token Rotation & Family Reuse Detection:**
   - Refresh tokens are tracked in families. If an already-rotated token is replayed, the entire family is revoked immediately, and an audit event is recorded.
5. **Privilege Escalation Guard:**
   - An administrator cannot assign roles or permissions that they do not personally possess.
6. **Immutable System Roles:**
   - Seeded system roles (`platform_admin`, `tenant_admin`, `user_manager`, `viewer`) cannot be modified or deleted.

---

## 4. Quickstart

### Prerequisites
- Docker & Docker Compose
- Go 1.22+ (if running locally without Docker)
- Make (optional)

### Option A: Run via Docker Compose (Recommended)

1. Clone and enter the repository:
   ```bash
   git clone git@github.com:aalekh12/multi-tenant-ums.git
   cd multi-tenant-ums
   ```

2. Copy environment file (if customized):
   ```bash
   cp .env.example .env
   ```

3. Start PostgreSQL and Redis:
   ```bash
   docker compose up -d postgres redis
   ```

4. Run database migrations:
   ```bash
   docker compose up --build migrate
   ```

5. Seed demo data:
   ```bash
   go run ./cmd/seed
   ```

6. Build and start the API container:
   ```bash
   docker compose up -d --build api
   ```
   > **Note:** Always include `--build` when updating Go source code so Docker recompiles the binary instead of using cached images.

The API will be available at `http://localhost:8081`.

### Option B: Run Locally on Host

1. Ensure Postgres and Redis are running (e.g. via `docker compose up -d postgres redis`).
2. Run database migrations:
   ```bash
   # Using docker compose migration runner:
   docker compose up --build migrate
   ```
3. Seed demo data:
   ```bash
   go run ./cmd/seed
   ```
4. Start the API on port 8081 (set `HTTP_PORT=8081` in `.env`):
   ```bash
   go run ./cmd/api
   ```

---

## 5. Seed Credentials Table

The database seed tool (`cmd/seed/main.go`) creates the following accounts with default password `ChangeMe!12345`:

| Tenant Code | Tenant Name | User Email | Assigned Role | Capabilities / Purpose |
|---|---|---|---|---|
| `platform` | Platform Admin | `root@platform.test` | `platform_admin` | Global platform administrator: can create, list, suspend, and activate tenants |
| `acme` | Acme Corp | `admin@acme.test` | `tenant_admin` | Full administrator of Acme Corp |
| `acme` | Acme Corp | `manager@acme.test` | `user_manager` | Can manage users and memberships |
| `acme` | Acme Corp | `viewer@acme.test` | `viewer` | Read-only access to users, roles, and tenant profile |
| `acme` | Acme Corp | `user01@acme.test` .. `user50@acme.test` | `viewer` | 50 filler users for pagination testing |
| `globex` | Globex Corporation | `admin@globex.test` | `tenant_admin` | Full administrator of Globex Corporation |
| **Multi-Tenant** | Both | `shared@example.test` | `viewer` (in Acme)<br>`tenant_admin` (in Globex) | Cross-tenant user demonstrating context switching via `/auth/switch-tenant` |

---

## 6. End-to-End Walkthrough via cURL

### Step 1: Healthcheck
```bash
curl -i http://localhost:8081/healthz
curl -i http://localhost:8081/readyz
```

### Step 2: Login as Platform Admin & List Tenants
```bash
# Login to platform tenant
LOGIN_RESP=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"root@platform.test","password":"ChangeMe!12345","tenant_code":"platform"}')

ROOT_TOKEN=$(echo $LOGIN_RESP | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# List all tenants
curl -i -H "Authorization: Bearer $ROOT_TOKEN" http://localhost:8081/api/v1/tenants
```

### Step 3: Login as Acme Admin & Create a User
```bash
# Login to Acme Corp
ACME_RESP=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.test","password":"ChangeMe!12345","tenant_code":"acme"}')

ACME_TOKEN=$(echo $ACME_RESP | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Create a new user in Acme
CREATE_USER_RESP=$(curl -s -X POST http://localhost:8081/api/v1/users \
  -H "Authorization: Bearer $ACME_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.test","full_name":"Alice Engineer","password":"ChangeMe!12345"}')

echo $CREATE_USER_RESP
USER_ID=$(echo $CREATE_USER_RESP | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)
```

### Step 4: Login as Multi-Tenant User (`shared@example.test`)
```bash
# Login to Acme context
SHARED_RESP=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"shared@example.test","password":"ChangeMe!12345","tenant_code":"acme"}')

SHARED_TOKEN=$(echo $SHARED_RESP | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Inspect permissions in Acme (viewer only: user:read, role:read, etc.)
curl -s -H "Authorization: Bearer $SHARED_TOKEN" http://localhost:8081/api/v1/auth/me
```

### Step 5: Switch Tenant to Globex
```bash
# Fetch Globex tenant ID from tenant listing or database
# Switch context
SWITCH_RESP=$(curl -s -X POST http://localhost:8081/api/v1/auth/switch-tenant \
  -H "Authorization: Bearer $SHARED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_tenant_id":"<globex-tenant-id>"}')

GLOBEX_TOKEN=$(echo $SWITCH_RESP | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Inspect permissions in Globex (tenant_admin: full control)
curl -s -H "Authorization: Bearer $GLOBEX_TOKEN" http://localhost:8081/api/v1/auth/me
```

### Step 6: Verify Strict Tenant Isolation (Cross-Tenant Access Returns 404)
```bash
# Attempt to read Acme's user using Globex token -> Returns 404 Not Found!
curl -i -H "Authorization: Bearer $GLOBEX_TOKEN" http://localhost:8081/api/v1/users/$USER_ID
```
*Response: `HTTP/1.1 404 Not Found` with `{ "error": { "code": "NOT_FOUND", "message": "user not found" } }`.*

### Step 7: Verify RBAC Permission Guard (Viewer Cannot Mutate)
```bash
# Login as Acme viewer
VIEWER_RESP=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"viewer@acme.test","password":"ChangeMe!12345","tenant_code":"acme"}')

VIEWER_TOKEN=$(echo $VIEWER_RESP | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Attempt to delete user -> Returns 403 Forbidden!
curl -i -X DELETE -H "Authorization: Bearer $VIEWER_TOKEN" http://localhost:8081/api/v1/users/$USER_ID
```
*Response: `HTTP/1.1 403 Forbidden` with `{ "error": { "code": "FORBIDDEN", "details": [{"issue": "requires user:delete"}] } }`.*

### Step 8: Query Keyset-Paginated Audit Logs

#### 8A. Tenant Admin (Strictly Scoped to Own Tenant)
```bash
# Acme Admin queries Acme's audit trail
curl -i -H "Authorization: Bearer $ACME_TOKEN" "http://localhost:8081/api/v1/audit-logs?limit=10"
```

#### 8B. Platform Admin (Platform-Wide or Tenant-Specific)
```bash
# Platform Admin sees all platform events (tenant.create, tenant.suspend, etc.)
curl -i -H "Authorization: Bearer $ROOT_TOKEN" "http://localhost:8081/api/v1/audit-logs?limit=10"

# Platform Admin filters by a specific tenant
curl -i -H "Authorization: Bearer $ROOT_TOKEN" "http://localhost:8081/api/v1/audit-logs?tenant_id=<target-tenant-id>&limit=10"
```

### Step 9: Suspend & Reactivate a Tenant (with Immediate Token Revocation)
```bash
# 1. Platform Admin suspends Globex
curl -i -X POST -H "Authorization: Bearer $ROOT_TOKEN" \
  http://localhost:8081/api/v1/tenants/<globex-tenant-id>/suspend

# 2. Existing tokens for Globex are immediately invalidated -> Returns 403 TENANT_SUSPENDED
curl -i -H "Authorization: Bearer $GLOBEX_TOKEN" http://localhost:8081/api/v1/auth/me

# 3. New logins for Globex are rejected
curl -i -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@globex.test","password":"ChangeMe!12345","tenant_code":"globex"}'

# 4. Platform Admin reactivates Globex
curl -i -X POST -H "Authorization: Bearer $ROOT_TOKEN" \
  http://localhost:8081/api/v1/tenants/<globex-tenant-id>/activate
```

---

## 7. Performance & Scalability Strategy

1. **Composite & Partial Indexes:**
   - Every tenant-scoped query filters on `tenant_id` and leverages partial indexes with `WHERE deleted_at IS NULL`.
   - Composite keys on `(tenant_id, created_at DESC, user_id)` ensure index-only scans for high-volume pagination.
2. **SingleFlight Permission Resolver:**
   - Permission codes for `(tenant_id, user_id)` are cached in Redis with a 5-minute TTL.
   - High-concurrency requests for the same user share a single in-flight DB lookup via `golang.org/x/sync/singleflight`, completely eliminating cache stampedes.
3. **Tenant Suspension Fast-Path:**
   - Operational status (`active` vs `suspended`) is cached for 30 seconds.
   - Suspended tenants fail immediately at the `TenantActive` middleware layer without loading downstream domain objects.
4. **Keyset (Cursor) Pagination for Audit Logs:**
   - Audit logs utilize `(created_at, id)` keyset pagination, maintaining O(1) performance regardless of table depth (unlike traditional `OFFSET/LIMIT`).

---

## 8. Testing Suite

The repository contains extensive unit and integration test coverage:

```bash
# Run all unit tests
go test ./internal/...

# Run integration tests (cross-tenant isolation matrix, unknown body rejection, malformed UUID probing)
go test -v ./test/integration

# Run entire suite with race detection
go test -race ./...
```

---

## 9. API Documentation & Artifacts

- **Interactive Swagger UI:** Served locally at [`http://localhost:8081/swagger/index.html`](http://localhost:8081/swagger/index.html).
- **OpenAPI 3.0 Specification:** Stored at [`docs/openapi.yaml`](https://github.com/aalekh12/multi-tenant-ums/blob/master/docs/openapi.yaml).
- **Postman Collection:** Stored at [`docs/postman_collection.json`](https://github.com/aalekh12/multi-tenant-ums/blob/master/docs/postman_collection.json).
- **Architecture Design Document:** Read [`docs/DESIGN.md`](https://github.com/aalekh12/multi-tenant-ums/blob/master/docs/DESIGN.md) for full architectural trade-offs.
- **Database ER Diagram:** [Visual Diagram](https://github.com/aalekh12/multi-tenant-ums/blob/master/docs/multi_tenant_database_erd.jpg) 
- **SQL Relationship Documentation:** [`docs/er-diagram.md`](https://github.com/aalekh12/multi-tenant-ums/blob/master/docs/er-diagram.md).

---

## 10. Troubleshooting & Common Run Issues

Below are common errors encountered during local deployment or testing, their root causes, and verified fixes:

| Error / Symptom | Root Cause | Solution / Fix |
|---|---|---|
| **Port 8080 Conflict**<br>`listen tcp 0.0.0.0:8080: bind: Only one usage of each socket address...` | Host service (e.g., Windows `db_setup` or another web server) is occupying port `8080`. | The docker-compose mapping binds host port `8081:8080`. Connect to **`http://localhost:8081`**. If running with `go run ./cmd/api`, set `HTTP_PORT=8081` in your `.env`. |
| **Go Code Changes Not Reflected**<br>`500 INTERNAL_ERROR` persists after modifying Go files in Docker | `docker compose up -d api` reuses the previously built container image and does not recompile the Go binary. | Always pass the `--build` flag to force recompilation:<br>`docker compose up -d --build api` |
| **PostgreSQL `inet` Input Error**<br>`ERROR: invalid input syntax for type inet: "172.21.0.1:41384"` | Go's `http.Request.RemoteAddr` includes the ephemeral client port (`IP:port`). PostgreSQL `inet` only accepts pure IP addresses or CIDR blocks. | Stripped client port with `net.SplitHostPort` in `audit.EventFromRequest()` prior to saving to `audit_logs` and `refresh_tokens`. |
| **Audit Logs 500 on Read**<br>`cannot scan inet (OID 869) in binary format into *string` | PostgreSQL returns `inet` in binary format by default in `pgx/v5`, which cannot scan directly into `*string`. | Wrapped column in `host(al.ip)` inside `internal/audit/repository.go` so PostgreSQL outputs standard text representation. |
| **Audit Logs Missing on Suspend/Activate**<br>Platform Admin suspends a tenant, but `GET /audit-logs` shows empty array | Suspend/activate events are stored with `tenant_id = target_tenant_id`, while the Platform Admin belongs to `platform` tenant. | In `internal/audit/repository.go`, Platform Admin now has system-wide audit visibility across all tenants by default, and can filter by `?tenant_id=<id>`. |
| **Database Does Not Exist**<br>`FATAL: database "multi_tenant_ums" does not exist (SQLSTATE 3D000)` | Docker volume `postgres_data` was initialized before database configuration. | Reset Docker volumes:<br>`docker compose down -v`<br>`docker compose up -d postgres redis`<br>`docker compose up --build migrate`<br>`go run ./cmd/seed` |
| **Swagger UI Spec Not Found**<br>`Fetch error Not Found /openapi.yaml` | Relative filesystem path was not present in the minimal Alpine Docker runtime container. | Embedded `openapi.yaml` directly into the Go executable via `//go:embed` directive in `internal/api/openapi_spec.go`. |
| **Go Mod Version Mismatch**<br>`go.mod requires go >= 1.26.0 (running go 1.22)` | Local Go toolchain version mismatch with container builder. | Aligned `Dockerfile` builder stage with matching Go Alpine version and verified `go.mod`. |



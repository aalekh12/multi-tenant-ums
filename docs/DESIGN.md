# Design Document: Multi-Tenant User Management System

**Stack:** Go, PostgreSQL, Redis (cache). **Style:** stateless REST API, shared-schema multi-tenancy.

## 1. Architecture

The code is organized by domain (`auth`, `tenant`, `user`, `role`, `permission`, `audit`). Each domain has the same three layers:

- **Handler:** HTTP only. Decodes and validates the request, maps DTOs, and writes responses and errors.
- **Service:** business rules, transactions, audit writes and cache invalidation. It depends on repository interfaces, so it is unit-testable with fakes.
- **Repository:** SQL only (pgx, no ORM). Every method for tenant-owned data requires an explicit `tenantID`.

Shared infrastructure (DB pool, cache, JWT, password hashing, HTTP helpers) lives under `internal/platform` and holds no business logic. The middleware chain is `RequestID → Recover → Logger → Authenticate → TenantActive → RequirePermission`.

The API is stateless. State lives in PostgreSQL (source of truth) and Redis (cache, rate limits), so API instances scale horizontally behind a load balancer.

## 2. Tenant Isolation Strategy

All tenants share one database and one schema; tenant-owned rows carry `tenant_id`. Isolation is enforced in layers:

1. **Token-only tenant.** The tenant ID is read from the verified JWT `tid` claim. Path, query, header and body values are never trusted, and a body containing `tenant_id` is rejected.
2. **Repository contract.** Every tenant-scoped query takes `tenantID` and filters on it. There is no "get by id alone" method for tenant data. User lookups join through `tenant_users`, so a foreign user id returns no row.
3. **404 for cross-tenant access.** A resource in another tenant is indistinguishable from a missing one, so ids cannot be probed. Permission (403) is checked before lookup (404).
4. **Database constraints.** Composite foreign keys such as `(tenant_id, role_id) → roles(tenant_id, id)` make cross-tenant role assignment impossible even if application code is wrong.
5. **Optional Row Level Security** (`ENABLE_RLS`): policies on tenant-owned tables using `SET LOCAL app.tenant_id` per transaction, as defense in depth.
6. **Tests.** An integration matrix runs every tenant-scoped route with tenant A's token against tenant B's ids and expects 404 (or a rejected request) every time.

## 3. RBAC Model

- **Users are global identities** (unique email) linked to tenants through `tenant_users`. One user can belong to many tenants.
- **Roles are tenant-specific.** Each tenant gets default roles (`tenant_admin`, `user_manager`, `viewer`) at creation and can define its own. A user can hold multiple roles per tenant (`user_roles`).
- **Permissions** are a global catalog of `resource:action` codes (for example `user:create`), mapped to roles through `role_permissions`. Matching is exact, with no wildcards in v1.
- **Resolution.** `RequirePermission` loads the union of the user's permission codes for the token's tenant. The result is cached at `perm:{tenant}:{user}` (TTL 5 minutes), with `singleflight` to avoid stampedes on a miss.
- **Invalidation.** Services invalidate after commit when roles are assigned or removed, role permissions change, a role or user is deleted, or a tenant is suspended. A per-tenant version key covers role-wide changes. If the cache fails, the system falls back to the database and never to "allow".
- **Guards.** System roles are immutable. An actor can only grant permissions they hold themselves, which prevents privilege escalation.
- **Platform tenant.** A seeded platform tenant holds `tenant:*` permissions. Only its tokens can create, list and suspend tenants.

## 4. Token Design

| | Access token | Refresh token |
|---|---|---|
| Format | JWT, HS256 | JWT, HS256 |
| TTL | 15 min | 7 days |
| Claims | `sub`, `tid`, `sid`, `jti`, `iss`, `aud`, `typ`, `iat`, `exp` | same, `typ=refresh` |
| Stored server-side | No | Yes (`refresh_tokens`, keyed by `jti`) |

- **Scoped to one tenant.** A token carries exactly one `tid`. Users move between tenants with `POST /auth/switch-tenant`, which checks membership and issues a new pair.
- **Rotation and reuse detection.** Each refresh marks the old `jti` as used and issues a new one in the same `family_id`. Presenting a used or revoked token revokes the whole family and is audited.
- **Permissions are not in the JWT.** This makes role changes, user removal and tenant suspension effective within seconds rather than at token expiry. The cost is a cached lookup per request.
- **Validation.** The verifier pins the algorithm and checks signature, `exp`, `iss`, `aud` and `typ`.
- **Status codes.** Invalid, expired or revoked credentials return 401. A valid identity without permission, or in a suspended tenant, returns 403.
- **Login hardening.** Failures return a generic message and always run a bcrypt comparison (dummy hash if the user is unknown). Logins are rate-limited per IP and email.

## 5. Scaling Approach

- **Indexes.** Every hot query is tenant-leading and uses partial indexes on `deleted_at IS NULL`: the user list, role membership, permission resolution joins and audit lookups. `EXPLAIN` results for the main queries are recorded in the README.
- **Connection pooling.** pgxpool with env-tuned max and min connections, lifetimes and health checks. Pool size per instance is chosen against Postgres `max_connections` divided by instance count (or via PgBouncer).
- **Caching.** Permission sets (5 minutes), tenant status (30 seconds) and rate-limit counters live in Redis. Redis is a shared cache, not a source of truth.
- **Pagination.** Offset pagination with a 100-row cap for users and roles. Keyset pagination (`created_at, id`) for audit logs, which is the largest table.
- **CPU cost.** bcrypt cost is configurable. Login is the only expensive path and is rate-limited. Normal requests only verify a JWT.
- **Growth path.** Read replicas for list and audit queries, monthly partitioning of `audit_logs`, and moving large tenants to dedicated databases.

## 6. Key Trade-offs

| Decision | Chosen | Alternative | Reason / cost |
|---|---|---|---|
| Tenancy model | Shared schema with `tenant_id` | Schema or database per tenant | Cheapest to operate and migrate at high tenant counts. Isolation depends on discipline, which is why constraints, tests and optional RLS back it up. |
| User identity | Global users with memberships | Separate user per tenant | One login for several tenants. Email is a global namespace, so attaching an existing email to a tenant reveals that it exists. |
| Permissions | Looked up and cached server-side | Embedded in JWT | Immediate revocation. Adds a cache dependency and one lookup per request. |
| Signing | HS256 with a shared secret | RS256/EdDSA with JWKS | Simple and fast. Every verifier holds the secret, and rotation is manual (`kid` supported). |
| Soft delete | Per-tenant membership, global user only when none remain | Hard delete or global flag | Tenant admins can't affect other tenants. Keeps history and audit references intact. |
| Audit writes | Same transaction as the change | Async queue | Never loses or invents events. Adds a small write to each mutation. |
| ORM | Hand-written SQL | ORM | Explicit tenant filters and predictable query plans. More boilerplate. |

## 7. Next Steps

- Invitation flow so users consent before joining a tenant, and to remove the email-existence leak.
- MFA, password reset and email verification.
- Asymmetric signing keys with JWKS and scheduled key rotation.
- Enable RLS by default and add a CI check that fails on any repository query missing `tenant_id`.
- Partition and archive `audit_logs`, and stream events to a SIEM through an outbox.
- Per-tenant quotas and rate limits, plus metrics and tracing (Prometheus, OpenTelemetry).
- Wildcard and resource-scoped permissions, and custom per-tenant role templates.

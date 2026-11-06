# Database ER Diagram

Shared database, shared schema. Tenant-owned tables carry `tenant_id`; `users` and `permissions` are global.

```mermaid
erDiagram
    TENANTS {
        uuid id PK
        text name
        citext code UK
        text status "active | suspended"
        boolean is_platform "exactly one true"
        timestamptz created_at
        timestamptz updated_at
    }

    USERS {
        uuid id PK
        citext email "unique where deleted_at is null"
        text password_hash
        text full_name
        timestamptz created_at
        timestamptz updated_at
        timestamptz deleted_at "soft delete"
    }

    TENANT_USERS {
        uuid tenant_id PK, FK
        uuid user_id PK, FK
        text status "active | inactive"
        timestamptz created_at
        timestamptz updated_at
        timestamptz deleted_at "soft delete per tenant"
    }

    ROLES {
        uuid id PK
        uuid tenant_id FK
        text name "unique per tenant"
        text description
        boolean is_system "immutable when true"
        timestamptz created_at
        timestamptz updated_at
    }

    PERMISSIONS {
        smallint id PK
        text resource
        text action
        text code UK "resource:action"
        text description
    }

    ROLE_PERMISSIONS {
        uuid tenant_id FK
        uuid role_id PK, FK
        smallint permission_id PK, FK
    }

    USER_ROLES {
        uuid tenant_id PK, FK
        uuid user_id PK, FK
        uuid role_id PK, FK
        uuid assigned_by FK
        timestamptz assigned_at
    }

    REFRESH_TOKENS {
        uuid jti PK
        uuid family_id "rotation chain"
        uuid user_id FK
        uuid tenant_id FK
        timestamptz expires_at
        timestamptz used_at
        timestamptz revoked_at
        timestamptz created_at
        inet ip
        text user_agent
    }

    AUDIT_LOGS {
        bigint id PK
        uuid tenant_id FK "nullable"
        uuid actor_user_id FK "nullable"
        text action
        text target_type
        text target_id
        jsonb metadata
        boolean success
        inet ip
        text user_agent
        text request_id
        timestamptz created_at
    }

    TENANTS ||--o{ TENANT_USERS : "has members"
    USERS ||--o{ TENANT_USERS : "belongs to"
    TENANTS ||--o{ ROLES : "defines"
    ROLES ||--o{ ROLE_PERMISSIONS : "grants"
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : "granted via"
    TENANT_USERS ||--o{ USER_ROLES : "holds"
    ROLES ||--o{ USER_ROLES : "assigned as"
    USERS ||--o{ USER_ROLES : "assigned_by"
    USERS ||--o{ REFRESH_TOKENS : "owns sessions"
    TENANTS ||--o{ REFRESH_TOKENS : "scopes"
    TENANTS ||--o{ AUDIT_LOGS : "records"
    USERS ||--o{ AUDIT_LOGS : "acts"
```

## Notes on keys and constraints

- **Many-to-many users and tenants** is resolved by `tenant_users` (composite PK `tenant_id, user_id`).
- **Composite foreign keys enforce isolation in the database.**
  - `user_roles (tenant_id, user_id)` references `tenant_users (tenant_id, user_id)`.
  - `user_roles (tenant_id, role_id)` references `roles (tenant_id, id)`.
  - `role_permissions (tenant_id, role_id)` references `roles (tenant_id, id)`.
  - A role from tenant B therefore cannot be linked to a user in tenant A, even if application code has a bug.
- **Soft delete:** `users.deleted_at` is set only when a user has no active memberships left. `tenant_users.deleted_at` is the per-tenant removal.
- **Uniqueness:**
  - `tenants.code` is globally unique.
  - `users.email` is unique among non-deleted rows (partial index).
  - `roles (tenant_id, name)` is unique.
  - `permissions.code` is unique.
  - Only one tenant may have `is_platform = true`.
- **Key indexes:**
  - `tenant_users (tenant_id, created_at DESC, user_id) WHERE deleted_at IS NULL` for user lists.
  - `user_roles (tenant_id, role_id)` for role-member lookups.
  - `audit_logs (tenant_id, created_at DESC, id DESC)` for keyset pagination.
  - `refresh_tokens (family_id)` for reuse-detection revocation.

-- 000004_rbac.up.sql
CREATE TABLE roles (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid        NOT NULL REFERENCES tenants(id),
  name        text        NOT NULL CHECK (length(name) BETWEEN 2 AND 64),
  description text        NOT NULL DEFAULT '',
  is_system   boolean     NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id)
);

CREATE TABLE permissions (
  id          smallserial PRIMARY KEY,
  resource    text        NOT NULL,
  action      text        NOT NULL,
  code        text        GENERATED ALWAYS AS (resource || ':' || action) STORED UNIQUE,
  description text        NOT NULL DEFAULT '',
  UNIQUE (resource, action)
);

CREATE TABLE role_permissions (
  tenant_id     uuid     NOT NULL,
  role_id       uuid     NOT NULL,
  permission_id smallint NOT NULL REFERENCES permissions(id),
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX ix_role_permissions_tenant ON role_permissions (tenant_id, role_id);

CREATE TABLE user_roles (
  tenant_id   uuid        NOT NULL,
  user_id     uuid        NOT NULL,
  role_id     uuid        NOT NULL,
  assigned_by uuid        REFERENCES users(id),
  assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, role_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES tenant_users (tenant_id, user_id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX ix_user_roles_role ON user_roles (tenant_id, role_id);


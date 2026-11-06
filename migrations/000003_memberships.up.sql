-- 000003_memberships.up.sql
CREATE TABLE tenant_users (
  tenant_id  uuid        NOT NULL REFERENCES tenants(id),
  user_id    uuid        NOT NULL REFERENCES users(id),
  status     text        NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX ix_tenant_users_user ON tenant_users (user_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_tenant_users_list ON tenant_users (tenant_id, created_at DESC, user_id) WHERE deleted_at IS NULL;


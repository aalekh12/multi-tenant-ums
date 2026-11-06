-- 000005_refresh_tokens.up.sql
CREATE TABLE refresh_tokens (
  jti        uuid        PRIMARY KEY,
  family_id  uuid        NOT NULL,
  user_id    uuid        NOT NULL REFERENCES users(id),
  tenant_id  uuid        NOT NULL REFERENCES tenants(id),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  ip         inet,
  user_agent text
);

CREATE INDEX ix_refresh_family ON refresh_tokens (family_id);
CREATE INDEX ix_refresh_user_tenant ON refresh_tokens (user_id, tenant_id) WHERE revoked_at IS NULL;


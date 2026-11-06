-- 000006_audit_logs.up.sql
CREATE TABLE audit_logs (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     uuid        REFERENCES tenants(id),
  actor_user_id uuid        REFERENCES users(id),
  action        text        NOT NULL,
  target_type   text        NOT NULL,
  target_id     text,
  metadata      jsonb       NOT NULL DEFAULT '{}',
  success       boolean     NOT NULL DEFAULT true,
  ip            inet,
  user_agent    text,
  request_id    text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_audit_tenant_time   ON audit_logs (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_audit_tenant_actor  ON audit_logs (tenant_id, actor_user_id, created_at DESC);
CREATE INDEX ix_audit_tenant_action ON audit_logs (tenant_id, action, created_at DESC);


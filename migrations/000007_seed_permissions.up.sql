-- 000007_seed_permissions.up.sql
INSERT INTO permissions (resource, action, description) VALUES
  ('tenant',     'create',  'Create a new tenant'),
  ('tenant',     'read',    'Read tenant information'),
  ('tenant',     'update',  'Update tenant information'),
  ('tenant',     'suspend', 'Suspend or activate a tenant'),
  ('user',       'create',  'Create a user in a tenant'),
  ('user',       'read',    'Read user information'),
  ('user',       'update',  'Update user information'),
  ('user',       'delete',  'Delete (soft) a user from a tenant'),
  ('role',       'create',  'Create a role'),
  ('role',       'read',    'Read role information'),
  ('role',       'update',  'Update a role'),
  ('role',       'delete',  'Delete a role'),
  ('role',       'assign',  'Assign roles to users'),
  ('permission', 'read',    'Read the permission catalog'),
  ('permission', 'assign',  'Assign permissions to roles'),
  ('audit',      'read',    'Read audit logs')
ON CONFLICT (resource, action) DO NOTHING;


-- Migration: OAuth states
-- Description: The state of an OAuth install (Slack, Google Drive) is kept
-- here, with its expiry, instead of in one API process's memory, so any
-- replica can finish it. It is bound to the Eve user who started it, or, for
-- the signed-link Slack install that has no Eve user, to a cookie set in the
-- browser that started it. The public callback records the provider's code;
-- the user who started the install completes it with their own token.
-- The id is the SHA-256 of the state, never the state itself.

CREATE TABLE IF NOT EXISTS oauth_states (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id TEXT,
  install_binding TEXT,
  code TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT oauth_states_bound CHECK (user_id IS NOT NULL OR install_binding IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS oauth_states_expires_at ON oauth_states (expires_at);

COMMENT ON COLUMN oauth_states.id IS 'SHA-256 (hex) of the state value';
COMMENT ON COLUMN oauth_states.user_id IS 'Eve user who started the install; NULL for a signed-link install';
COMMENT ON COLUMN oauth_states.install_binding IS 'SHA-256 (hex) of the install cookie; NULL when a user started the install';
COMMENT ON COLUMN oauth_states.code IS 'The provider code, recorded by the public callback';

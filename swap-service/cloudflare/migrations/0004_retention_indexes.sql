-- Add retention indexes without modifying existing offers, quotas or sessions.
CREATE INDEX IF NOT EXISTS offers_expires ON offers(expires);
CREATE INDEX IF NOT EXISTS quotas_window ON quotas(window);
CREATE INDEX IF NOT EXISTS swap_sessions_expires ON swap_sessions(expires);

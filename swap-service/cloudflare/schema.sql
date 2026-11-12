-- Separate from the local SQLite database. Safe to apply repeatedly to a database that already has the identity columns.
-- An existing database created before P5 needs migrations/0002_identity.sql instead (additive; back up first).
CREATE TABLE IF NOT EXISTS offers (
  id TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, public INTEGER NOT NULL,
  offer TEXT NOT NULL, expires INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0,
  reservation_hash TEXT, reservation_id TEXT, reservation_expires INTEGER,
  owner_identity TEXT, reservation_identity TEXT
);
CREATE INDEX IF NOT EXISTS offers_public ON offers(public, closed, expires);
CREATE INDEX IF NOT EXISTS offers_expires ON offers(expires);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, offer_id TEXT NOT NULL,
  reservation_id TEXT, sender TEXT NOT NULL, payload TEXT NOT NULL, created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_offer_session ON messages(offer_id, reservation_id, id);
CREATE TABLE IF NOT EXISTS quotas (key TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS quotas_window ON quotas(window);
-- A swap session is independent of the offer's listing and reservation lifetime.
CREATE TABLE IF NOT EXISTS swap_sessions (
  id TEXT PRIMARY KEY, offer_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
  owner_hash TEXT NOT NULL, taker_hash TEXT NOT NULL, offer_snapshot TEXT NOT NULL,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, UNIQUE (offer_id, reservation_id)
);
CREATE TABLE IF NOT EXISTS swap_packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
  sender TEXT NOT NULL CHECK (sender IN ('owner', 'taker')),
  sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 256),
  ciphertext TEXT NOT NULL, created INTEGER NOT NULL,
  UNIQUE (session_id, sender, sequence)
);
CREATE INDEX IF NOT EXISTS swap_packets_session ON swap_packets(session_id, id);
CREATE INDEX IF NOT EXISTS swap_sessions_expires ON swap_sessions(expires);
